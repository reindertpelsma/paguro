using System.Collections.Concurrent;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.Json.Nodes;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>The API method(s) a cmdlet calls ("nothing is GUI-only": CI checks
/// every schema method has one).</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public sealed class PaguroMethodAttribute(string method) : Attribute
{
    public string Method { get; } = method;
}

/// <summary>What every cmdlet shares: the connection to the service, progress
/// (Write-Progress on the pipeline thread), secrets the service asks back
/// for, -WhatIf as the method's dry run, and errors as ErrorRecords.</summary>
public abstract class PaguroCmdlet : PSCmdlet
{
    /// <summary>The pipe to use (default: $env:PAGURO_PIPE, else paguro).</summary>
    [Parameter(DontShow = true)]
    public string? PipeName { get; set; }

    /// <summary>The EFI System Partition, when there are several.</summary>
    [Parameter]
    public string? Esp { get; set; }

    PaguroClient? client;

    protected PaguroClient Client
    {
        get
        {
            if (client != null) return client;
            try
            {
                client = PaguroClient.ConnectAsync(PipeName).GetAwaiter().GetResult();
            }
            catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new InvalidOperationException($"the paguro service is not reachable ({e.Message}); install it with `paguro service install` from an elevated prompt", e),
                    "paguro.no_service", ErrorCategory.ConnectionError, PipeName ?? PaguroClient.PipeName));
            }
            return client!;
        }
    }

    protected override void EndProcessing()
    {
        client?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        client = null;
    }

    /// <summary>Secrets this cmdlet can supply without asking (by API name).</summary>
    protected virtual SecureString? SecretFor(string name) => null;

    /// <summary>Call and return the result, or write the error and return null.</summary>
    protected PaguroResult<T>? Call<T>(string method, ParamsBase p, bool terminating = false)
    {
        p.Esp ??= Esp;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                var r = Pump(method, Client.CallAsync<T>(method, p, progress, CancellationToken.None));
                foreach (var w in r.Warnings) WriteWarning(w);
                foreach (var l in r.Lines) WriteVerbose(l);
                if (r.Pending)
                    WriteWarning($"{method}: half done by design — run it again after the next step (restart, or --finish)");
                return r;
            }
            catch (PaguroException e) when (e.NeedsInput is { } ni && attempt < 3)
            {
                var s = SecretFor(ni.Value) ?? Ask(ni);
                if (s == null) { Fail(e, method, terminating); return null; }
                Set(p, ni.Value, Plain(s));
            }
            catch (PaguroException e)
            {
                Fail(e, method, terminating);
                return null;
            }
        }
        return null;
    }

    readonly BlockingCollection<Progress> queue = new();
    IProgress<Progress> progress => new Sink(queue);

    sealed class Sink(BlockingCollection<Progress> q) : IProgress<Progress>
    {
        public void Report(Progress value) => q.Add(value);
    }

    /// <summary>Wait for the call on the pipeline thread, writing its progress.</summary>
    T Pump<T>(string method, Task<T> t)
    {
        while (!t.IsCompleted)
        {
            if (queue.TryTake(out var p, 50)) Show(method, p);
        }
        while (queue.TryTake(out var p)) Show(method, p);
        return t.GetAwaiter().GetResult();
    }

    void Show(string method, Progress p)
    {
        var rec = new ProgressRecord(1, $"paguro {p.Operation}", $"{p.Step}: {p.State}")
        {
            PercentComplete = p.Total == 0 ? 0 : (int)Math.Min(100, (p.Index + (p.State == "running" ? 0UL : 1UL)) * 100 / p.Total),
            CurrentOperation = string.IsNullOrEmpty(p.Detail) ? null : p.Detail,
        };
        WriteProgress(rec);
        WriteVerbose($"[{p.Index + 1}/{p.Total}] {p.Step}: {p.State}{(string.IsNullOrEmpty(p.Detail) ? "" : " — " + p.Detail)}");
    }

    SecureString? Ask(NeedsInput ni)
    {
        // Nobody to ask (a script, CI, a redirected stdin): fail with the
        // needs_input error instead of reading from a pipe that has no answer.
        if (Console.IsInputRedirected || !Environment.UserInteractive
            || Environment.GetCommandLineArgs().Any(a => a.Equals("-NonInteractive", StringComparison.OrdinalIgnoreCase)))
            return null;
        try
        {
            Host.UI.Write($"{ni.Prompt}: ");
            var a = Host.UI.ReadLineAsSecureString();
            if (ni.Confirm)
            {
                Host.UI.Write($"{ni.Prompt} (again): ");
                var b = Host.UI.ReadLineAsSecureString();
                if (Plain(a) != Plain(b))
                {
                    WriteWarning("the two entries differ");
                    return null;
                }
            }
            return a;
        }
        catch (Exception e) when (e is PSInvalidOperationException or NotImplementedException or System.Management.Automation.Host.HostException)
        {
            return null;
        }
    }

    static void Set(ParamsBase p, string name, string value)
    {
        switch (name)
        {
            case "pin": p.Pin = value; break;
            case "mok_password": p.MokPassword = value; break;
            default: p.LinuxPassphrase = value; break;
        }
    }

    protected static string Plain(SecureString s)
    {
        var b = Marshal.SecureStringToBSTR(s);
        try { return Marshal.PtrToStringBSTR(b); }
        finally { Marshal.ZeroFreeBSTR(b); }
    }

    void Fail(PaguroException e, string method, bool terminating)
    {
        var cat = e.Code switch
        {
            "refused" => ErrorCategory.InvalidOperation,
            "not_found" => ErrorCategory.ObjectNotFound,
            "needs_elevation" => ErrorCategory.PermissionDenied,
            "usage" => ErrorCategory.InvalidArgument,
            "check_failed" => ErrorCategory.InvalidResult,
            _ => ErrorCategory.NotSpecified,
        };
        var rec = new ErrorRecord(e, "paguro." + e.Code, cat, method);
        if (e.Detail != null) rec.ErrorDetails = new ErrorDetails(e.Message) { RecommendedAction = e.Detail.ToJsonString() };
        if (terminating) ThrowTerminatingError(rec);
        else WriteError(rec);
    }

    /// <summary>Emit each item of a list.</summary>
    protected void WriteAll<T>(IEnumerable<T>? items)
    {
        if (items == null) return;
        foreach (var i in items) WriteObject(i);
    }

    /// <summary>-WhatIf: ShouldProcess false and WhatIf asked → the method's
    /// dry run, whose plan is returned (and its lines shown as "What if").</summary>
    protected bool WhatIfRequested => MyInvocation.BoundParameters.TryGetValue("WhatIf", out var w) && w is SwitchParameter { IsPresent: true };

    /// <summary>Run a mutating call: for real if confirmed, as a dry run on -WhatIf.</summary>
    protected PaguroResult<T>? Mutate<T>(string method, ParamsBase p, string target, string action)
    {
        if (ShouldProcess(target, action))
            return Call<T>(method, p);
        if (!WhatIfRequested) return null;
        p.DryRun = true;
        var r = Call<T>(method, p);
        if (r != null)
            foreach (var l in r.Lines) Host.UI.WriteLine("What if: " + l);
        return r;
    }

    /// <summary>A size as the API takes it: 32G, 512M, or bytes.</summary>
    protected static string SizeText(object size) => size switch
    {
        string s => s,
        PSObject { BaseObject: var o } => SizeText(o),
        IConvertible c => Convert.ToUInt64(c, System.Globalization.CultureInfo.InvariantCulture).ToString(System.Globalization.CultureInfo.InvariantCulture),
        _ => size.ToString() ?? "",
    };

    /// <summary>Run the shell the service named, attached to this console
    /// ($env:PAGURO_SHELL replaces the program, for tests).</summary>
    protected int RunShell(IReadOnlyList<string> command)
    {
        if (command.Count == 0) return 0;
        var prog = Environment.GetEnvironmentVariable("PAGURO_SHELL") is { Length: > 0 } s ? s : command[0];
        var psi = new System.Diagnostics.ProcessStartInfo(prog) { UseShellExecute = false };
        if (Environment.GetEnvironmentVariable("PAGURO_SHELL") is not { Length: > 0 })
            foreach (var a in command.Skip(1)) psi.ArgumentList.Add(a);
        using var proc = System.Diagnostics.Process.Start(psi)!;
        proc.WaitForExit();
        return proc.ExitCode;
    }

    /// <summary>An absolute path for the service: a Windows path as given
    /// (C:\…, \\…), anything else resolved against the current location.</summary>
    protected string FullPath(string p) =>
        p.Length >= 3 && char.IsAsciiLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') || p.StartsWith(@"\\", StringComparison.Ordinal)
            ? p
            : GetUnresolvedProviderPathFromPSPath(p);

    protected static JsonNode? Node(object? o) => o is null ? null : JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(o, PaguroJson.Options));
}
