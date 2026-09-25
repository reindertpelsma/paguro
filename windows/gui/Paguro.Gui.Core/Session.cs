using System.Collections.ObjectModel;
using Paguro.Api;

namespace Paguro.Gui;

/// <summary>The connection to the paguro service, shared by every screen:
/// who we are to it, calls with secrets asked back from the user, and the
/// last error in words.</summary>
public sealed class Session : ObservableObject
{
    readonly Func<CancellationToken, Task<IPaguroClient>> connect;
    IPaguroClient? client;
    string state = "connecting";
    ServiceInfo? info;

    public Session(Func<CancellationToken, Task<IPaguroClient>> connect, Strings strings, IDialogs dialogs)
    {
        this.connect = connect;
        S = strings;
        Dialogs = dialogs;
    }

    /// <summary>The service on its pipe (PAGURO_PIPE for tests).</summary>
    public static Func<CancellationToken, Task<IPaguroClient>> Pipe(string? name = null) =>
        async ct => await PaguroClient.ConnectAsync(name, 3000, ct);

    public Strings S { get; }
    public IDialogs Dialogs { get; }

    /// <summary>connecting, connected, no_service, error.</summary>
    public string State { get => state; private set { if (Set(ref state, value)) { Raise(nameof(Banner)); Raise(nameof(ReadOnly)); Raise(nameof(Connected)); } } }
    public ServiceInfo? Info { get => info; private set { if (Set(ref info, value)) { Raise(nameof(Banner)); Raise(nameof(ReadOnly)); } } }
    public bool Connected => State == "connected";
    /// <summary>The service answers, but this user may only read.</summary>
    public bool ReadOnly => Connected && Info?.Caller.Admin != true;
    public bool NoService => State is "no_service" or "error";

    /// <summary>The one line on top of every screen.</summary>
    public string Banner => State switch
    {
        "connecting" => S["banner_connecting"],
        "no_service" => S["banner_no_service"],
        "error" => S["banner_error"],
        _ when ReadOnly => S["banner_read_only"],
        _ => "",
    };

    public async Task<bool> EnsureAsync(CancellationToken ct = default)
    {
        if (client != null) return true;
        try
        {
            State = "connecting";
            client = await connect(ct);
            Info = (await client.ServiceInfoAsync(cancel: ct)).Data;
            State = "connected";
            return true;
        }
        catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException or PaguroException)
        {
            client = null;
            State = e is TimeoutException or FileNotFoundException ? "no_service" : "error";
            LastError = e.Message;
            return false;
        }
    }

    public async Task ReconnectAsync()
    {
        if (client != null) await client.DisposeAsync();
        client = null;
        await EnsureAsync();
    }

    string? lastError;
    /// <summary>The last failure, in words for the user.</summary>
    public string? LastError { get => lastError; set => Set(ref lastError, value); }

    /// <summary>Call a method: a secret the service asks back for is asked of
    /// the user; a failure is put in words (<see cref="LastError"/>) and gives null.</summary>
    public async Task<PaguroResult<T>?> CallAsync<T>(string method, ParamsBase p, IProgress<Progress>? progress = null)
    {
        if (!await EnsureAsync()) return null;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                LastError = null;
                return await client!.CallAsync<T>(method, p, progress);
            }
            catch (PaguroException e) when (e.NeedsInput is { } ni && attempt < 3)
            {
                var title = ni.Value == "pin" ? S["secret_title_pin"] : ni.Value == "mok_password" ? S["secret_title_mok"] : S["secret_title_passphrase"];
                var s = await Dialogs.AskSecretAsync(title, ni.Prompt, ni.Confirm);
                if (s == null) { LastError = S["cancelled"]; return null; }
                switch (ni.Value)
                {
                    case "pin": p.Pin = s; break;
                    case "mok_password": p.MokPassword = s; break;
                    default: p.LinuxPassphrase = s; break;
                }
            }
            catch (PaguroException e)
            {
                LastError = Describe(e);
                LastException = e;
                return null;
            }
            catch (Exception e) when (e is IOException or EndOfStreamException or InvalidDataException)
            {
                client = null;
                State = "error";
                LastError = S["banner_error"] + " " + e.Message;
                return null;
            }
        }
        return null;
    }

    public PaguroException? LastException { get; private set; }

    string Describe(PaguroException e) => e.Code switch
    {
        "needs_elevation" => S["err_needs_admin"],
        _ => e.Message,
    };

    /// <summary>paguro.exe: the one next to the GUI's folder (Program Files\paguro),
    /// else the repair copy (INTERFACES §11.7a).</summary>
    public static string PaguroExe()
    {
        if (Environment.GetEnvironmentVariable("PAGURO_EXE") is { Length: > 0 } e) return e;
        var beside = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "paguro.exe"));
        if (File.Exists(beside)) return beside;
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "paguro", "setup", "paguro.exe");
    }

    /// <summary>Run paguro.exe itself, elevated (the one UAC prompt), for what the
    /// service cannot do: install it, uninstall it. Returns its --json envelope
    /// (null: cancelled or no report).</summary>
    public async Task<System.Text.Json.Nodes.JsonObject?> RunPaguroAsync(params string[] args)
    {
        var report = Path.Combine(Path.GetTempPath(), $"paguro-gui-{Guid.NewGuid():N}.json");
        var all = args.Concat(new[] { "--json", "--direct", "--report", report }).ToArray();
        var code = await Dialogs.RunAsync(PaguroExe(), all, elevated: true);
        try
        {
            if (!File.Exists(report)) { LastError = S.F("err_not_run", ("code", code)); return null; }
            var env = System.Text.Json.Nodes.JsonNode.Parse(await File.ReadAllTextAsync(report))?.AsObject();
            if (env?["ok"]?.GetValue<bool>() != true)
                LastError = env?["error"]?["message"]?.GetValue<string>() ?? S.F("err_not_run", ("code", code));
            return env;
        }
        finally
        {
            try { File.Delete(report); File.Delete(report + ".err"); } catch (IOException) { }
        }
    }

    /// <summary>Install the service (the one UAC prompt: INTERFACES §11.7).</summary>
    public async Task<bool> InstallServiceAsync()
    {
        var code = await Dialogs.RunAsync(PaguroExe(), ["--direct", "service", "install"], elevated: true);
        if (code != 0) { LastError = S.F("err_service_install", ("code", code)); return false; }
        await ReconnectAsync();
        return Connected;
    }
}

/// <summary>Progress that reaches the UI thread (the thread that made it),
/// or runs inline where there is none (tests).</summary>
public sealed class UiProgress<T> : IProgress<T>
{
    readonly Action<T> handler;
    readonly SynchronizationContext? ctx = SynchronizationContext.Current;

    public UiProgress(Action<T> handler) => this.handler = handler;

    public void Report(T value)
    {
        if (ctx == null) handler(value);
        else ctx.Post(_ => handler(value), null);
    }
}

/// <summary>The steps of a long operation (install, uninstall), as they happen.</summary>
public sealed class OperationViewModel : ObservableObject
{
    readonly Strings s;
    public OperationViewModel(Strings s, string operation, IEnumerable<string> steps)
    {
        this.s = s;
        Operation = operation;
        foreach (var id in steps) Steps.Add(new StepItem(id, s[$"step_{operation}_{id.Replace('-', '_')}"]));
        Progress = new UiProgress<Progress>(On);
    }

    public string Operation { get; }
    public ObservableCollection<StepItem> Steps { get; } = new();
    public IProgress<Progress> Progress { get; }

    int percent;
    public int Percent { get => percent; private set => Set(ref percent, value); }
    string current = "";
    public string Current { get => current; private set => Set(ref current, value); }

    void On(Progress p)
    {
        var item = Steps.FirstOrDefault(x => x.Id == p.Step);
        if (item == null) Steps.Add(item = new StepItem(p.Step, p.Step));
        item.State = p.State;
        item.Detail = p.Detail ?? "";
        Current = p.State == "running" ? item.Title : Current;
        if (p.Total > 0) Percent = (int)Math.Min(100, (p.Index + (p.State == "running" ? 0UL : 1UL)) * 100 / p.Total);
    }

    /// <summary>Take the final states from a journal.</summary>
    public void Apply(IEnumerable<JournalStep>? steps)
    {
        foreach (var j in steps ?? [])
            if (Steps.FirstOrDefault(x => x.Id == j.Id) is { } i) i.State = j.State;
    }
}

public sealed class StepItem(string id, string title) : ObservableObject
{
    public string Id { get; } = id;
    public string Title { get; } = title;
    string state = "pending";
    public string State { get => state; set { if (Set(ref state, value)) Raise(nameof(Glyph)); } }
    string detail = "";
    public string Detail { get => detail; set => Set(ref detail, value); }
    /// <summary>A Segoe Fluent Icons glyph for the state.</summary>
    public string Glyph => State switch
    {
        "done" => "",
        "skipped" => "",
        "failed" => "",
        "running" => "",
        "awaiting_user" or "awaiting_reboot" => "",
        _ => "",
    };
}
