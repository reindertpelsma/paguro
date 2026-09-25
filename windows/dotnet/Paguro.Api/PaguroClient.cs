using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Paguro.Api;

/// <summary>Something that calls the API: the pipe client, or a test double.</summary>
public interface IPaguroClient : IAsyncDisposable
{
    /// <summary>Call <paramref name="method"/>; <c>progress</c> notifications
    /// arriving meanwhile go to <paramref name="progress"/>.</summary>
    Task<PaguroResult<T>> CallAsync<T>(string method, ParamsBase parameters, IProgress<Progress>? progress = null, CancellationToken cancel = default);
}

/// <summary>JSON-RPC 2.0 over <c>\\.\pipe\paguro</c>: one message per line.
/// One call at a time per connection.</summary>
public sealed class PaguroClient : IPaguroClient
{
    public const string DefaultPipe = "paguro";
    /// <summary>Largest line accepted (the service's own limit).</summary>
    public const int MaxMessage = 4 << 20;

    readonly Stream stream;
    readonly StreamReader reader;
    readonly SemaphoreSlim gate = new(1, 1);
    long nextId;

    public PaguroClient(Stream stream)
    {
        this.stream = stream;
        reader = new StreamReader(stream, new UTF8Encoding(false), false, 64 * 1024, leaveOpen: true);
    }

    /// <summary>The pipe name: <c>PAGURO_PIPE</c>, else <c>paguro</c>.</summary>
    public static string PipeName => Environment.GetEnvironmentVariable("PAGURO_PIPE") is { Length: > 0 } p ? p : DefaultPipe;

    /// <summary>Connect to the service. The real pipe must be owned by
    /// SYSTEM or Administrators: a pipe squatted by another user never
    /// receives a passphrase.</summary>
    public static async Task<PaguroClient> ConnectAsync(string? pipe = null, int timeoutMs = 3000, CancellationToken cancel = default)
    {
        var name = pipe ?? PipeName;
        var s = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await s.ConnectAsync(timeoutMs, cancel).ConfigureAwait(false);
            if (OperatingSystem.IsWindows() && name == DefaultPipe)
                VerifyServer(s);
            return new PaguroClient(s);
        }
        catch
        {
            await s.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    static void VerifyServer(NamedPipeClientStream s)
    {
        var owner = s.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var ok = owner != null && (owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));
        if (!ok)
            throw new UnauthorizedAccessException($"\\\\.\\pipe\\{DefaultPipe} is owned by {owner?.Value ?? "nobody"}, not by the paguro service: refusing to talk to it");
    }

    public async Task<PaguroResult<T>> CallAsync<T>(string method, ParamsBase parameters, IProgress<Progress>? progress = null, CancellationToken cancel = default)
    {
        var p = JsonSerializer.SerializeToNode(parameters, parameters.GetType(), PaguroJson.Options) ?? new JsonObject();
        var result = await CallRawAsync(method, p.AsObject(), progress, cancel).ConfigureAwait(false);
        return result.Deserialize<PaguroResult<T>>(PaguroJson.Options)
            ?? throw new InvalidDataException($"{method}: empty result");
    }

    /// <summary>Call with a raw parameter object; returns the raw result.</summary>
    public async Task<JsonObject> CallRawAsync(string method, JsonObject parameters, IProgress<Progress>? progress = null, CancellationToken cancel = default)
    {
        await gate.WaitAsync(cancel).ConfigureAwait(false);
        try
        {
            var id = Interlocked.Increment(ref nextId);
            var req = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method, ["params"] = parameters };
            var bytes = Encoding.UTF8.GetBytes(req.ToJsonString(PaguroJson.Options) + "\n");
            await stream.WriteAsync(bytes, cancel).ConfigureAwait(false);
            await stream.FlushAsync(cancel).ConfigureAwait(false);
            while (true)
            {
                var line = await reader.ReadLineAsync(cancel).ConfigureAwait(false)
                    ?? throw new EndOfStreamException("the paguro service closed the connection");
                if (line.Length > MaxMessage)
                    throw new InvalidDataException("message too long");
                if (line.Length == 0) continue;
                var msg = JsonNode.Parse(line)?.AsObject() ?? throw new InvalidDataException("not a JSON object");
                if (!msg.ContainsKey("id") || msg["id"] is null && msg.ContainsKey("method"))
                {
                    if (msg["method"]?.GetValue<string>() == "progress" && progress != null)
                    {
                        var pr = msg["params"].Deserialize<Progress>(PaguroJson.Options);
                        if (pr != null) progress.Report(pr);
                    }
                    continue;
                }
                if (msg["id"] is JsonValue v && v.TryGetValue<long>(out var got) && got != id)
                    continue;
                if (msg["error"] is JsonObject e)
                    throw new PaguroException(e["code"]?.GetValue<long>() ?? -32603, e["message"]?.GetValue<string>() ?? "", e["data"]);
                return msg["result"] as JsonObject ?? throw new InvalidDataException($"{method}: no result");
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        reader.Dispose();
        await stream.DisposeAsync().ConfigureAwait(false);
        gate.Dispose();
    }
}
