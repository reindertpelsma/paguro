using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json.Nodes;

namespace Paguro.Testing;

/// <summary>A fake paguro service: answers JSON-RPC lines on a named pipe
/// from canned responses (the API fixtures, or responses a test sets), and
/// records every call.</summary>
public sealed class FakeServer : IDisposable
{
    readonly ConcurrentDictionary<string, Func<JsonObject, Reply>> handlers = new();
    readonly ConcurrentQueue<Call> calls = new();
    readonly CancellationTokenSource stop = new();
    readonly Task loop;

    /// <summary>One recorded call.</summary>
    public sealed record Call(string Method, JsonObject Params);

    /// <summary>What to answer: notifications first, then a result or an error.</summary>
    public sealed record Reply(JsonObject? Result, JsonObject? Error, IReadOnlyList<JsonObject> Notifications);

    public string PipeName { get; }

    FakeServer(string name)
    {
        PipeName = name;
        loop = Task.Run(() => Serve(stop.Token));
    }

    /// <summary>Start on a fresh pipe name (or <paramref name="name"/>).</summary>
    public static FakeServer Start(string? name = null) => new(name ?? "paguro-test-" + Guid.NewGuid().ToString("N")[..12]);

    public IReadOnlyList<Call> Calls => calls.ToArray();

    public void ClearCalls() { while (calls.TryDequeue(out _)) { } }

    /// <summary>Answer <paramref name="method"/> with a result whose data is <paramref name="dataJson"/>.</summary>
    public void OnData(string method, string dataJson, string exit = "ok", params string[] lines)
        => On(method, _ => Ok(JsonNode.Parse(dataJson), exit, lines));

    /// <summary>Answer <paramref name="method"/> with an error.</summary>
    public void OnError(string method, string code, long exit, string message, string? dataJson = null)
        => On(method, _ => Error(code, exit, message, dataJson is null ? null : JsonNode.Parse(dataJson)));

    public void On(string method, Func<JsonObject, Reply> handler) => handlers[method] = handler;

    public static Reply Ok(JsonNode? data, string exit = "ok", params string[] lines) => new(new JsonObject
    {
        ["data"] = data,
        ["warnings"] = new JsonArray(),
        ["lines"] = new JsonArray(lines.Select(l => (JsonNode?)JsonValue.Create(l)).ToArray()),
        ["exit"] = exit,
        ["dry_run"] = false,
    }, null, Array.Empty<JsonObject>());

    public static Reply Error(string code, long exit, string message, JsonNode? data = null)
    {
        var d = new JsonObject { ["code"] = code, ["exit"] = exit };
        if (data != null) d["data"] = data;
        return new(null, new JsonObject { ["code"] = -32000 - exit, ["message"] = message, ["data"] = d }, Array.Empty<JsonObject>());
    }

    /// <summary>Answer every method with its fixture (windows/api/fixtures):
    /// the first example's response, with its notifications.</summary>
    public void LoadFixtures(string dir)
    {
        foreach (var f in Directory.GetFiles(dir, "*.json").OrderBy(f => f, StringComparer.Ordinal))
        {
            var fx = JsonNode.Parse(File.ReadAllText(f))!.AsObject();
            var method = fx["method"]!.GetValue<string>();
            if (Path.GetFileNameWithoutExtension(f) != method) continue;
            var resp = fx["response"]!.AsObject();
            var notes = fx["notifications"]!.AsArray().Select(n => n!.AsObject()).ToList();
            var result = resp["result"]?.DeepClone().AsObject();
            var error = resp["error"]?.DeepClone().AsObject();
            On(method, _ => new Reply(result?.DeepClone().AsObject(), error?.DeepClone().AsObject(), notes.Select(n => n.DeepClone().AsObject()).ToList()));
        }
    }

    async Task Serve(CancellationToken cancel)
    {
        while (!cancel.IsCancellationRequested)
        {
            var s = new NamedPipeServerStream(PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            try
            {
                await s.WaitForConnectionAsync(cancel).ConfigureAwait(false);
            }
            catch
            {
                await s.DisposeAsync().ConfigureAwait(false);
                return;
            }
            _ = Task.Run(() => Connection(s, cancel), CancellationToken.None);
        }
    }

    async Task Connection(NamedPipeServerStream s, CancellationToken cancel)
    {
        await using var _ = s;
        using var r = new StreamReader(s, new UTF8Encoding(false), false, 65536, leaveOpen: true);
        try
        {
            while (!cancel.IsCancellationRequested)
            {
                var line = await r.ReadLineAsync(cancel).ConfigureAwait(false);
                if (line is null) return;
                if (line.Length == 0) continue;
                var req = JsonNode.Parse(line)!.AsObject();
                var id = req["id"]?.DeepClone();
                var method = req["method"]?.GetValue<string>() ?? "";
                var p = req["params"] as JsonObject ?? new JsonObject();
                calls.Enqueue(new Call(method, (JsonObject)p.DeepClone()));
                var reply = handlers.TryGetValue(method, out var h)
                    ? h(p)
                    : new Reply(null, new JsonObject { ["code"] = -32601, ["message"] = $"no method {method} (fake)" }, Array.Empty<JsonObject>());
                foreach (var n in reply.Notifications)
                {
                    var note = (JsonObject)n.DeepClone();
                    if (note["params"] is JsonObject np) np["id"] = id?.DeepClone();
                    await Write(s, note, cancel).ConfigureAwait(false);
                }
                var resp = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id };
                if (reply.Error != null) resp["error"] = reply.Error.DeepClone();
                else resp["result"] = reply.Result?.DeepClone();
                await Write(s, resp, cancel).ConfigureAwait(false);
            }
        }
        catch (Exception) when (cancel.IsCancellationRequested) { }
        catch (IOException) { }
    }

    static async Task Write(Stream s, JsonObject o, CancellationToken cancel)
    {
        var b = Encoding.UTF8.GetBytes(o.ToJsonString() + "\n");
        await s.WriteAsync(b, cancel).ConfigureAwait(false);
        await s.FlushAsync(cancel).ConfigureAwait(false);
    }

    public void Dispose()
    {
        stop.Cancel();
        try { loop.Wait(2000); } catch (AggregateException) { }
        stop.Dispose();
    }
}
