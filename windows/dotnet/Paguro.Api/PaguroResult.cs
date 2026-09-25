using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Paguro.Api;

/// <summary>A successful call (<c>$defs/Result</c>): the method's data, and the
/// text <c>paguro.exe</c> prints.</summary>
public sealed class PaguroResult<T>
{
    [JsonPropertyName("data")] public T Data { get; set; } = default!;
    [JsonPropertyName("warnings")] public List<string> Warnings { get; set; } = new();
    [JsonPropertyName("lines")] public List<string> Lines { get; set; } = new();
    /// <summary><c>ok</c>, or <c>pending</c>: half done by design, call again to resume.</summary>
    [JsonPropertyName("exit")] public string Exit { get; set; } = "ok";
    [JsonPropertyName("dry_run")] public bool DryRun { get; set; }
    [JsonIgnore] public bool Pending => Exit == "pending";
}

/// <summary>A failed call: the JSON-RPC error, with the command's code
/// (<c>$defs/ErrorData</c>).</summary>
public sealed class PaguroException : Exception
{
    public PaguroException(long rpcCode, string message, JsonNode? data) : base(message)
    {
        RpcCode = rpcCode;
        ErrorData = data;
        Code = data?["code"]?.GetValue<string>() ?? (rpcCode switch
        {
            -32602 or -32601 => "usage",
            _ => "internal",
        });
        Exit = data?["exit"] is JsonValue v && v.TryGetValue<long>(out var e) ? e : 1;
        Detail = data?["data"];
        if (Detail is JsonObject o && o.ContainsKey("needs_input"))
            NeedsInput = o.Deserialize<NeedsInput>(PaguroJson.Options);
    }

    /// <summary>The JSON-RPC error code (-32000 - exit for a command's error).</summary>
    public long RpcCode { get; }
    /// <summary><c>refused</c>, <c>not_found</c>, <c>needs_elevation</c>, …</summary>
    public string Code { get; }
    /// <summary>The CLI's exit code for the same failure.</summary>
    public long Exit { get; }
    public JsonNode? ErrorData { get; }
    /// <summary>Structured detail: failing checks, a journal, …</summary>
    public JsonNode? Detail { get; }
    /// <summary>Set when a secret is missing: ask the user and call again.</summary>
    public NeedsInput? NeedsInput { get; }
}

public static class PaguroJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        NumberHandling = JsonNumberHandling.Strict,
        WriteIndented = false,
    };
}
