using System.Reflection;
using System.Text.Json.Nodes;

namespace Paguro.Api;

/// <summary>The schema these types were generated from, embedded.</summary>
public static class PaguroSchema
{
    public static JsonObject Load()
    {
        using var s = typeof(PaguroSchema).Assembly.GetManifestResourceStream("paguro-api.json")
            ?? throw new InvalidOperationException("paguro-api.json is not embedded");
        return JsonNode.Parse(s)!.AsObject();
    }
}
