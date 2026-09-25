using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Paguro.Api;
using Xunit;

namespace Paguro.Api.Tests;

[AttributeUsage(AttributeTargets.Assembly)]
public sealed class FixturesDirAttribute(string dir) : Attribute
{
    public string Dir { get; } = dir;
}

/// <summary>INTERFACES.md §11.7: "a contract test that round-trips every
/// message through both". The Rust side made these exchanges
/// (crates/paguro-win/tests/api_contract.rs); here each goes through the
/// generated C# types and back, and must come out equal.</summary>
public class ContractTests
{
    public static string FixturesDir =>
        typeof(ContractTests).Assembly.GetCustomAttribute<FixturesDirAttribute>()!.Dir;

    public static IEnumerable<object[]> Fixtures() =>
        Directory.GetFiles(FixturesDir, "*.json").OrderBy(f => f, StringComparer.Ordinal).Select(f => new object[] { Path.GetFileName(f) });

    static JsonObject Load(string file) => JsonNode.Parse(File.ReadAllText(Path.Combine(FixturesDir, file)))!.AsObject();

    /// <summary>Equal, where an absent field and a null one are the same.</summary>
    public static bool Same(JsonNode? a, JsonNode? b, string at, List<string> diffs)
    {
        if (a is null || b is null)
        {
            if (a is null && b is null) return true;
            diffs.Add($"{at}: {a?.ToJsonString() ?? "null"} vs {b?.ToJsonString() ?? "null"}");
            return false;
        }
        switch (a)
        {
            case JsonObject oa when b is JsonObject ob:
                var ok = true;
                foreach (var k in oa.Select(p => p.Key).Union(ob.Select(p => p.Key)))
                    ok &= Same(oa[k], ob[k], $"{at}.{k}", diffs);
                return ok;
            case JsonArray aa when b is JsonArray ab:
                if (aa.Count != ab.Count) { diffs.Add($"{at}: {aa.Count} vs {ab.Count} items"); return false; }
                var all = true;
                for (var i = 0; i < aa.Count; i++) all &= Same(aa[i], ab[i], $"{at}[{i}]", diffs);
                return all;
            default:
                if (JsonNode.DeepEquals(a, b)) return true;
                diffs.Add($"{at}: {a.ToJsonString()} vs {b.ToJsonString()}");
                return false;
        }
    }

    static PaguroMethodInfo Info(string method) => PaguroMethods.All.Single(m => m.Name == method);

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Request_roundtrips_through_the_params_type(string file)
    {
        var fx = Load(file);
        var info = Info(fx["method"]!.GetValue<string>());
        var p = fx["request"]!["params"]!;
        var typed = p.Deserialize(info.Params, PaguroJson.Options)!;
        Assert.IsAssignableFrom<ParamsBase>(typed);
        var back = JsonSerializer.SerializeToNode(typed, info.Params, PaguroJson.Options);
        var diffs = new List<string>();
        Assert.True(Same(p, back, "params", diffs), string.Join("\n", diffs));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Response_roundtrips_through_the_result_type(string file)
    {
        var fx = Load(file);
        var info = Info(fx["method"]!.GetValue<string>());
        var resp = fx["response"]!.AsObject();
        if (resp["result"] is JsonObject r)
        {
            var t = typeof(PaguroResult<>).MakeGenericType(info.Result);
            var typed = r.Deserialize(t, PaguroJson.Options)!;
            var back = JsonSerializer.SerializeToNode(typed, t, PaguroJson.Options);
            var diffs = new List<string>();
            Assert.True(Same(r, back, "result", diffs), string.Join("\n", diffs));
        }
        else
        {
            var e = resp["error"]!.AsObject();
            var ex = new PaguroException(e["code"]!.GetValue<long>(), e["message"]!.GetValue<string>(), e["data"]);
            Assert.NotEqual("internal", ex.Code);
            Assert.Equal(-32000 - ex.Exit, ex.RpcCode);
        }
        foreach (var n in fx["notifications"]!.AsArray())
        {
            var pr = n!["params"].Deserialize<Progress>(PaguroJson.Options)!;
            var diffs = new List<string>();
            Assert.True(Same(n["params"], JsonSerializer.SerializeToNode(pr, PaguroJson.Options), "progress", diffs), string.Join("\n", diffs));
        }
    }

    [Fact]
    public void Every_method_has_a_fixture_and_a_cmdlet()
    {
        var names = Directory.GetFiles(FixturesDir, "*.json").Select(f => Load(Path.GetFileName(f))["method"]!.GetValue<string>()).ToHashSet();
        foreach (var m in PaguroMethods.All)
        {
            Assert.Contains(m.Name, names);
            Assert.NotEmpty(m.Cmdlets);
            Assert.NotEmpty(m.CliExample);
            Assert.Contains(m.Access, new[] { "read", "admin", "elevated" });
        }
    }

    [Fact]
    public void The_result_envelope_matches_the_schema()
    {
        var s = PaguroSchema.Load();
        var props = s["$defs"]!["Result"]!["properties"]!.AsObject().Select(p => p.Key).ToHashSet();
        var cs = typeof(PaguroResult<object>).GetProperties()
            .Select(p => p.GetCustomAttribute<System.Text.Json.Serialization.JsonPropertyNameAttribute>()?.Name)
            .Where(n => n != null).ToHashSet();
        Assert.Equal(props.OrderBy(x => x), cs.OrderBy(x => x));
        Assert.Equal(PaguroMethods.ApiVersion, s["version"]!.GetValue<string>());
    }
}
