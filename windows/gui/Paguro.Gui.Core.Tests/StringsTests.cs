using System.Text.RegularExpressions;
using Paguro.Gui.ViewModels;
using Xunit;

namespace Paguro.Gui.Tests;

/// <summary>The shared string tables (INTERFACES §13.5): every key the app
/// uses exists, in every language, with the same placeholders.</summary>
public partial class StringsTests
{
    [GeneratedRegex(@"\{[a-z_]+\}")] private static partial Regex Placeholder();

    static IEnumerable<string> UsedKeys()
    {
        var src = Directory.GetFiles(Path.GetFullPath(Paths.Gui), "*.*", SearchOption.AllDirectories)
            .Where(f => (f.EndsWith(".cs") || f.EndsWith(".xaml")) && !f.Contains("/obj/") && !f.Contains("\\obj\\") && !f.Contains("Tests"));
        var rx = new Regex(@"(?:\bS|App\.S|\bs)\[""([a-z0-9_]+)""\]|S\.F\(""([a-z0-9_]+)""|Key=([a-z0-9_]+)");
        foreach (var f in src)
            foreach (Match m in rx.Matches(File.ReadAllText(f)))
                yield return m.Groups.Cast<Group>().Skip(1).First(g => g.Success).Value;
        // Keys built from data.
        foreach (var id in new[] { "uefi", "wsl2", "disk_space", "bitlocker", "tpm", "secure_boot", "microsoft_uefi_ca", "fast_startup" })
        { yield return $"check_{id}"; yield return $"check_{id}_why"; }
        foreach (var st in new[] { "ok", "warn", "fail" }) yield return $"state_{st}";
        foreach (var st in DistributionsViewModel.InstallSteps) yield return $"step_install_{st.Replace('-', '_')}";
        foreach (var st in UninstallViewModel.Steps) yield return $"step_uninstall_{st.Replace('-', '_')}";
        foreach (var k in new[] { "gpu", "wifi", "network", "storage" }) yield return $"hw_{k}";
        foreach (var w in new[] { "off", "tpm_pin", "tpm_startup_key", "tpm_only", "no_tpm" }) yield return $"windows_{w}";
        foreach (var c in new[] { "tpm_pin", "passphrase", "tpm_only", "unprotected" })
        { yield return $"choice_{c}"; yield return $"choice_{c}_why"; yield return $"choice_{c}_not_offered"; }
        foreach (var p in MainViewModel.PageKeys) yield return $"page_{p}";
    }

    [Fact]
    public void Every_key_the_app_uses_is_in_english()
    {
        var en = Strings.Table("en");
        var missing = UsedKeys().Distinct().Where(k => !en.ContainsKey(k)).ToList();
        Assert.True(missing.Count == 0, "missing in en.toml [win]: " + string.Join(", ", missing));
        Assert.True(UsedKeys().Count() > 150, "the scan found the keys");
    }

    [Theory]
    [InlineData("nl")]
    [InlineData("de")]
    [InlineData("fr")]
    [InlineData("es")]
    public void Every_language_has_the_same_keys_and_placeholders(string lang)
    {
        var en = Strings.Table("en");
        var t = Strings.Table(lang);
        Assert.Equal(en.Keys.OrderBy(k => k), t.Keys.OrderBy(k => k));
        foreach (var (k, v) in en)
        {
            var a = Placeholder().Matches(v).Select(m => m.Value).OrderBy(x => x);
            var b = Placeholder().Matches(t[k]).Select(m => m.Value).OrderBy(x => x);
            Assert.True(a.SequenceEqual(b), $"{lang}.{k}: placeholders differ");
            Assert.True(v.Length == 0 || t[k].Length > 0, $"{lang}.{k} is empty");
        }
    }

    [Fact]
    public void Toml_subset()
    {
        var t = Toml.Parse("# c\n[a]\nx = \"1 \\\"q\\\" \\u00e9\\n\"\ny = \"\"\"\nline one\nline two\"\"\"\n[b]\nz = \"\"\n");
        Assert.Equal("1 \"q\" é\n", t["a"]["x"]);
        Assert.Equal("line one\nline two", t["a"]["y"]);
        Assert.Equal("", t["b"]["z"]);
        Assert.Throws<FormatException>(() => Toml.Parse("[a]\nx = 3\n"));
    }

    [Fact]
    public void Fallback_and_placeholders()
    {
        var s = Strings.Load("xx");
        Assert.Equal("en", s.Language);
        Assert.Equal("[no_such_key]", s["no_such_key"]);
        Assert.Contains("C:\\x", s.F("remove_body", ("name", "d"), ("path", "C:\\x")));
        Assert.Equal("de", Strings.LanguageFor(new System.Globalization.CultureInfo("de-CH")));
        Assert.Equal("en", Strings.LanguageFor(new System.Globalization.CultureInfo("ja-JP")));
        Assert.NotEqual(Strings.Load("nl")["page_checks"], Strings.Load("en")["page_checks"]);
    }
}
