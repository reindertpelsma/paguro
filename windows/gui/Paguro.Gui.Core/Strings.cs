using System.Globalization;
using System.Text;

namespace Paguro.Gui;

/// <summary>The app's strings: the <c>[win]</c> table of the shared
/// <c>themes/default/strings/&lt;lang&gt;.toml</c> (INTERFACES.md §13.5), with
/// English as the fallback for a key a language lacks. <c>{name}</c> is a
/// placeholder.</summary>
public sealed class Strings
{
    public static readonly string[] Languages = ["en", "nl", "de", "fr", "es"];

    readonly Dictionary<string, string> table;
    readonly Dictionary<string, string> english;

    public string Language { get; }

    Strings(string lang, Dictionary<string, string> table, Dictionary<string, string> english)
    {
        Language = lang;
        this.table = table;
        this.english = english;
    }

    /// <summary>The <c>[win]</c> table of an embedded language file.</summary>
    public static Dictionary<string, string> Table(string lang)
    {
        using var s = typeof(Strings).Assembly.GetManifestResourceStream($"strings.{lang}.toml")
            ?? throw new ArgumentException($"no strings for {lang}");
        using var r = new StreamReader(s, Encoding.UTF8);
        var all = Toml.Parse(r.ReadToEnd());
        return all.TryGetValue("win", out var w) ? w : new Dictionary<string, string>();
    }

    public static Strings Load(string lang)
    {
        if (!Languages.Contains(lang)) lang = "en";
        var en = Table("en");
        return new Strings(lang, lang == "en" ? en : Table(lang), en);
    }

    /// <summary>The language for a culture (Windows' display language), falling back to en.</summary>
    public static string LanguageFor(CultureInfo c)
    {
        var two = c.TwoLetterISOLanguageName;
        return Languages.Contains(two) ? two : "en";
    }

    public string this[string key] =>
        table.TryGetValue(key, out var v) ? v : english.TryGetValue(key, out var e) ? e : $"[{key}]";

    /// <summary>A string with its placeholders filled: F("x", ("n", 3)).</summary>
    public string F(string key, params (string Name, object Value)[] args)
    {
        var s = this[key];
        foreach (var (n, v) in args)
            s = s.Replace("{" + n + "}", Convert.ToString(v, CultureInfo.CurrentCulture));
        return s;
    }

    public IReadOnlyDictionary<string, string> Table() => table;
}

/// <summary>The TOML the string files use: [sections], comments, and
/// key = "basic" or """multi-line""" strings with \\ \" \n \t \uXXXX escapes.</summary>
public static class Toml
{
    public static Dictionary<string, Dictionary<string, string>> Parse(string text)
    {
        var result = new Dictionary<string, Dictionary<string, string>>();
        var section = new Dictionary<string, string>();
        result[""] = section;
        var lines = text.Replace("\r\n", "\n").Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            if (line[0] == '[')
            {
                var name = line.Trim('[', ']').Trim();
                if (!result.TryGetValue(name, out section!))
                    result[name] = section = new Dictionary<string, string>();
                continue;
            }
            var eq = line.IndexOf('=');
            if (eq < 0) throw new FormatException($"line {i + 1}: expected key = value");
            var key = line[..eq].Trim();
            var rest = line[(eq + 1)..].Trim();
            if (rest.StartsWith("\"\"\""))
            {
                var sb = new StringBuilder();
                var body = rest[3..];
                while (true)
                {
                    var end = body.IndexOf("\"\"\"", StringComparison.Ordinal);
                    if (end >= 0) { sb.Append(body[..end]); break; }
                    sb.Append(body).Append('\n');
                    if (++i >= lines.Length) throw new FormatException($"{key}: unterminated \"\"\"");
                    body = lines[i];
                }
                var v = sb.ToString();
                if (v.StartsWith('\n')) v = v[1..];
                section[key] = Unescape(v);
            }
            else if (rest.StartsWith('"'))
            {
                var end = ClosingQuote(rest);
                section[key] = Unescape(rest[1..end]);
            }
            else throw new FormatException($"line {i + 1}: {key}: only strings are supported");
        }
        return result;
    }

    static int ClosingQuote(string s)
    {
        for (var j = 1; j < s.Length; j++)
        {
            if (s[j] == '\\') { j++; continue; }
            if (s[j] == '"') return j;
        }
        throw new FormatException("unterminated string");
    }

    static string Unescape(string s)
    {
        var sb = new StringBuilder(s.Length);
        for (var j = 0; j < s.Length; j++)
        {
            if (s[j] != '\\' || j + 1 >= s.Length) { sb.Append(s[j]); continue; }
            var c = s[++j];
            switch (c)
            {
                case 'n': sb.Append('\n'); break;
                case 't': sb.Append('\t'); break;
                case '"': sb.Append('"'); break;
                case '\\': sb.Append('\\'); break;
                case 'u' when j + 4 < s.Length:
                    sb.Append((char)Convert.ToInt32(s.Substring(j + 1, 4), 16));
                    j += 4;
                    break;
                default: sb.Append('\\').Append(c); break;
            }
        }
        return sb.ToString();
    }
}
