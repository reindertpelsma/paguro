using System.Text.Json.Nodes;
using FlaUI.Core.Tools;
using Paguro.Testing;
using Xunit;

namespace Paguro.Gui.UiTests;

/// <summary>The main flows (INTERFACES §11.7 "UI automation with FlaUI"):
/// launch, the checks screen, the protection choice, the restart dialog;
/// with screenshots of every screen.</summary>
[Collection("gui")]
public class FlowTests
{
    /// <summary>A TextBlock's text (UIA gives it as the Name).</summary>
    static string Text(FlaUI.Core.AutomationElements.AutomationElement e) =>
        e.Properties.Name.TryGetValue(out var n) ? n ?? "" : "";

    [Fact]
    public void Launch_shows_every_screen_and_the_checks()
    {
        using var g = new GuiApp();
        Assert.Equal("paguro", g.Window.Title);
        foreach (var p in Paguro.Gui.ViewModels.MainViewModel.PageKeys)
            Assert.Equal(g.S[$"page_{p}"], g.Find("nav_" + p).Name);
        g.FindName(g.S["check_fast_startup"]);
        var summary = Retry.WhileEmpty(() => Text(g.Find("ChecksSummary")), TimeSpan.FromSeconds(10)).Result;
        Assert.Contains(summary, new[] { g.S["checks_ready"], g.S["checks_not_ready"] });
        g.Shot("checks");
        g.Called("checks.list");
    }

    [Fact]
    public void A_check_is_fixed_after_confirming()
    {
        using var g = new GuiApp();
        g.Click(g.Find("fix_fast_startup"));
        var yes = g.DialogPrimary();
        Assert.Equal(g.S["fix_yes"], yes.Name);
        g.Shot("checks-fix-dialog");
        g.Click(yes);
        var call = g.Called("checks.fix");
        Assert.Equal("fast_startup", call.Params["id"]!.GetValue<string>());
    }

    static string Options(string windows) => new JsonObject
    {
        ["asked"] = true, ["target"] = "image", ["windows"] = windows, ["tpm_present"] = true,
        ["choices"] = new JsonArray(
            new JsonObject { ["id"] = "tpm_pin", ["offered"] = true, ["recommended"] = true, ["reason"] = "" },
            new JsonObject { ["id"] = "passphrase", ["offered"] = true, ["recommended"] = false, ["reason"] = "" },
            new JsonObject { ["id"] = "tpm_only", ["offered"] = windows == "tpm_only", ["recommended"] = false, ["reason"] = "" },
            new JsonObject { ["id"] = "unprotected", ["offered"] = false, ["recommended"] = false, ["reason"] = "" }),
        ["pin_bypass_default"] = true, ["keyboard_suggested"] = "fr", ["current"] = null,
        ["keyboards"] = new JsonArray(
            new JsonObject { ["id"] = "us", ["name"] = "English (US)" },
            new JsonObject { ["id"] = "de", ["name"] = "German" },
            new JsonObject { ["id"] = "fr", ["name"] = "French" }),
    }.ToJsonString();

    static void Protection(FakeServer s)
    {
        s.OnData("protection.options", Options("tpm_pin"));
        s.On("protection.check", p => p["pin"]!.GetValue<string>().Contains('ê')
            ? FakeServer.Error("refused", 3, "refused", JsonNode.Parse("""{"ok":false,"keyboard":"fr","length":2,"refused":[{"char":"ê","position":1,"reason":"dead key"}]}"""))
            : FakeServer.Ok(JsonNode.Parse("""{"ok":true,"keyboard":"fr","length":4,"refused":[]}""")));
        s.OnData("protection.set", """{"choice":"tpm_pin","keyboard":"fr","pin_bypass":true,"pending":[]}""");
    }

    [Fact]
    public void Protection_choice_caps_tpm_only_refuses_dead_keys_and_applies()
    {
        using var g = new GuiApp(setup: Protection);
        g.Go("protection");
        g.FindName(g.S["choice_tpm_pin"]);
        // TPM-only is shown with the reason it is not offered (Windows uses TPM + PIN).
        g.FindName(g.S["choice_tpm_only_not_offered"]);
        Assert.Equal("0000040C", g.Called("protection.options").Params["klid"]!.GetValue<string>());
        var bypass = g.Find("PinBypass");
        Assert.Equal(FlaUI.Core.Definitions.ToggleState.On, bypass.Patterns.Toggle.Pattern.ToggleState.Value);
        g.Shot("protection");

        g.Type(g.Find("Secret"), "aê");
        g.Type(g.Find("SecretAgain"), "aê");
        var refused = Retry.WhileEmpty(() => Text(g.Find("Refused")), TimeSpan.FromSeconds(10)).Result;
        Assert.Contains("ê", refused);
        Assert.False(g.Find("Apply").IsEnabled);
        g.Shot("protection-dead-key");

        g.Type(g.Find("Secret"), "4711");
        g.Type(g.Find("SecretAgain"), "4711");
        Retry.WhileTrue(() => Text(g.Find("Refused")).Length > 0, TimeSpan.FromSeconds(10));
        Retry.WhileFalse(() => g.Find("Apply").IsEnabled, TimeSpan.FromSeconds(10));
        g.Click(g.Find("Apply"));
        var apply = g.DialogPrimary();
        g.Shot("protection-confirm");
        g.Click(apply);
        var set = g.Called("protection.set");
        Assert.Equal("tpm_pin", set.Params["choice"]!.GetValue<string>());
        Assert.Equal("4711", set.Params["pin"]!.GetValue<string>());
        Assert.Equal("fr", set.Params["keyboard"]!.GetValue<string>());
        Assert.True(set.Params["pin_bypass"]!.GetValue<bool>());
    }

    [Fact]
    public void Restart_dialog_summarises_then_restarts()
    {
        using var g = new GuiApp();
        g.Go("restart");
        g.FindName(g.S.F("restart_boots_default", ("entry", "debian")));
        g.Shot("restart");
        Retry.WhileFalse(() => g.Find("Restart").IsEnabled, TimeSpan.FromSeconds(10));
        g.Click(g.Find("Restart"));
        var now = g.DialogPrimary();
        Assert.Equal(g.S["restart_now"], now.Name);
        g.Shot("restart-dialog");
        g.Server.ClearCalls();
        g.Click(now);
        var call = g.Called("restart-linux");
        Assert.True(call.Params["yes"]!.GetValue<bool>());
        Assert.False(call.Params.ContainsKey("dry_run"));
    }

    [Fact]
    public void Read_only_user_sees_why()
    {
        using var g = new GuiApp(caller: """{"user":"PC\\guest","admin":false,"elevated":false}""");
        var banner = g.Find("Banner");
        g.FindName(g.S["banner_read_only"]);
        g.Shot("read-only");
        g.FindName(g.S["check_fast_startup"]);
        Assert.Null(g.Window.FindFirstDescendant(cf => cf.ByAutomationId("fix_fast_startup")));
        _ = banner;
    }

    [Fact]
    public void Every_other_screen_renders()
    {
        using var g = new GuiApp();
        foreach (var p in new[] { "distributions", "hardware", "secureboot", "uninstall" })
        {
            g.Go(p);
            Assert.Equal(g.S[$"{p}_title"], g.Find("PageTitle").Name);
            Thread.Sleep(600);
            g.Shot(p);
        }
        g.Go("uninstall");
        g.FindName(g.S["untouched_windows"]);
        g.Go("secureboot");
        g.FindName(g.S["mok_title"]);
    }

    [Theory]
    [InlineData("nl")]
    [InlineData("de")]
    [InlineData("fr")]
    [InlineData("es")]
    public void Languages(string lang)
    {
        using var g = new GuiApp(lang, Protection);
        Assert.Equal(g.S["page_checks"], g.Find("nav_checks").Name);
        g.FindName(g.S["check_fast_startup"]);
        g.Shot("checks");
        g.Go("protection");
        g.FindName(g.S["choice_tpm_pin"]);
        g.Shot("protection");
    }
}

/// <summary>Every screen against a real service (PAGURO_GUI_TOUR_PIPE, e.g.
/// "paguro" in the local Windows VM): the real machine's checks, hardware,
/// Secure Boot state. Read-only; nothing is changed.</summary>
[Collection("gui")]
public class TourTests
{
    [Fact]
    public void Tour_of_a_real_service()
    {
        var pipe = Environment.GetEnvironmentVariable("PAGURO_GUI_TOUR_PIPE");
        if (string.IsNullOrEmpty(pipe)) return;
        using var g = new GuiApp(realPipe: pipe);
        g.FindName(g.S["check_uefi"], seconds: 60);
        g.Shot("real-checks");
        foreach (var p in new[] { "distributions", "hardware", "protection", "secureboot", "restart", "uninstall" })
        {
            g.Go(p);
            Assert.Equal(g.S[$"{p}_title"], g.Find("PageTitle").Name);
            Thread.Sleep(2500);
            g.Shot("real-" + p);
        }
    }
}

[CollectionDefinition("gui", DisableParallelization = true)]
public class GuiCollection { }
