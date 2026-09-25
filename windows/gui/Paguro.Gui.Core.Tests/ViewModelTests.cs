using System.Text.Json.Nodes;
using Paguro.Gui.ViewModels;
using Paguro.Testing;
using Xunit;

namespace Paguro.Gui.Tests;

/// <summary>The screens' view models against a fake service (the API
/// fixtures, made by the Rust side from the real methods), through the real
/// pipe client.</summary>
public class ViewModelTests
{
    const string Admin = """{"user":"PC\\me","admin":true,"elevated":false}""";
    const string Reader = """{"user":"PC\\guest","admin":false,"elevated":false}""";

    [Fact]
    public async Task Session_connects_and_says_who_we_are()
    {
        using var rig = new Rig(Admin);
        Assert.True(await rig.Session.EnsureAsync());
        Assert.True(rig.Session.Connected);
        Assert.False(rig.Session.ReadOnly);
        Assert.Equal("", rig.Session.Banner);

        using var ro = new Rig(Reader);
        await ro.Session.EnsureAsync();
        Assert.True(ro.Session.ReadOnly);
        Assert.Equal(ro.S["banner_read_only"], ro.Session.Banner);
    }

    [Fact]
    public async Task No_service_offers_to_install_it_with_one_uac_prompt()
    {
        var dialogs = new FakeDialogs();
        var s = new Session(Session.Pipe("paguro-nobody-" + Guid.NewGuid().ToString("N")[..8]), Strings.Load("en"), dialogs);
        var main = new MainViewModel(s);
        await main.StartAsync();
        Assert.True(s.NoService);
        Assert.Equal(s.S["banner_no_service"], s.Banner);
        Assert.True(main.InstallService.CanExecute(null));
        await main.InstallService.ExecuteAsync();
        Assert.Contains(dialogs.Ran, r => r.StartsWith("elevated ") && r.EndsWith("paguro.exe --direct service install"));
    }

    [Fact]
    public async Task Checks_are_explained_and_fixable()
    {
        using var rig = new Rig(Admin);
        var vm = new ChecksViewModel(rig.Session);
        await vm.LoadAsync();
        Assert.Equal(8, vm.Items.Count);
        var fs = vm.Items.Single(i => i.Id == "fast_startup");
        Assert.Equal(rig.S["check_fast_startup"], fs.Title);
        Assert.Equal(rig.S["check_fast_startup_why"], fs.Why);
        Assert.True(fs.CanFix);
        Assert.True(vm.Fix.CanExecute(fs));
        Assert.False(vm.Fix.CanExecute(vm.Items.Single(i => i.Id == "uefi")));
        await vm.FixAsync(fs);
        Assert.Equal("fast_startup", rig.P("checks.fix", "id"));
        Assert.Contains("confirm:" + rig.S["fix_title"], rig.Dialogs.Asked);
        // Declined: nothing is sent.
        rig.Server.ClearCalls();
        rig.Dialogs.Answer = false;
        await vm.FixAsync(fs);
        Assert.DoesNotContain(rig.Server.Calls, c => c.Method == "checks.fix");
    }

    [Fact]
    public async Task A_reader_cannot_fix()
    {
        using var rig = new Rig(Reader);
        var vm = new ChecksViewModel(rig.Session);
        await vm.LoadAsync();
        Assert.False(vm.Fix.CanExecute(vm.Items.Single(i => i.Id == "fast_startup")));
    }

    [Fact]
    public async Task Distributions_list_install_and_maintenance()
    {
        using var rig = new Rig(Admin);
        var vm = new DistributionsViewModel(rig.Session);
        await vm.LoadAsync();
        Assert.Equal(2, vm.Items.Count);
        var debian = vm.Items.Single(i => i.Name == "debian");
        Assert.True(debian.IsImage);
        Assert.Equal("32 GB", debian.SizeText);
        var ubuntu = vm.Items.Single(i => i.IsWsl);

        // The install form.
        Assert.False(vm.CanInstall);
        vm.NewName = "fedora";
        Assert.Equal(@"C:\paguro\fedora.vhd", vm.NewPath);
        vm.IsoPath = @"C:\iso\fedora.iso";
        Assert.True(vm.CanInstall);
        rig.Server.On("install", FakeServer.FromFixture(File.ReadAllText(Path.Combine(Paths.Fixtures, "install.1.json"))));
        await vm.InstallAsync();
        Assert.Equal("iso", rig.P("install", "source"));
        Assert.Equal(@"C:\iso\fedora.iso", rig.P("install", "iso"));
        Assert.Contains("STUB", vm.Error);
        Assert.Equal("done", vm.Operation!.Steps.Single(s => s.Id == "host").State);
        Assert.Equal("failed", vm.Operation.Steps.Single(s => s.Id == "build").State);
        Assert.Equal(rig.S["step_install_build"], vm.Operation.Steps.Single(s => s.Id == "build").Title);

        // Make the WSL distribution bootable.
        await vm.MakeBootableAsync(ubuntu);
        Assert.Equal("wsl", rig.P("install", "source"));
        Assert.Equal("Ubuntu", rig.P("install", "wsl_distro"));

        // Open in a container, then close.
        await vm.OpenAsync(debian);
        Assert.Equal("debian", rig.P("distro.enter", "name"));
        Assert.Contains(rig.Dialogs.Ran, r => r.StartsWith("wt.exe wsl.exe --user root"));
        Assert.True(vm.Detach.CanExecute(null));
        await vm.DetachAsync();
        Assert.Equal("debian", rig.P("distro.leave", "name"));
        Assert.Null(vm.Attached);

        // Rename, remove with the image, grow (a stub, said plainly).
        await vm.RenameAsync(debian);
        Assert.Equal("renamed", rig.P("distro.rename", "new_name"));
        await vm.RemoveAsync(debian);
        Assert.Equal("true", rig.P("distro.remove", "delete_image"));
        await vm.GrowAsync(debian);
        Assert.Contains(rig.Dialogs.Asked, a => a.StartsWith("message:" + rig.S["grow_title"]) && a.Contains("STUB"));
    }

    [Fact]
    public async Task Manual_install_opens_the_shell_the_service_names()
    {
        using var rig = new Rig(Admin);
        rig.Server.OnData("install", """{"steps":[{"id":"build","state":"awaiting_user"}],"shell":["wsl.exe","--user","root"]}""", "pending", []);
        var vm = new DistributionsViewModel(rig.Session) { NewName = "arch", IsoPath = @"C:\a.iso", Manual = true };
        await vm.InstallAsync();
        Assert.Equal("true", rig.P("install", "shell"));
        Assert.Contains(rig.Dialogs.Ran, r => r == "wt.exe wsl.exe --user root");
        Assert.Contains("--finish", vm.Notice);
    }

    [Fact]
    public async Task Hardware_shows_the_export_and_what_the_installer_is_told()
    {
        using var rig = new Rig(Admin);
        var vm = new HardwareViewModel(rig.Session);
        await vm.LoadAsync();
        Assert.Contains(vm.Rows, r => r.Kind == rig.S["hw_cpu"]);
        Assert.Contains(vm.Rows, r => r.Kind == rig.S["hw_board"]);
        Assert.Contains(vm.Rows, r => r.Kind == rig.S["hw_disk"]);
        Assert.NotEmpty(vm.Told);
        Assert.Equal("gpu", HardwareViewModel.ClassOf("030000"));
        Assert.Equal("wifi", HardwareViewModel.ClassOf("028000"));
    }

    static string Options(string windows, bool asked, params (string Id, bool Offered, bool Recommended)[] choices)
    {
        var c = new JsonArray(choices.Select(x => (JsonNode)new JsonObject { ["id"] = x.Id, ["offered"] = x.Offered, ["recommended"] = x.Recommended, ["reason"] = "r" }).ToArray());
        return new JsonObject
        {
            ["asked"] = asked, ["target"] = "image", ["windows"] = windows, ["tpm_present"] = true, ["choices"] = c,
            ["pin_bypass_default"] = true, ["keyboard_suggested"] = "de", ["current"] = null,
            ["keyboards"] = new JsonArray(new JsonObject { ["id"] = "us", ["name"] = "English (US)" }, new JsonObject { ["id"] = "de", ["name"] = "German" }, new JsonObject { ["id"] = "fr", ["name"] = "French" }),
        }.ToJsonString();
    }

    [Fact]
    public async Task Protection_offers_what_windows_allows_and_defaults_right()
    {
        using var rig = new Rig(Admin);
        var vm = new ProtectionViewModel(rig.Session);
        await vm.LoadAsync("00000407");
        // The demo machine: BitLocker with the TPM alone.
        Assert.True(vm.Asked);
        Assert.Equal(rig.S["windows_tpm_only"], vm.WindowsText);
        Assert.Equal("tpm_pin", vm.Selected!.Id);
        Assert.True(vm.PinBypass);
        Assert.True(vm.ShowPinBypass);
        Assert.Equal("00000407", rig.P("protection.options", "klid"));
        Assert.True(vm.Choices.Single(c => c.Id == "tpm_only").Offered);
        Assert.False(vm.Choices.Single(c => c.Id == "unprotected").Offered);
    }

    [Fact]
    public async Task Tpm_only_is_capped_at_windows_level()
    {
        using var rig = new Rig(Admin);
        rig.Server.OnData("protection.options", Options("tpm_pin", true, ("tpm_pin", true, true), ("passphrase", true, false), ("tpm_only", false, false), ("unprotected", false, false)));
        var vm = new ProtectionViewModel(rig.Session);
        await vm.LoadAsync(null);
        var tpmOnly = vm.Choices.Single(c => c.Id == "tpm_only");
        Assert.False(tpmOnly.Offered);
        Assert.Equal(rig.S["choice_tpm_only_not_offered"], tpmOnly.Reason);
        vm.Selected = tpmOnly;
        Assert.Equal("tpm_pin", vm.Selected!.Id);
        Assert.Equal("de", vm.Keyboard!.Id);
    }

    [Fact]
    public async Task Not_asked_without_bitlocker()
    {
        using var rig = new Rig(Admin);
        rig.Server.OnData("protection.options", Options("off", false));
        var vm = new ProtectionViewModel(rig.Session);
        await vm.LoadAsync(null);
        Assert.False(vm.Asked);
        Assert.True(vm.NotAsked);
        Assert.Empty(vm.Choices);
        Assert.False(vm.CanApply);
    }

    [Fact]
    public async Task Dead_keys_are_refused_and_a_good_pin_is_applied()
    {
        using var rig = new Rig(Admin);
        rig.Server.On("protection.check", p => p["pin"]!.GetValue<string>().Contains('ê')
            ? FakeServer.Error("refused", 3, "no", JsonNode.Parse("""{"ok":false,"keyboard":"fr","length":2,"refused":[{"char":"ê","position":1,"reason":"dead key"}]}"""))
            : FakeServer.Ok(JsonNode.Parse("""{"ok":true,"keyboard":"fr","length":4,"refused":[]}""")));
        var vm = new ProtectionViewModel(rig.Session);
        await vm.LoadAsync(null);
        vm.Keyboard = vm.Keyboards.Single(k => k.Id == "fr");
        vm.Secret = "aê";
        vm.SecretAgain = "aê";
        await vm.CheckAsync();
        Assert.Contains("ê", vm.Refused);
        Assert.Contains("French", vm.Refused);
        Assert.False(vm.CanApply);
        vm.Secret = "4711";
        vm.SecretAgain = "4712";
        await vm.CheckAsync();
        Assert.Equal("", vm.Refused);
        Assert.True(vm.Mismatch);
        Assert.False(vm.CanApply);
        vm.SecretAgain = "4711";
        Assert.True(vm.CanApply);
        vm.PinBypass = false;
        await vm.ApplyAsync();
        Assert.Equal("tpm_pin", rig.P("protection.set", "choice"));
        Assert.Equal("4711", rig.P("protection.set", "pin"));
        Assert.Equal("fr", rig.P("protection.set", "keyboard"));
        Assert.Equal("false", rig.P("protection.set", "pin_bypass"));
        Assert.Equal("", vm.Secret);
        Assert.NotNull(vm.Result);
    }

    [Fact]
    public async Task Secure_boot_explains_mokmanager_before_it_happens()
    {
        using var rig = new Rig(Admin);
        var vm = new SecureBootViewModel(rig.Session);
        await vm.LoadAsync();
        Assert.True(vm.On);
        Assert.True(vm.ShowMok);
        Assert.Equal(rig.S["sb_mok_ahead"], vm.Headline);
        Assert.Equal(4, vm.MokSteps.Length);
        rig.Server.OnData("secure-boot.status", """{"secure_boot":true,"mokmanager_next_boot":false,"enrolment_needed":false,"db_change_needed":true,"bitlocker_suspend_needed":true}""");
        await vm.LoadAsync();
        Assert.True(vm.DbChange);
        Assert.True(vm.BitLockerSuspend);
        Assert.Equal(rig.S["sb_db_change"], vm.Headline);
    }

    [Fact]
    public async Task Restart_into_linux_with_an_entry_choice()
    {
        using var rig = new Rig(Admin);
        var vm = new RestartViewModel(rig.Session);
        await vm.LoadAsync();
        Assert.Equal(["debian"], vm.Entries);
        Assert.Equal("debian", vm.Entry);
        await vm.PlanAsync();
        Assert.True(vm.Ready);
        Assert.Contains(rig.S.F("restart_boots_default", ("entry", "debian")), vm.Summary);
        Assert.Equal("true", rig.P("restart-linux", "dry_run"));
        Assert.True(vm.Restart.CanExecute(null));
        await vm.RestartAsync();
        var last = rig.Last("restart-linux");
        Assert.Equal("true", last.Params["yes"]?.ToString());
        Assert.False(last.Params.ContainsKey("dry_run"));
        Assert.False(last.Params.ContainsKey("entry"), "the default needs no PaguroBootTarget");
    }

    [Fact]
    public async Task Restart_blocked_by_a_failed_check()
    {
        using var rig = new Rig(Admin);
        rig.Server.OnError("restart-linux", "check_failed", 6, "not restarting",
            """{"checks":[{"id":"esp_files","state":"fail","detail":"shim missing"}],"secure_boot":true,"action":null}""");
        var vm = new RestartViewModel(rig.Session);
        await vm.LoadAsync();
        await vm.PlanAsync();
        Assert.False(vm.Ready);
        Assert.Single(vm.Problems);
        Assert.Contains(rig.S["restart_blocked"], vm.Summary);
        Assert.False(vm.Restart.CanExecute(null));
    }

    [Fact]
    public async Task Uninstall_says_what_is_and_is_not_touched()
    {
        using var rig = new Rig(Admin);
        var vm = new UninstallViewModel(rig.Session);
        await vm.LoadAsync();
        Assert.Equal("true", rig.P("uninstall", "dry_run"));
        Assert.DoesNotContain(rig.S["step_uninstall_images"], vm.Touched);
        Assert.Contains(rig.S["untouched_images"], vm.Untouched);
        Assert.Contains(rig.S["untouched_windows"], vm.Untouched);
        vm.DeleteImages = true;
        await vm.LoadAsync();
        Assert.Contains(rig.S["step_uninstall_images"], vm.Touched);
        Assert.DoesNotContain(rig.S["untouched_images"], vm.Untouched);
        await vm.UninstallAsync();
        var last = rig.Last("uninstall");
        Assert.Equal("true", last.Params["yes"]?.ToString());
        Assert.Equal("true", last.Params["delete_images"]?.ToString());
    }

    [Fact]
    public async Task A_secret_the_service_asks_for_is_asked_of_the_user()
    {
        using var rig = new Rig(Admin);
        rig.Server.OnNeedsInput("restart-linux", "linux_passphrase", "Linux passphrase", true, """{"checks":[],"secure_boot":true,"action":{"action":"stage_setup_tpm","reason":"firmware"}}""");
        var r = await rig.Session.CallAsync<Paguro.Api.Preflight>("restart-linux", new Paguro.Api.RestartLinuxParams { Yes = true });
        Assert.NotNull(r);
        Assert.Contains("secret:" + rig.S["secret_title_passphrase"], rig.Dialogs.Asked);
        Assert.Equal("correct horse", rig.P("restart-linux", "linux_passphrase"));
        // Cancelled by the user: nothing more is sent.
        rig.Dialogs.Secret = null;
        rig.Server.ClearCalls();
        Assert.Null(await rig.Session.CallAsync<Paguro.Api.Preflight>("restart-linux", new Paguro.Api.RestartLinuxParams { Yes = true }));
        Assert.Single(rig.Server.Calls);
        Assert.Equal(rig.S["cancelled"], rig.Session.LastError);
    }

    [Theory]
    [InlineData("checks", "checks.list")]
    [InlineData("distributions", "distro.list")]
    [InlineData("hardware", "hw.export")]
    [InlineData("protection", "protection.options")]
    [InlineData("secureboot", "secure-boot.status")]
    [InlineData("restart", "distro.list")]
    [InlineData("uninstall", "uninstall")]
    public async Task Each_screen_loads_its_method(string page, string method)
    {
        using var rig = new Rig(Admin);
        var main = new MainViewModel(rig.Session);
        await main.ShowAsync(page);
        Assert.Contains(rig.Server.Calls, c => c.Method == method);
        Assert.Contains(main.Pages, p => p.Key == page && p.Title == rig.S[$"page_{page}"]);
    }
}
