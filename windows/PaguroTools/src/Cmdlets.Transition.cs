using System.Text.Json;
using System.Management.Automation;
using System.Security;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>Everything the next Linux boot depends on (DESIGN §4.6).</summary>
[Cmdlet(VerbsDiagnostic.Test, "PaguroPreflight"), OutputType(typeof(Preflight)), PaguroMethod("preflight")]
public sealed class TestPaguroPreflight : PaguroCmdlet
{
    /// <summary>Also fix what can be fixed (administrators).</summary>
    [Parameter] public SwitchParameter Repair { get; set; }

    protected override void ProcessRecord() =>
        WriteObject(Call<Preflight>(PaguroMethods.Preflight, new PreflightParams { Repair = Repair.IsPresent ? true : null })?.Data);
}

/// <summary>Restart into Linux: pre-flight, PIN bypass or setupTPM, BootNext,
/// restart. `Get-PaguroDistribution | ? Size -gt 20GB | Start-PaguroLinux`.</summary>
[Cmdlet(VerbsLifecycle.Restart, "PaguroLinux", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High), OutputType(typeof(Preflight)), PaguroMethod("restart-linux")]
[Alias("Start-PaguroLinux")]
public sealed class RestartPaguroLinux : PaguroCmdlet
{
    /// <summary>Boot this entry once instead of the default.</summary>
    [Parameter(Position = 0, ValueFromPipelineByPropertyName = true), Alias("Name")]
    public string? Entry { get; set; }

    /// <summary>Prepare everything but do not restart.</summary>
    [Parameter] public SwitchParameter NoRestart { get; set; }

    /// <summary>The Linux passphrase, if setupTPM has to be staged.</summary>
    [Parameter] public SecureString? Passphrase { get; set; }

    bool done;

    protected override SecureString? SecretFor(string name) => name == "linux_passphrase" ? Passphrase : null;

    protected override void ProcessRecord()
    {
        // Several objects piped in: the first one is the one that boots.
        if (done) { WriteWarning($"already restarting into {Entry}: ignoring the rest of the pipeline"); return; }
        var p = new RestartLinuxParams { Entry = Entry, Yes = NoRestart.IsPresent ? null : true };
        var r = Mutate<Preflight>(PaguroMethods.RestartLinux, p, Entry ?? "the default entry", NoRestart ? "prepare the restart into Linux" : "restart into Linux");
        done = r != null && !r.DryRun;
        WriteObject(r?.Data);
    }
}

/// <summary>Stage a one-shot setupTPM for the next boot.</summary>
[Cmdlet(VerbsLifecycle.Request, "PaguroSetupTpm", SupportsShouldProcess = true), OutputType(typeof(StageSetup)), PaguroMethod("stage-setup")]
public sealed class RequestPaguroSetupTpm : PaguroCmdlet
{
    [Parameter] public SecureString? Passphrase { get; set; }

    protected override SecureString? SecretFor(string name) => name == "linux_passphrase" ? Passphrase : null;

    protected override void ProcessRecord() =>
        WriteObject(Mutate<StageSetup>(PaguroMethods.StageSetup, new NoParams { LinuxPassphrase = Passphrase == null ? null : Plain(Passphrase) }, "the next boot", "stage setupTPM")?.Data);
}

/// <summary>Re-install ESP files and the entry; stage or bootstrap when needed (DESIGN §7).</summary>
[Cmdlet(VerbsDiagnostic.Repair, "Paguro", SupportsShouldProcess = true), OutputType(typeof(Preflight)), PaguroMethod("repair")]
public sealed class RepairPaguro : PaguroCmdlet
{
    [Parameter] public SwitchParameter Stage { get; set; }
    [Parameter] public SwitchParameter Bootstrap { get; set; }
    /// <summary>Only paguro's own files, service, driver and entries.</summary>
    [Parameter] public SwitchParameter AppOnly { get; set; }
    [Parameter] public SecureString? Passphrase { get; set; }

    protected override SecureString? SecretFor(string name) => name == "linux_passphrase" ? Passphrase : null;

    protected override void ProcessRecord() =>
        WriteObject(Mutate<Preflight>(PaguroMethods.Repair, new RepairParams { Stage = Stage.IsPresent ? true : null, Bootstrap = Bootstrap.IsPresent ? true : null, AppOnly = AppOnly.IsPresent ? true : null }, "paguro", "repair")?.Data);
}

/// <summary>Remove paguro from this machine (DESIGN §6b, INTERFACES §11.7a).
/// Two phases around a reboot; the second finishes by itself at the next
/// administrator logon. -WhatIf shows what is and is not touched. The Linux
/// images: -KeepImages or -DeleteImages, never silently. Runs paguro.exe
/// itself (elevated): the service is one of the things it removes.</summary>
[Cmdlet(VerbsLifecycle.Uninstall, "Paguro", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High, DefaultParameterSetName = "Keep"), OutputType(typeof(UninstallResult)), PaguroMethod("uninstall")]
public sealed class UninstallPaguro : PaguroCmdlet
{
    [Parameter(Mandatory = true, ParameterSetName = "Keep")] public SwitchParameter KeepImages { get; set; }
    [Parameter(Mandatory = true, ParameterSetName = "Delete")] public SwitchParameter DeleteImages { get; set; }
    [Parameter] public SwitchParameter SkipFinalBoot { get; set; }

    protected override void ProcessRecord()
    {
        var what = DeleteImages ? "uninstall paguro AND delete the Linux images" : "uninstall paguro, keeping the Linux images";
        if (!ShouldProcess("this machine", what))
        {
            if (!WhatIfRequested) return;
            var plan = Call<UninstallResult>(PaguroMethods.Uninstall, new UninstallParams { DryRun = true, DeleteImages = DeleteImages ? true : null });
            if (plan != null) foreach (var l in plan.Lines) Host.UI.WriteLine("What if: " + l);
            WriteObject(plan?.Data);
            return;
        }
        var args = new List<string> { "uninstall", "--yes", DeleteImages ? "--delete-images" : "--keep-images" };
        if (SkipFinalBoot) args.Add("--skip-final-boot");
        var data = RunPaguro(PaguroExe(), args.ToArray());
        if (data != null) WriteObject(data.Deserialize<UninstallResult>(PaguroJson.Options));
    }
}

/// <summary>Install paguro itself from a downloaded paguro.exe (INTERFACES
/// §11.7a): Program Files, the service, the minifilter, Apps & Features.
/// Runs that paguro.exe (elevated): there is no service yet to ask.</summary>
[Cmdlet(VerbsLifecycle.Install, "Paguro", SupportsShouldProcess = true), OutputType(typeof(SetupInstall)), PaguroMethod("setup.install")]
public sealed class InstallPaguro : PaguroCmdlet
{
    /// <summary>The paguro.exe to install from (default: $env:PAGURO_EXE, or paguro.exe on PATH).</summary>
    [Parameter(Position = 0)] public string? Path { get; set; }

    protected override void ProcessRecord()
    {
        var exe = Path == null ? PaguroExe() : FullPath(Path);
        if (!ShouldProcess(exe, "install paguro"))
        {
            if (WhatIfRequested) WriteObject(RunPaguro(exe, "install", "--dry-run")?.Deserialize<SetupInstall>(PaguroJson.Options));
            return;
        }
        WriteObject(RunPaguro(exe, "install")?.Deserialize<SetupInstall>(PaguroJson.Options));
    }
}

/// <summary>Is paguro installed, and what does the installed paguro.exe carry.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroSetup"), OutputType(typeof(SetupState)), PaguroMethod("setup.status")]
public sealed class GetPaguroSetup : PaguroCmdlet
{
    protected override void ProcessRecord() => WriteObject(Call<SetupState>(PaguroMethods.SetupStatus, new NoParams())?.Data);
}
