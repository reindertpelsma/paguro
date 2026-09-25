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
    [Parameter] public SecureString? Passphrase { get; set; }

    protected override SecureString? SecretFor(string name) => name == "linux_passphrase" ? Passphrase : null;

    protected override void ProcessRecord() =>
        WriteObject(Mutate<Preflight>(PaguroMethods.Repair, new RepairParams { Stage = Stage.IsPresent ? true : null, Bootstrap = Bootstrap.IsPresent ? true : null }, "paguro", "repair")?.Data);
}

/// <summary>Remove paguro from this machine (DESIGN §6b). Two phases around a
/// reboot: run it again after restarting. -WhatIf shows what is and is not touched.</summary>
[Cmdlet(VerbsLifecycle.Uninstall, "Paguro", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High), OutputType(typeof(UninstallResult)), PaguroMethod("uninstall")]
public sealed class UninstallPaguro : PaguroCmdlet
{
    [Parameter] public SwitchParameter DeleteImages { get; set; }
    [Parameter] public SwitchParameter SkipFinalBoot { get; set; }

    protected override void ProcessRecord()
    {
        var p = new UninstallParams { Yes = true, DeleteImages = DeleteImages ? true : null, SkipFinalBoot = SkipFinalBoot ? true : null };
        WriteObject(Mutate<UninstallResult>(PaguroMethods.Uninstall, p, "this machine", DeleteImages ? "uninstall paguro AND delete the Linux images" : "uninstall paguro")?.Data);
    }
}
