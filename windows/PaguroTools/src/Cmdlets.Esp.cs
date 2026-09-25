using System.Management.Automation;
using System.Security;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>Install shim, MokManager and paguro.efi on the ESP.</summary>
[Cmdlet(VerbsLifecycle.Install, "PaguroEsp", SupportsShouldProcess = true), OutputType(typeof(EspState)), PaguroMethod("esp.install")]
public sealed class InstallPaguroEsp : PaguroCmdlet
{
    [Parameter(Mandatory = true)] public string Shim { get; set; } = "";
    [Parameter(Mandatory = true)] public string MokManager { get; set; } = "";
    [Parameter(Mandatory = true)] public string Loader { get; set; } = "";

    protected override void ProcessRecord()
    {
        var p = new EspInstallParams
        {
            Shim = FullPath(Shim),
            Mm = FullPath(MokManager),
            Loader = FullPath(Loader),
        };
        WriteObject(Mutate<EspState>(PaguroMethods.EspInstall, p, "the ESP", "install shim, MokManager, paguro.efi")?.Data);
    }
}

/// <summary>Check the ESP files against what was installed.</summary>
[Cmdlet(VerbsDiagnostic.Test, "PaguroEsp"), OutputType(typeof(EspState)), PaguroMethod("esp.verify")]
public sealed class TestPaguroEsp : PaguroCmdlet
{
    protected override void ProcessRecord() => WriteObject(Call<EspState>(PaguroMethods.EspVerify, new NoParams())?.Data);
}

/// <summary>Restore the ESP files from the saved copies.</summary>
[Cmdlet(VerbsDiagnostic.Repair, "PaguroEsp", SupportsShouldProcess = true), OutputType(typeof(EspState)), PaguroMethod("esp.repair")]
public sealed class RepairPaguroEsp : PaguroCmdlet
{
    protected override void ProcessRecord() =>
        WriteObject(Mutate<EspState>(PaguroMethods.EspRepair, new NoParams(), "the ESP", "restore paguro's files")?.Data);
}

/// <summary>Request MOK enrolment of a DER certificate; the one-time password is in the result.</summary>
[Cmdlet(VerbsLifecycle.Register, "PaguroMok", SupportsShouldProcess = true), OutputType(typeof(MokEnroll)), PaguroMethod("mok.enroll")]
public sealed class RegisterPaguroMok : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0)] public string Certificate { get; set; } = "";
    /// <summary>Choose the one-time password instead of having one generated.</summary>
    [Parameter] public SecureString? Password { get; set; }

    protected override void ProcessRecord()
    {
        var p = new MokEnrollParams { Cert = FullPath(Certificate) };
        if (Password != null) p.MokPassword = Plain(Password);
        WriteObject(Mutate<MokEnroll>(PaguroMethods.MokEnroll, p, Certificate, "request MOK enrolment")?.Data);
    }
}

/// <summary>The machine key's enrolment state.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroMok"), OutputType(typeof(MokStatus)), PaguroMethod("mok.status")]
public sealed class GetPaguroMok : PaguroCmdlet
{
    [Parameter] public string? Certificate { get; set; }

    protected override void ProcessRecord() =>
        WriteObject(Call<MokStatus>(PaguroMethods.MokStatus, new MokStatusParams { Cert = Certificate == null ? null : FullPath(Certificate) })?.Data);
}
