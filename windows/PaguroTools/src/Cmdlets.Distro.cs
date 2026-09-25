using System.Management.Automation;
using System.Security;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>paguro's bootable images and the WSL2 distributions.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroDistribution"), OutputType(typeof(Distribution)), PaguroMethod("distro.list")]
public sealed class GetPaguroDistribution : PaguroCmdlet
{
    [Parameter(Position = 0)] public string[]? Name { get; set; }
    /// <summary>image or wsl.</summary>
    [Parameter, ValidateSet("image", "wsl")] public string? Kind { get; set; }

    protected override void ProcessRecord()
    {
        var pats = Name?.Select(n => new WildcardPattern(n, WildcardOptions.IgnoreCase)).ToList();
        WriteAll(Call<DistroList>(PaguroMethods.DistroList, new NoParams())?.Data.Distributions
            .Where(d => (Kind == null || d.Kind == Kind) && (pats == null || pats.Any(p => p.IsMatch(d.Name)))));
    }
}

/// <summary>Rename a distribution's entry.</summary>
[Cmdlet(VerbsCommon.Rename, "PaguroDistribution", SupportsShouldProcess = true), OutputType(typeof(ConfigChange)), PaguroMethod("distro.rename")]
public sealed class RenamePaguroDistribution : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)] public string Name { get; set; } = "";
    [Parameter(Mandatory = true, Position = 1)] public string NewName { get; set; } = "";

    protected override void ProcessRecord() =>
        WriteObject(Mutate<ConfigChange>(PaguroMethods.DistroRename, new DistroRenameParams { Name = Name, NewName = NewName }, Name, $"rename to {NewName}")?.Data);
}

/// <summary>Remove a distribution's entry, and with -DeleteImage its disk file.</summary>
[Cmdlet(VerbsCommon.Remove, "PaguroDistribution", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High), OutputType(typeof(ConfigChange)), PaguroMethod("distro.remove")]
public sealed class RemovePaguroDistribution : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)] public string Name { get; set; } = "";
    [Parameter] public SwitchParameter DeleteImage { get; set; }

    protected override void ProcessRecord() =>
        WriteObject(Mutate<ConfigChange>(PaguroMethods.DistroRemove, new DistroRemoveParams { Name = Name, DeleteImage = DeleteImage ? true : null, Yes = DeleteImage ? true : null }, Name, DeleteImage ? "remove the entry AND delete its image" : "remove the entry")?.Data);
}

/// <summary>Grow an image. STUB: needs the Linux side (DESIGN §5.6).</summary>
[Cmdlet(VerbsCommon.Resize, "PaguroDistribution", SupportsShouldProcess = true), OutputType(typeof(ConfigChange)), PaguroMethod("distro.grow")]
public sealed class ResizePaguroDistribution : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)] public string Name { get; set; } = "";
    [Parameter(Mandatory = true, Position = 1)] public object Size { get; set; } = "";

    protected override void ProcessRecord() =>
        WriteObject(Mutate<ConfigChange>(PaguroMethods.DistroGrow, new DistroGrowParams { Name = Name, Size = SizeText(Size) }, Name, "grow")?.Data);
}

/// <summary>Attach an image (or any .vhd/.vhdx) to WSL2 and open a root shell
/// in this console; detached again when the shell exits.</summary>
[Cmdlet(VerbsCommon.Enter, "PaguroDistro", DefaultParameterSetName = "Name"), OutputType(typeof(DistroAttach)), PaguroMethod("distro.enter")]
public sealed class EnterPaguroDistro : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true, ParameterSetName = "Name")] public string Name { get; set; } = "";
    [Parameter(Mandatory = true, ParameterSetName = "Path")] public string Path { get; set; } = "";
    /// <summary>Only attach (Dismount-PaguroDistro detaches).</summary>
    [Parameter] public SwitchParameter NoShell { get; set; }

    protected override void ProcessRecord()
    {
        var p = ParameterSetName == "Path"
            ? new DistroTargetParams { Path = FullPath(Path) }
            : new DistroTargetParams { Name = Name };
        var r = Call<DistroAttach>(PaguroMethods.DistroEnter, p);
        if (r == null) return;
        if (!NoShell)
        {
            var code = RunShell(r.Data.Command ?? new List<string>());
            r.Data.ShellExit = code;
            var back = Call<DistroAttach>(PaguroMethods.DistroLeave, p);
            r.Data.Detached = back?.Data.Detached;
        }
        WriteObject(r.Data);
    }
}

/// <summary>Detach an image from WSL2.</summary>
[Cmdlet(VerbsData.Dismount, "PaguroDistro", DefaultParameterSetName = "Name"), OutputType(typeof(DistroAttach)), PaguroMethod("distro.leave")]
public sealed class DismountPaguroDistro : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true, ParameterSetName = "Name")] public string Name { get; set; } = "";
    [Parameter(Mandatory = true, ParameterSetName = "Path")] public string Path { get; set; } = "";

    protected override void ProcessRecord()
    {
        var p = ParameterSetName == "Path"
            ? new DistroTargetParams { Path = FullPath(Path) }
            : new DistroTargetParams { Name = Name };
        WriteObject(Call<DistroAttach>(PaguroMethods.DistroLeave, p)?.Data);
    }
}

/// <summary>Install a distribution (INTERFACES §11.4): from its ISO, from a WSL2
/// distribution, or by a script; -Shell / -Finish for the manual mode.</summary>
[Cmdlet(VerbsLifecycle.Install, "PaguroDistro", SupportsShouldProcess = true, DefaultParameterSetName = "Iso"), OutputType(typeof(Journal)), PaguroMethod("install")]
public sealed class InstallPaguroDistro : InstallBase
{
    [Parameter(Mandatory = true, ParameterSetName = "Iso")] public string Iso { get; set; } = "";
    [Parameter(Mandatory = true, ParameterSetName = "Wsl")] public string FromWsl { get; set; } = "";
    [Parameter(Mandatory = true, ParameterSetName = "Script")] public string Script { get; set; } = "";
    [Parameter(Mandatory = true, ParameterSetName = "Finish")] public SwitchParameter Finish { get; set; }
    /// <summary>Manual mode: a root shell with the disk attached; complete with -Finish.</summary>
    [Parameter(ParameterSetName = "Iso")][Parameter(ParameterSetName = "Wsl")][Parameter(ParameterSetName = "Script")]
    public SwitchParameter Shell { get; set; }

    protected override void ProcessRecord()
    {
        var p = Params();
        switch (ParameterSetName)
        {
            case "Iso": p.Source = "iso"; p.Iso = FullPath(Iso); break;
            case "Wsl": p.Source = "wsl"; p.WslDistro = FromWsl; break;
            case "Script": p.Source = "script"; p.Script = FullPath(Script); break;
            case "Finish": p.Finish = true; break;
        }
        if (Shell) p.Shell = true;
        Run(p, Finish ? "finish the install" : "install");
    }
}

/// <summary>The manual install: a root shell inside the installer's container
/// with the target disk attached (INTERFACES §11.7); then Install-PaguroDistro -Finish.</summary>
[Cmdlet(VerbsCommon.Enter, "PaguroInstaller", SupportsShouldProcess = true), OutputType(typeof(Journal)), PaguroMethod("install")]
public sealed class EnterPaguroInstaller : InstallBase
{
    [Parameter(Mandatory = true)] public string Iso { get; set; } = "";

    protected override void ProcessRecord()
    {
        var p = Params();
        p.Source = "iso";
        p.Iso = FullPath(Iso);
        p.Shell = true;
        Run(p, "open the installer's shell");
    }
}

public abstract class InstallBase : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0)] public string Name { get; set; } = "";
    [Parameter(Mandatory = true, Position = 1)] public string Path { get; set; } = "";
    [Parameter] public object? Size { get; set; }
    [Parameter] public string? Shim { get; set; }
    [Parameter] public string? MokManager { get; set; }
    [Parameter] public string? Loader { get; set; }
    [Parameter] public string? MokCertificate { get; set; }
    /// <summary>Restart at the end.</summary>
    [Parameter] public SwitchParameter Restart { get; set; }
    /// <summary>The Linux passphrase to choose (else asked).</summary>
    [Parameter] public SecureString? Passphrase { get; set; }

    protected override SecureString? SecretFor(string name) => name == "linux_passphrase" ? Passphrase : null;

    string? Full(string? p) => p == null ? null : FullPath(p);

    protected InstallParams Params() => new()
    {
        Distro = Name,
        Path = FullPath(Path),
        Size = Size == null ? null : SizeText(Size),
        Shim = Full(Shim), Mm = Full(MokManager), Loader = Full(Loader), MokCert = Full(MokCertificate),
        Yes = Restart ? true : null,
    };

    protected void Run(InstallParams p, string action)
    {
        var r = Mutate<Journal>(PaguroMethods.Install, p, Name, action);
        if (r == null) return;
        if (p.Shell == true && r.Pending && !r.DryRun && r.Data.Shell is { Count: > 0 } sh)
        {
            r.Data.ShellExit = RunShell(sh);
            Host.UI.WriteLine($"when the system is installed: Install-PaguroDistro {Name} {Path} -Finish");
        }
        WriteObject(r.Data);
    }
}
