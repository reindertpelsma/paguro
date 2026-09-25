using System.Management.Automation;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>The API version and what this caller may call.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroService"), OutputType(typeof(ServiceInfo)), PaguroMethod("service.info")]
public sealed class GetPaguroService : PaguroCmdlet
{
    protected override void ProcessRecord() => WriteObject(Call<ServiceInfo>(PaguroMethods.ServiceInfo, new NoParams())?.Data);
}

/// <summary>Everything at once: volumes, firmware, ESP, images, pre-flight.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroStatus"), OutputType(typeof(Status)), PaguroMethod("status")]
public sealed class GetPaguroStatus : PaguroCmdlet
{
    protected override void ProcessRecord() => WriteObject(Call<Status>(PaguroMethods.Status, new NoParams())?.Data);
}

/// <summary>The installer's checks (INTERFACES §11.8), one object each.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroCheck"), OutputType(typeof(SystemCheck)), PaguroMethod("checks.list")]
public sealed class GetPaguroCheck : PaguroCmdlet
{
    /// <summary>Only these ids.</summary>
    [Parameter(Position = 0)]
    public string[]? Id { get; set; }

    protected override void ProcessRecord()
    {
        var r = Call<ChecksList>(PaguroMethods.ChecksList, new NoParams());
        WriteAll(r?.Data.Checks.Where(c => Id == null || Id.Contains(c.Id)));
    }
}

/// <summary>Fix a check where Windows allows it: `Get-PaguroCheck | ? State -ne ok | Repair-PaguroCheck`.</summary>
[Cmdlet(VerbsDiagnostic.Repair, "PaguroCheck", SupportsShouldProcess = true), OutputType(typeof(CheckFixResult)), PaguroMethod("checks.fix")]
public sealed class RepairPaguroCheck : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
    public string Id { get; set; } = "";

    protected override void ProcessRecord() =>
        WriteObject(Mutate<CheckFixResult>(PaguroMethods.ChecksFix, new CheckFixParams { Id = Id }, Id, "fix")?.Data);
}

/// <summary>What the Secure Boot step will do (MokManager, db).</summary>
[Cmdlet(VerbsCommon.Get, "PaguroSecureBoot"), OutputType(typeof(SecureBootStatus)), PaguroMethod("secure-boot.status")]
public sealed class GetPaguroSecureBoot : PaguroCmdlet
{
    protected override void ProcessRecord() => WriteObject(Call<SecureBootStatus>(PaguroMethods.SecureBootStatus, new NoParams())?.Data);
}

/// <summary>The host hardware export (INTERFACES §11.5); -Path writes host-hardware.json.</summary>
[Cmdlet(VerbsData.Export, "PaguroHardware", SupportsShouldProcess = true), OutputType(typeof(HostHardware)), PaguroMethod("hw.export")]
public sealed class ExportPaguroHardware : PaguroCmdlet
{
    [Parameter(Position = 0)]
    public string? Path { get; set; }

    protected override void ProcessRecord()
    {
        var r = Call<HostHardware>(PaguroMethods.HwExport, new NoParams());
        if (r == null) return;
        if (Path != null && ShouldProcess(Path, "write host-hardware.json"))
        {
            var full = FullPath(Path);
            File.WriteAllText(full, System.Text.Json.JsonSerializer.Serialize(r.Data, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }) + "\n");
        }
        WriteObject(r.Data);
    }
}

/// <summary>The modaliases an export presents to the installer.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroModalias", DefaultParameterSetName = "Path"), OutputType(typeof(string)), PaguroMethod("hw.modalias")]
public sealed class GetPaguroModalias : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Path")]
    public string Path { get; set; } = "";

    /// <summary>An export object: `Export-PaguroHardware | Get-PaguroModalias`.</summary>
    [Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = "Hardware")]
    public HostHardware? Hardware { get; set; }

    protected override void ProcessRecord()
    {
        var hw = Hardware ?? System.Text.Json.JsonSerializer.Deserialize<HostHardware>(File.ReadAllText(FullPath(Path)))!;
        WriteAll(Call<Modaliases>(PaguroMethods.HwModalias, new ModaliasParams { Hardware = hw })?.Data.Items);
    }
}
