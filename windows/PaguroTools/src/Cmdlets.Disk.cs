using System.Management.Automation;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>Create a fixed, fully allocated VHD and verify it.</summary>
[Cmdlet(VerbsCommon.New, "PaguroDisk", SupportsShouldProcess = true), OutputType(typeof(DiskInfo)), PaguroMethod("disk.create")]
public sealed class NewPaguroDisk : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0)]
    public string Path { get; set; } = "";

    /// <summary>32G, 512M, or bytes (20GB works).</summary>
    [Parameter(Mandatory = true, Position = 1)]
    public object Size { get; set; } = "";

    protected override void ProcessRecord()
    {
        var full = FullPath(Path);
        WriteObject(Mutate<DiskInfo>(PaguroMethods.DiskCreate, new DiskCreateParams { Path = full, Size = SizeText(Size) }, full, "create fixed VHD")?.Data);
    }
}

/// <summary>Format, extents and UEFI file system of disk files.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroDisk"), OutputType(typeof(DiskInfo)), PaguroMethod("disk.inspect")]
public sealed class GetPaguroDisk : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [Alias("FullName")]
    public string[] Path { get; set; } = [];

    protected override void ProcessRecord()
    {
        foreach (var p in Path)
            WriteObject(Call<DiskInfo>(PaguroMethods.DiskInspect, new PathParams { Path = FullPath(p) })?.Data);
    }
}
