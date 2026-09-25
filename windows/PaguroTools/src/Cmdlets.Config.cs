using System.Management.Automation;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>paguro.ini, parsed, with its hash.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroConfig"), OutputType(typeof(ConfigFile)), PaguroMethod("config.show")]
public sealed class GetPaguroConfig : PaguroCmdlet
{
    protected override void ProcessRecord() => WriteObject(Call<ConfigFile>(PaguroMethods.ConfigShow, new NoParams())?.Data);
}

/// <summary>Parse paguro.ini, check its hash and files.</summary>
[Cmdlet(VerbsDiagnostic.Test, "PaguroConfig"), OutputType(typeof(ConfigValidation)), PaguroMethod("config.validate")]
public sealed class TestPaguroConfig : PaguroCmdlet
{
    protected override void ProcessRecord() => WriteObject(Call<ConfigValidation>(PaguroMethods.ConfigValidate, new NoParams())?.Data);
}

/// <summary>Change entries or settings of paguro.ini.</summary>
[Cmdlet(VerbsCommon.Set, "PaguroConfig", SupportsShouldProcess = true), OutputType(typeof(ConfigChange)), PaguroMethod("config.set")]
public sealed class SetPaguroConfig : PaguroCmdlet
{
    [Parameter(Position = 0, ValueFromPipelineByPropertyName = true), Alias("Name")] public string? Entry { get; set; }
    [Parameter] public string? Volume { get; set; }
    [Parameter] public string? Root { get; set; }
    [Parameter] public string? EfiDisk { get; set; }
    [Parameter] public string? Efi { get; set; }
    [Parameter] public string? EfiFile { get; set; }
    [Parameter] public string? Default { get; set; }
    [Parameter] public string? RemoveEntry { get; set; }
    [Parameter] public bool? Tpm { get; set; }
    [Parameter] public bool? SetupTpm { get; set; }
    [Parameter] public bool? Passphrase { get; set; }
    [Parameter] public string? Theme { get; set; }
    [Parameter] public string? Mode { get; set; }
    [Parameter] public string? Keyboard { get; set; }

    protected override void ProcessRecord()
    {
        var p = new ConfigSetParams
        {
            Entry = Entry, Volume = Volume, Root = Root, EfiDisk = EfiDisk, Efi = Efi, EfiFile = EfiFile,
            Default = Default, RemoveEntry = RemoveEntry, Tpm = Tpm, SetupTpm = SetupTpm, Passphrase = Passphrase,
            Theme = Theme, Mode = Mode, Keyboard = Keyboard,
        };
        WriteObject(Mutate<ConfigChange>(PaguroMethods.ConfigSet, p, "paguro.ini", "change")?.Data);
    }
}
