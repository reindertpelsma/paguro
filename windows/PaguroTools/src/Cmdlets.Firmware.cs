using System.Management.Automation;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>paguro's firmware variables (all, or -Name).</summary>
[Cmdlet(VerbsCommon.Get, "PaguroFirmwareVariable"), OutputType(typeof(FirmwareVariable))]
[PaguroMethod("efi.vars.list"), PaguroMethod("efi.vars.get")]
public sealed class GetPaguroFirmwareVariable : PaguroCmdlet
{
    [Parameter(Position = 0, ValueFromPipelineByPropertyName = true)]
    public string? Name { get; set; }

    protected override void ProcessRecord()
    {
        if (Name == null) WriteAll(Call<VariableList>(PaguroMethods.EfiVarsList, new NoParams())?.Data.Variables);
        else WriteObject(Call<FirmwareVariable>(PaguroMethods.EfiVarsGet, new NameParams { Name = Name })?.Data);
    }
}

/// <summary>Expert: write one of paguro's firmware variables.</summary>
[Cmdlet(VerbsCommon.Set, "PaguroFirmwareVariable", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High), OutputType(typeof(FirmwareVariable)), PaguroMethod("efi.vars.set")]
public sealed class SetPaguroFirmwareVariable : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0)] public string Name { get; set; } = "";
    [Parameter(Mandatory = true, Position = 1)] public string Hex { get; set; } = "";

    protected override void ProcessRecord() =>
        WriteObject(Mutate<FirmwareVariable>(PaguroMethods.EfiVarsSet, new VarSetParams { Name = Name, Hex = Hex }, Name, "write firmware variable")?.Data);
}

/// <summary>Expert: delete one of paguro's firmware variables.</summary>
[Cmdlet(VerbsCommon.Remove, "PaguroFirmwareVariable", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High), OutputType(typeof(FirmwareVariable)), PaguroMethod("efi.vars.delete")]
public sealed class RemovePaguroFirmwareVariable : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)] public string Name { get; set; } = "";

    protected override void ProcessRecord() =>
        WriteObject(Mutate<FirmwareVariable>(PaguroMethods.EfiVarsDelete, new NameParams { Name = Name }, Name, "delete firmware variable")?.Data);
}

/// <summary>Boot#### entries.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroBootEntry"), OutputType(typeof(FirmwareBootEntry)), PaguroMethod("efi.boot-entry.list")]
public sealed class GetPaguroBootEntry : PaguroCmdlet
{
    [Parameter] public SwitchParameter Ours { get; set; }

    protected override void ProcessRecord() =>
        WriteAll(Call<BootEntryList>(PaguroMethods.EfiBootEntryList, new NoParams())?.Data.Entries.Where(e => !Ours || e.Ours == true));
}

/// <summary>Create or repair paguro's boot entry.</summary>
[Cmdlet(VerbsCommon.New, "PaguroBootEntry", SupportsShouldProcess = true), OutputType(typeof(BootEntryChange)), PaguroMethod("efi.boot-entry.create")]
public sealed class NewPaguroBootEntry : PaguroCmdlet
{
    protected override void ProcessRecord() =>
        WriteObject(Mutate<BootEntryChange>(PaguroMethods.EfiBootEntryCreate, new NoParams(), "paguro's Boot#### entry", "create or repair")?.Data);
}

/// <summary>Delete a boot entry: `Get-PaguroBootEntry -Ours | Remove-PaguroBootEntry`.</summary>
[Cmdlet(VerbsCommon.Remove, "PaguroBootEntry", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High), OutputType(typeof(BootEntryChange)), PaguroMethod("efi.boot-entry.delete")]
public sealed class RemovePaguroBootEntry : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true), Alias("Name")]
    public string Entry { get; set; } = "";

    protected override void ProcessRecord() =>
        WriteObject(Mutate<BootEntryChange>(PaguroMethods.EfiBootEntryDelete, new EntryParams { Entry = Entry }, Entry, "delete boot entry")?.Data);
}

/// <summary>Set BootNext (default: paguro's entry) or -Clear it.</summary>
[Cmdlet(VerbsCommon.Set, "PaguroBootNext", SupportsShouldProcess = true), OutputType(typeof(BootEntryChange)), PaguroMethod("efi.bootnext")]
public sealed class SetPaguroBootNext : PaguroCmdlet
{
    [Parameter(Position = 0, ValueFromPipelineByPropertyName = true), Alias("Name")] public string? Entry { get; set; }
    [Parameter] public SwitchParameter Clear { get; set; }

    protected override void ProcessRecord() =>
        WriteObject(Mutate<BootEntryChange>(PaguroMethods.EfiBootnext, new BootNextParams { Entry = Entry, Clear = Clear.IsPresent ? true : null }, Entry ?? "paguro", Clear ? "clear BootNext" : "set BootNext")?.Data);
}
