using System.Management.Automation;
using System.Security;
using Paguro.Api;

namespace Paguro.PowerShell;

/// <summary>How Linux may unlock here (DESIGN §8d), and the keyboard layouts.</summary>
[Cmdlet(VerbsCommon.Get, "PaguroProtection"), OutputType(typeof(ProtectionOptions)), PaguroMethod("protection.options")]
public sealed class GetPaguroProtection : PaguroCmdlet
{
    [Parameter, ValidateSet("image", "disk")] public string? Target { get; set; }
    /// <summary>The keyboard layout to suggest (Windows KLID); default: this session's.</summary>
    [Parameter] public string? Klid { get; set; }

    protected override void ProcessRecord() =>
        WriteObject(Call<ProtectionOptions>(PaguroMethods.ProtectionOptions, new ProtectionOptionsParams { Target = Target, Klid = Klid ?? Keyboards.CurrentKlid() })?.Data);
}

/// <summary>Choose how Linux unlocks: tpm_pin, passphrase or tpm_only. The PIN
/// or passphrase is checked against the keyboard layout (dead keys refused).</summary>
[Cmdlet(VerbsCommon.Set, "PaguroProtection", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High), OutputType(typeof(ProtectionSet)), PaguroMethod("protection.set")]
public sealed class SetPaguroProtection : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0), ValidateSet("tpm_pin", "passphrase", "tpm_only", "unprotected")]
    public string Choice { get; set; } = "";
    [Parameter] public string Keyboard { get; set; } = "us";
    [Parameter] public SecureString? Pin { get; set; }
    /// <summary>Always ask for the PIN, also after Restart-PaguroLinux.</summary>
    [Parameter] public SwitchParameter NoPinBypass { get; set; }
    [Parameter, ValidateSet("image", "disk")] public string? Target { get; set; }

    protected override SecureString? SecretFor(string name) => name == "pin" ? Pin : null;

    protected override void ProcessRecord()
    {
        var p = new ProtectionSetParams { Choice = Choice, Keyboard = Keyboard, PinBypass = !NoPinBypass.IsPresent, Target = Target };
        if (Pin != null) p.Pin = Plain(Pin);
        WriteObject(Mutate<ProtectionSet>(PaguroMethods.ProtectionSet, p, "how Linux unlocks", $"set to {Choice}")?.Data);
    }
}

/// <summary>Can this PIN or passphrase be typed at boot on a layout?</summary>
[Cmdlet(VerbsDiagnostic.Test, "PaguroSecret"), OutputType(typeof(SecretCheck)), PaguroMethod("protection.check")]
public sealed class TestPaguroSecret : PaguroCmdlet
{
    [Parameter(Mandatory = true, Position = 0)] public SecureString Secret { get; set; } = new();
    [Parameter] public string Keyboard { get; set; } = "us";

    protected override void ProcessRecord()
    {
        try
        {
            WriteObject(Client.ProtectionCheckAsync(new ProtectionCheckParams { Keyboard = Keyboard, Pin = Plain(Secret) }).GetAwaiter().GetResult().Data);
        }
        catch (PaguroException e) when (e.Detail is System.Text.Json.Nodes.JsonObject d && d.ContainsKey("refused"))
        {
            // A refusal is the answer, not a failure.
            WriteObject(System.Text.Json.JsonSerializer.Deserialize<SecretCheck>(d.ToJsonString(), PaguroJson.Options));
        }
        catch (PaguroException e)
        {
            WriteError(new ErrorRecord(e, "paguro." + e.Code, ErrorCategory.InvalidArgument, Keyboard));
        }
    }
}

static class Keyboards
{
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern bool GetKeyboardLayoutNameW(System.Text.StringBuilder name);

    /// <summary>The session's keyboard layout (KLID), when there is one.</summary>
    public static string? CurrentKlid()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var sb = new System.Text.StringBuilder(9);
            return GetKeyboardLayoutNameW(sb) ? sb.ToString() : null;
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }
}
