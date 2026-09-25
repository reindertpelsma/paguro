using System.Collections.ObjectModel;
using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 4, unlocking (INTERFACES §11.8, DESIGN §8d): the choice —
/// TPM + PIN, passphrase, TPM only (capped at Windows' own level),
/// unprotected — asked only under BitLocker; the PIN or passphrase with the
/// keyboard layout it will be typed in, dead-key characters refused; the
/// PIN-bypass checkbox, on by default.</summary>
public sealed class ProtectionViewModel : ObservableObject
{
    readonly Session session;
    public ProtectionViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(() => LoadAsync(null));
        Apply = new AsyncCommand(ApplyAsync, () => CanApply);
    }

    public Strings S => session.S;
    public AsyncCommand Load { get; }
    public AsyncCommand Apply { get; }
    public ObservableCollection<ChoiceItem> Choices { get; } = new();
    public ObservableCollection<KeyboardLayout> Keyboards { get; } = new();

    bool asked;
    /// <summary>Windows uses BitLocker, so there is a choice to make.</summary>
    public bool Asked { get => asked; private set { if (Set(ref asked, value)) Raise(nameof(NotAsked)); } }
    public bool NotAsked => loaded && !Asked;
    bool loaded;
    string windowsText = "";
    public string WindowsText { get => windowsText; private set => Set(ref windowsText, value); }

    ChoiceItem? selected;
    public ChoiceItem? Selected
    {
        get => selected;
        set
        {
            if (value is { Offered: false }) return;
            if (!Set(ref selected, value)) return;
            foreach (var c in Choices) c.IsSelected = c == value;
            Raise(nameof(NeedsSecret)); Raise(nameof(ShowPinBypass)); Raise(nameof(SecretLabel)); Raise(nameof(CanApply));
            Apply.Refresh();
            _ = CheckAsync();
        }
    }

    public bool NeedsSecret => Selected?.Id is "tpm_pin" or "passphrase";
    public bool ShowPinBypass => Selected?.Id == "tpm_pin";
    public string SecretLabel => Selected?.Id == "tpm_pin" ? S["pin_label"] : S["passphrase_label"];

    KeyboardLayout? keyboard;
    public KeyboardLayout? Keyboard { get => keyboard; set { if (Set(ref keyboard, value)) { Raise(nameof(KeyboardNote)); _ = CheckAsync(); } } }
    public string KeyboardNote => Keyboard == null ? "" : S.F("keyboard_note", ("layout", Keyboard.Name));

    bool pinBypass = true;
    /// <summary>"Restart into Linux" skips the PIN; on by default (DESIGN §8d).</summary>
    public bool PinBypass { get => pinBypass; set => Set(ref pinBypass, value); }

    string secret = "", again = "";
    public string Secret { get => secret; set { if (Set(ref secret, value)) { Raise(nameof(Mismatch)); Raise(nameof(CanApply)); Apply.Refresh(); _ = CheckAsync(); } } }
    public string SecretAgain { get => again; set { if (Set(ref again, value)) { Raise(nameof(Mismatch)); Raise(nameof(CanApply)); Apply.Refresh(); } } }
    public bool Mismatch => SecretAgain.Length > 0 && Secret != SecretAgain;

    string refused = "";
    /// <summary>Characters that cannot be typed at boot on the layout, and why.</summary>
    public string Refused { get => refused; private set { if (Set(ref refused, value)) { Raise(nameof(HasRefused)); Raise(nameof(CanApply)); Apply.Refresh(); } } }
    public bool HasRefused => Refused.Length > 0;

    string? result;
    public string? Result { get => result; private set => Set(ref result, value); }
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }

    public bool CanApply => Selected is { Offered: true } && !session.ReadOnly &&
        (!NeedsSecret || (Secret.Length > 0 && Secret == SecretAgain && !HasRefused));

    public async Task LoadAsync(string? klid)
    {
        var r = await session.CallAsync<ProtectionOptions>(PaguroMethods.ProtectionOptions, new ProtectionOptionsParams { Klid = klid ?? KeyboardLayouts.Current() });
        Error = session.LastError;
        if (r == null) return;
        var o = r.Data;
        loaded = true;
        Asked = o.Asked;
        Raise(nameof(NotAsked));
        WindowsText = S[$"windows_{o.Windows}"];
        Choices.Clear();
        foreach (var c in o.Choices) Choices.Add(new ChoiceItem(S, c));
        Keyboards.Clear();
        foreach (var k in o.Keyboards) Keyboards.Add(k);
        Keyboard = Keyboards.FirstOrDefault(k => k.Id == (o.Current?.Keyboard ?? o.KeyboardSuggested)) ?? Keyboards.FirstOrDefault();
        PinBypass = o.Current?.PinBypass ?? o.PinBypassDefault;
        Selected = Choices.FirstOrDefault(c => c.Id == o.Current?.Choice && c.Offered) ?? Choices.FirstOrDefault(c => c.Recommended);
    }

    int checkSeq;
    /// <summary>Ask the service whether the secret can be typed at boot.</summary>
    public async Task CheckAsync()
    {
        if (!NeedsSecret || Secret.Length == 0 || Keyboard == null) { Refused = ""; return; }
        var seq = ++checkSeq;
        var r = await session.CallAsync<SecretCheck>(PaguroMethods.ProtectionCheck, new ProtectionCheckParams { Keyboard = Keyboard.Id, Pin = Secret });
        if (seq != checkSeq) return;
        var check = r?.Data;
        if (check == null && session.LastException?.Detail is System.Text.Json.Nodes.JsonObject d && d.ContainsKey("refused"))
            check = System.Text.Json.JsonSerializer.Deserialize<SecretCheck>(d.ToJsonString(), PaguroJson.Options);
        Refused = check == null || check.Ok
            ? ""
            : S.F("refused_chars", ("chars", string.Join(" ", check.Refused.Select(x => x.Char))), ("layout", Keyboard.Name));
    }

    public async Task ApplyAsync()
    {
        if (Selected == null || Keyboard == null) return;
        if (!await session.Dialogs.ConfirmAsync(S["protection_confirm_title"], S.F("protection_confirm_body", ("choice", Selected.Title), ("layout", Keyboard.Name)), S["protection_apply"], S["cancel"])) return;
        var p = new ProtectionSetParams { Choice = Selected.Id, Keyboard = Keyboard.Id, PinBypass = ShowPinBypass ? PinBypass : false };
        if (NeedsSecret) p.Pin = Secret;
        var r = await session.CallAsync<ProtectionSet>(PaguroMethods.ProtectionSet, p);
        Error = session.LastError;
        Secret = SecretAgain = "";
        if (r == null) return;
        Result = r.Data.Pending.Count == 0 ? S["protection_done"] : S["protection_done_pending"] + "\n" + string.Join("\n", r.Data.Pending);
    }
}

public sealed class ChoiceItem : ObservableObject
{
    public ChoiceItem(Strings s, ProtectionOffer o)
    {
        Id = o.Id;
        Title = s[$"choice_{o.Id}"];
        Explanation = s[$"choice_{o.Id}_why"];
        Offered = o.Offered;
        Recommended = o.Recommended;
        Reason = o.Offered ? "" : s[$"choice_{o.Id}_not_offered"];
        Badge = o.Recommended ? s["recommended"] : "";
    }
    public string Id { get; }
    public string Title { get; }
    public string Explanation { get; }
    public bool Offered { get; }
    public bool Recommended { get; }
    /// <summary>Why it is not offered here.</summary>
    public string Reason { get; }
    public string Badge { get; }
    bool isSelected;
    public bool IsSelected { get => isSelected; set => Set(ref isSelected, value); }
    /// <summary>The list item's name for UI automation and screen readers.</summary>
    public override string ToString() => Title;
}

static class KeyboardLayouts
{
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern bool GetKeyboardLayoutNameW(System.Text.StringBuilder name);

    /// <summary>Windows' active input layout (KLID), when there is one.</summary>
    public static string? Current()
    {
        if (Environment.GetEnvironmentVariable("PAGURO_KLID") is { Length: 8 } k) return k;
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var sb = new System.Text.StringBuilder(9);
            return GetKeyboardLayoutNameW(sb) ? sb.ToString() : null;
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { return null; }
    }
}
