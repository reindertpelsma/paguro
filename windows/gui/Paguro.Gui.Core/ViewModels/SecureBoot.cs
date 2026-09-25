using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 5: the one MokManager screen explained before it happens
/// (what it looks like, the one-time password, why it is safe), and the
/// one-reboot BitLocker suspend when db must change (INTERFACES §2.1).</summary>
public sealed class SecureBootViewModel : ObservableObject
{
    readonly Session session;
    public SecureBootViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
    }

    public Strings S => session.S;
    public AsyncCommand Load { get; }
    SecureBootStatus? status;
    public SecureBootStatus? Status { get => status; private set { if (Set(ref status, value)) RaiseAll(); } }
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }

    public bool On => Status?.SecureBoot == true;
    public bool Off => Status is { SecureBoot: false };
    /// <summary>MokManager will (or must, at install) show once.</summary>
    public bool ShowMok => On && (Status!.MokmanagerNextBoot || Status.EnrolmentNeeded);
    public bool DbChange => Status?.DbChangeNeeded == true;
    public bool BitLockerSuspend => Status?.BitlockerSuspendNeeded == true;
    public bool AllDone => On && !ShowMok && !DbChange;
    public string Headline => Status == null ? "" : !On ? S["sb_off"] : ShowMok ? S["sb_mok_ahead"] : DbChange ? S["sb_db_change"] : S["sb_all_done"];
    public string[] MokSteps => [S["mok_step_1"], S["mok_step_2"], S["mok_step_3"], S["mok_step_4"]];

    void RaiseAll()
    {
        foreach (var n in new[] { nameof(On), nameof(Off), nameof(ShowMok), nameof(DbChange), nameof(BitLockerSuspend), nameof(AllDone), nameof(Headline) })
            Raise(n);
    }

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<SecureBootStatus>(PaguroMethods.SecureBootStatus, new NoParams());
        Error = session.LastError;
        if (r != null) Status = r.Data;
    }
}
