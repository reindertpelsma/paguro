using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>paguro itself (INTERFACES §11.7a): what is installed, and repair
/// (files, service, driver, entries, the ESP files and boot entry; never the
/// Linux images).</summary>
public sealed class SetupViewModel : ObservableObject
{
    readonly Session session;
    public SetupViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
        Repair = new AsyncCommand(RepairAsync, () => !session.ReadOnly);
    }

    public Strings S => session.S;
    public AsyncCommand Load { get; }
    public AsyncCommand Repair { get; }
    SetupState? state;
    public SetupState? State { get => state; private set { if (Set(ref state, value)) { Raise(nameof(Rows)); } } }
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }
    string? result;
    public string? Result { get => result; private set => Set(ref result, value); }
    OperationViewModel? operation;
    public OperationViewModel? Operation { get => operation; private set => Set(ref operation, value); }

    public IReadOnlyList<string> Rows => State is not { } s ? [] :
    [
        S.F("setup_version", ("version", s.Version)),
        S.F("setup_where", ("dir", s.InstallDir)),
        (s.Service ? "✓ " : "✗ ") + S["setup_service"],
        (s.AppsAndFeatures ? "✓ " : "✗ ") + S["setup_arp"],
        (s.SetupCopy ? "✓ " : "✗ ") + S["setup_copy"],
    ];

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<SetupState>(PaguroMethods.SetupStatus, new NoParams());
        Error = session.LastError;
        if (r != null) State = r.Data;
    }

    public async Task RepairAsync()
    {
        if (!await session.Dialogs.ConfirmAsync(S["repair_confirm_title"], S["repair_confirm_body"], S["repair_now"], S["cancel"])) return;
        Operation = new OperationViewModel(S, "repair", ["files", "setup-copy", "driver", "service", "apps-and-features", "shortcut"]);
        var r = await session.CallAsync<Preflight>(PaguroMethods.Repair, new RepairParams(), Operation.Progress);
        Error = session.LastError;
        Result = r == null ? null : S["repair_done"];
        await LoadAsync();
    }
}
