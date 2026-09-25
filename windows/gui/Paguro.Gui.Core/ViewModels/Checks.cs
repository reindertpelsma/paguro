using System.Collections.ObjectModel;
using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 1 (INTERFACES §11.8): the checks, each explained in one
/// sentence and fixable from the screen.</summary>
public sealed class ChecksViewModel : ObservableObject
{
    readonly Session session;
    public ChecksViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
        Fix = new AsyncCommand(p => FixAsync((CheckItem)p!), p => p is CheckItem { CanFix: true } && !session.ReadOnly);
    }

    public Strings S => session.S;
    public ObservableCollection<CheckItem> Items { get; } = new();
    public AsyncCommand Load { get; }
    public AsyncCommand Fix { get; }

    bool ready;
    /// <summary>No check failed: the install can go ahead.</summary>
    public bool Ready { get => ready; private set { if (Set(ref ready, value)) Raise(nameof(Summary)); } }
    public string Summary => Items.Count == 0 ? "" : Ready ? S["checks_ready"] : S["checks_not_ready"];
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<ChecksList>(PaguroMethods.ChecksList, new NoParams());
        Error = session.LastError;
        if (r == null) return;
        Items.Clear();
        foreach (var c in r.Data.Checks) Items.Add(new CheckItem(S, c));
        Ready = r.Data.Ready;
        Raise(nameof(Summary));
        Fix.Refresh();
    }

    public async Task FixAsync(CheckItem item)
    {
        if (!await session.Dialogs.ConfirmAsync(S["fix_title"], item.FixText, S["fix_yes"], S["cancel"])) return;
        var r = await session.CallAsync<CheckFixResult>(PaguroMethods.ChecksFix, new CheckFixParams { Id = item.Id });
        Error = session.LastError;
        if (r != null) await LoadAsync();
    }
}

public sealed class CheckItem : ObservableObject
{
    public CheckItem(Strings s, SystemCheck c)
    {
        Id = c.Id;
        Title = s[$"check_{c.Id}"];
        Why = s[$"check_{c.Id}_why"];
        State = c.State;
        Detail = c.Detail;
        CanFix = c.Fix?.Automatic == true && c.State != "ok";
        FixText = c.Fix?.Instruction ?? "";
        StateText = s[$"state_{c.State}"];
    }

    public string Id { get; }
    /// <summary>What is checked (localised).</summary>
    public string Title { get; }
    /// <summary>Why it matters, one sentence (localised).</summary>
    public string Why { get; }
    public string State { get; }
    public string StateText { get; }
    /// <summary>What the service found.</summary>
    public string Detail { get; }
    public bool CanFix { get; }
    public string FixText { get; }
    public bool HasFixText => FixText.Length > 0;
    public string Glyph => State switch { "ok" => "\uE73E", "warn" => "\uE7BA", _ => "\uE783" };
}
