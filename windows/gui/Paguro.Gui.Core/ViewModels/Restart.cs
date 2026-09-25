using System.Collections.ObjectModel;
using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 6a: restart into Linux, choosing the entry, with a summary
/// of what will and will not happen first (the method's dry run).</summary>
public sealed class RestartViewModel : ObservableObject
{
    readonly Session session;
    public RestartViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
        Restart = new AsyncCommand(RestartAsync, () => Ready && !session.ReadOnly);
    }

    public Strings S => session.S;
    public AsyncCommand Load { get; }
    public AsyncCommand Restart { get; }
    public ObservableCollection<string> Entries { get; } = new();
    public ObservableCollection<string> Summary { get; } = new();
    public ObservableCollection<PreflightCheck> Problems { get; } = new();

    string? entry;
    public string? Entry { get => entry; set { if (Set(ref entry, value) && value != null) _ = PlanAsync(); } }
    string? defaultEntry;
    bool ready;
    public bool Ready { get => ready; private set { if (Set(ref ready, value)) Restart.Refresh(); } }
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }
    string? result;
    public string? Result { get => result; private set => Set(ref result, value); }

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<DistroList>(PaguroMethods.DistroList, new NoParams());
        Error = session.LastError;
        if (r == null) return;
        Entries.Clear();
        foreach (var d in r.Data.Distributions.Where(d => d.Kind == "image")) Entries.Add(d.Name);
        defaultEntry = r.Data.Distributions.FirstOrDefault(d => d.Kind == "image" && d.Default)?.Name;
        entry = null;
        Entry = defaultEntry ?? Entries.FirstOrDefault();
    }

    readonly SemaphoreSlim planning = new(1, 1);

    /// <summary>The dry run for the chosen entry. One at a time: choosing an
    /// entry plans too, and two plans must not fill the lists at once.</summary>
    public async Task PlanAsync()
    {
        await planning.WaitAsync();
        try { await PlanOnceAsync(); }
        finally { planning.Release(); }
    }

    async Task PlanOnceAsync()
    {
        var r = await session.CallAsync<Preflight>(PaguroMethods.RestartLinux, Params(dry: true));
        var data = r?.Data;
        if (data == null && session.LastException?.Detail is System.Text.Json.Nodes.JsonObject d)
            data = System.Text.Json.JsonSerializer.Deserialize<Preflight>(d.ToJsonString(), PaguroJson.Options);
        Error = session.LastError;
        Summary.Clear();
        Problems.Clear();
        if (data == null) { Ready = false; return; }
        foreach (var c in data.Checks.Where(c => c.State is "fail" or "warn")) Problems.Add(c);
        Ready = data.Action != null;
        if (!Ready) { Summary.Add(S["restart_blocked"]); return; }
        Summary.Add(Entry == defaultEntry || Entry == null ? S.F("restart_boots_default", ("entry", Entry ?? "")) : S.F("restart_boots_once", ("entry", Entry)));
        Summary.Add(data.Action!.Action == "stage_setup_tpm" ? S["restart_setup_tpm"] : S["restart_pin_bypass"]);
        Summary.Add(S["restart_untouched"]);
    }

    RestartLinuxParams Params(bool dry) => new() { Entry = Entry == defaultEntry ? null : Entry, DryRun = dry ? true : null, Yes = dry ? null : true };

    public async Task RestartAsync()
    {
        if (!await session.Dialogs.ConfirmAsync(S["restart_confirm_title"], string.Join("\n", Summary), S["restart_now"], S["cancel"])) return;
        var r = await session.CallAsync<Preflight>(PaguroMethods.RestartLinux, Params(dry: false));
        Error = session.LastError;
        if (r != null) Result = r.Data.Restarting == true ? S["restart_restarting"] : S["restart_ready"];
    }
}
