using System.Collections.ObjectModel;
using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 6b: the uninstall (DESIGN §6b), with a clear summary of
/// what will and will not be touched before anything happens.</summary>
public sealed class UninstallViewModel : ObservableObject
{
    readonly Session session;
    public static readonly string[] Steps = ["inventory", "windows-tasks", "driver-disable", "final-boot", "boot-entries", "esp", "driver-remove", "images", "store"];

    public UninstallViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
        Uninstall = new AsyncCommand(UninstallAsync, () => Touched.Count > 0 && !session.ReadOnly);
    }

    public Strings S => session.S;
    public AsyncCommand Load { get; }
    public AsyncCommand Uninstall { get; }
    public ObservableCollection<string> Touched { get; } = new();
    public ObservableCollection<string> Untouched { get; } = new();

    bool deleteImages;
    public bool DeleteImages { get => deleteImages; set { if (Set(ref deleteImages, value)) _ = LoadAsync(); } }
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }
    string? result;
    public string? Result { get => result; private set => Set(ref result, value); }
    OperationViewModel? operation;
    public OperationViewModel? Operation { get => operation; private set => Set(ref operation, value); }

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<UninstallResult>(PaguroMethods.Uninstall, new UninstallParams { DryRun = true, DeleteImages = DeleteImages ? true : null });
        Error = session.LastError;
        Touched.Clear();
        Untouched.Clear();
        if (r == null) return;
        foreach (var s in r.Data.Steps ?? [])
            if (s.Id != "images" || DeleteImages) Touched.Add(S[$"step_uninstall_{s.Id.Replace('-', '_')}"]);
        Untouched.Add(S["untouched_windows"]);
        Untouched.Add(S["untouched_files"]);
        Untouched.Add(S["untouched_bitlocker"]);
        if (!DeleteImages) Untouched.Add(S["untouched_images"]);
        Uninstall.Refresh();
    }

    public async Task UninstallAsync()
    {
        if (!await session.Dialogs.ConfirmAsync(S["uninstall_confirm_title"], S["uninstall_confirm_body"], S["uninstall_now"], S["cancel"], danger: true)) return;
        Operation = new OperationViewModel(S, "uninstall", Steps);
        var r = await session.CallAsync<UninstallResult>(PaguroMethods.Uninstall, new UninstallParams { Yes = true, DeleteImages = DeleteImages ? true : null }, Operation.Progress);
        Error = session.LastError;
        if (r == null) return;
        Operation.Apply(r.Data.Journal?.Steps);
        Result = r.Pending ? S["uninstall_restart"] : S["uninstall_done"];
    }
}
