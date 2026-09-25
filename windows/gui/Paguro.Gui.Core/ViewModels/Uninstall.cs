using System.Collections.ObjectModel;
using System.Text.Json;
using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 6b: the uninstall (DESIGN §6b), with a clear summary of
/// what will and will not be touched before anything happens.</summary>
public sealed class UninstallViewModel : ObservableObject
{
    readonly Session session;
    public static readonly string[] Steps = ["inventory", "windows-tasks", "driver-disable", "final-boot", "boot-entries", "esp", "driver-remove", "images", "app-files", "shortcut", "apps-and-features", "store", "setup-copy"];

    public UninstallViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
        Uninstall = new AsyncCommand(UninstallAsync, () => Touched.Count > 0 && Chosen && !session.ReadOnly);
    }

    public Strings S => session.S;
    public AsyncCommand Load { get; }
    public AsyncCommand Uninstall { get; }
    public ObservableCollection<string> Touched { get; } = new();
    public ObservableCollection<string> Untouched { get; } = new();

    bool? deleteImages;
    /// <summary>The Linux images: kept (false) or deleted (true); the user
    /// must choose (never silently, INTERFACES §11.7a).</summary>
    public bool? DeleteImages
    {
        get => deleteImages;
        set { if (Set(ref deleteImages, value)) { Raise(nameof(Chosen)); Uninstall.Refresh(); _ = LoadAsync(); } }
    }
    public bool Chosen => DeleteImages.HasValue;
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }
    string? result;
    public string? Result { get => result; private set => Set(ref result, value); }
    OperationViewModel? operation;
    public OperationViewModel? Operation { get => operation; private set => Set(ref operation, value); }

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<UninstallResult>(PaguroMethods.Uninstall, new UninstallParams { DryRun = true, DeleteImages = DeleteImages == true ? true : null });
        Error = session.LastError;
        Touched.Clear();
        Untouched.Clear();
        if (r == null) return;
        foreach (var s in r.Data.Steps ?? [])
            if (s.Id != "images" || DeleteImages == true) Touched.Add(S[$"step_uninstall_{s.Id.Replace('-', '_')}"]);
        Untouched.Add(S["untouched_windows"]);
        Untouched.Add(S["untouched_files"]);
        Untouched.Add(S["untouched_bitlocker"]);
        if (DeleteImages != true) Untouched.Add(S["untouched_images"]);
        Uninstall.Refresh();
    }

    public async Task UninstallAsync()
    {
        if (DeleteImages is not { } delete) return;
        if (!await session.Dialogs.ConfirmAsync(S["uninstall_confirm_title"], S["uninstall_confirm_body"], S["uninstall_now"], S["cancel"], danger: true)) return;
        // Uninstall runs in paguro.exe itself (elevated): the service is one of
        // the things it removes.
        var env = await session.RunPaguroAsync("uninstall", "--yes", delete ? "--delete-images" : "--keep-images");
        Error = session.LastError;
        if (env?["ok"]?.GetValue<bool>() != true) return;
        var r = env["data"].Deserialize<UninstallResult>(PaguroJson.Options);
        Operation = new OperationViewModel(S, "uninstall", Steps);
        Operation.Apply(r?.Journal?.Steps);
        Result = r?.Finished == true ? S["uninstall_done"] : S["uninstall_restart"];
    }
}
