using System.Collections.ObjectModel;
using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 2: install from an ISO (its own installer through WSLg),
/// from a script, or make a WSL2 distribution bootable; list, rename,
/// remove, grow; open an image in a WSL2 container.</summary>
public sealed class DistributionsViewModel : ObservableObject
{
    readonly Session session;

    public DistributionsViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
        Install = new AsyncCommand(InstallAsync, () => CanInstall);
        MakeBootable = new AsyncCommand(p => MakeBootableAsync((DistroItem)p!), p => p is DistroItem { IsWsl: true });
        OpenInContainer = new AsyncCommand(p => OpenAsync((DistroItem)p!), p => p is DistroItem { IsImage: true });
        Detach = new AsyncCommand(DetachAsync, () => Attached != null);
        Rename = new AsyncCommand(p => RenameAsync((DistroItem)p!), p => p is DistroItem { IsImage: true });
        Remove = new AsyncCommand(p => RemoveAsync((DistroItem)p!), p => p is DistroItem { IsImage: true });
        Grow = new AsyncCommand(p => GrowAsync((DistroItem)p!), p => p is DistroItem { IsImage: true });
    }

    public Strings S => session.S;
    public ObservableCollection<DistroItem> Items { get; } = new();
    public AsyncCommand Load { get; }
    public AsyncCommand Install { get; }
    public AsyncCommand MakeBootable { get; }
    public AsyncCommand OpenInContainer { get; }
    public AsyncCommand Detach { get; }
    public AsyncCommand Rename { get; }
    public AsyncCommand Remove { get; }
    public AsyncCommand Grow { get; }

    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }
    string? notice;
    public string? Notice { get => notice; private set => Set(ref notice, value); }

    // The install form.
    string newName = "";
    public string NewName { get => newName; set { if (Set(ref newName, value)) { if (!pathEdited) Raise(nameof(NewPath)); Install.Refresh(); } } }
    bool pathEdited;
    string? newPath;
    public string NewPath { get => newPath ?? (NewName.Length > 0 ? $@"C:\paguro\{NewName}.vhd" : ""); set { pathEdited = true; Set(ref newPath, value); Install.Refresh(); } }
    string newSize = "32G";
    public string NewSize { get => newSize; set => Set(ref newSize, value); }
    string isoPath = "";
    public string IsoPath { get => isoPath; set { if (Set(ref isoPath, value)) Install.Refresh(); } }
    bool manual;
    /// <summary>Install by hand in a root shell (the manual mode).</summary>
    public bool Manual { get => manual; set => Set(ref manual, value); }
    public bool CanInstall => NewName.Length > 0 && NewPath.Length > 0 && IsoPath.Length > 0 && !session.ReadOnly;

    OperationViewModel? operation;
    public OperationViewModel? Operation { get => operation; private set => Set(ref operation, value); }
    DistroItem? attached;
    public DistroItem? Attached { get => attached; private set { if (Set(ref attached, value)) Detach.Refresh(); } }

    public static readonly string[] InstallSteps = ["host", "hw-export", "disk", "wsl-mount", "build", "wsl-unmount", "esp", "mok", "bootstrap"];

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<DistroList>(PaguroMethods.DistroList, new NoParams());
        Error = session.LastError;
        if (r == null) return;
        Items.Clear();
        foreach (var d in r.Data.Distributions) Items.Add(new DistroItem(S, d));
    }

    async Task RunInstall(InstallParams p, string title)
    {
        Operation = new OperationViewModel(S, "install", InstallSteps);
        var r = await session.CallAsync<Journal>(PaguroMethods.Install, p, Operation.Progress);
        Error = session.LastError;
        if (session.LastException?.Detail is System.Text.Json.Nodes.JsonObject j && j["steps"] is not null)
            Operation.Apply(System.Text.Json.JsonSerializer.Deserialize<Journal>(j.ToJsonString(), PaguroJson.Options)?.Steps);
        if (r == null) return;
        Operation.Apply(r.Data.Steps);
        if (r.Pending && r.Data.Shell is { Count: > 0 } sh)
        {
            // The manual mode: the user's own terminal, with the disk attached.
            await session.Dialogs.RunAsync("wt.exe", sh, elevated: false);
            Notice = S.F("install_manual_next", ("name", p.Distro));
        }
        else Notice = S.F("install_done", ("name", title));
        await LoadAsync();
    }

    public Task InstallAsync() => RunInstall(new InstallParams
    {
        Distro = NewName, Path = NewPath, Size = NewSize, Source = "iso", Iso = IsoPath, Shell = Manual ? true : null,
    }, NewName);

    public async Task MakeBootableAsync(DistroItem wsl)
    {
        var name = new string(wsl.Name.Where(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_').ToArray());
        if (!await session.Dialogs.ConfirmAsync(S["wsl_bootable_title"], S.F("wsl_bootable_body", ("name", wsl.Name)), S["wsl_bootable_yes"], S["cancel"])) return;
        await RunInstall(new InstallParams { Distro = name, Path = $@"C:\paguro\{name}.vhd", Source = "wsl", WslDistro = wsl.Name }, wsl.Name);
    }

    public async Task OpenAsync(DistroItem d)
    {
        var r = await session.CallAsync<DistroAttach>(PaguroMethods.DistroEnter, new DistroTargetParams { Name = d.Name });
        Error = session.LastError;
        if (r == null) return;
        Attached = d;
        await session.Dialogs.RunAsync("wt.exe", r.Data.Command ?? ["wsl.exe", "--user", "root"], elevated: false);
        Notice = S.F("container_open", ("name", d.Name));
    }

    public async Task DetachAsync()
    {
        if (Attached is not { } d) return;
        var r = await session.CallAsync<DistroAttach>(PaguroMethods.DistroLeave, new DistroTargetParams { Name = d.Name });
        Error = session.LastError;
        if (r != null) { Attached = null; Notice = S.F("container_closed", ("name", d.Name)); }
    }

    public async Task RenameAsync(DistroItem d)
    {
        var to = await session.Dialogs.AskTextAsync(S["rename_title"], S.F("rename_prompt", ("name", d.Name)), d.Name);
        if (string.IsNullOrWhiteSpace(to)) return;
        await session.CallAsync<ConfigChange>(PaguroMethods.DistroRename, new DistroRenameParams { Name = d.Name, NewName = to.Trim() });
        Error = session.LastError;
        await LoadAsync();
    }

    public async Task RemoveAsync(DistroItem d)
    {
        if (!await session.Dialogs.ConfirmAsync(S["remove_title"], S.F("remove_body", ("name", d.Name), ("path", d.Path ?? "")), S["remove_yes"], S["cancel"], danger: true)) return;
        var delete = await session.Dialogs.ConfirmAsync(S["remove_image_title"], S.F("remove_image_body", ("path", d.Path ?? "")), S["remove_image_yes"], S["remove_image_keep"], danger: true);
        await session.CallAsync<ConfigChange>(PaguroMethods.DistroRemove, new DistroRemoveParams { Name = d.Name, DeleteImage = delete ? true : null, Yes = delete ? true : null });
        Error = session.LastError;
        await LoadAsync();
    }

    public async Task GrowAsync(DistroItem d)
    {
        await session.CallAsync<ConfigChange>(PaguroMethods.DistroGrow, new DistroGrowParams { Name = d.Name, Size = "64G" });
        // A stub on the service side (DESIGN §5.6): say so plainly.
        await session.Dialogs.MessageAsync(S["grow_title"], session.LastError ?? S["grow_done"]);
        Error = null;
    }
}

public sealed class DistroItem
{
    public DistroItem(Strings s, Distribution d)
    {
        Name = d.Name;
        Kind = d.Kind;
        Path = d.Path;
        Default = d.Default;
        Size = d.Size;
        KindText = d.Kind == "image" ? s["kind_image"] : s["kind_wsl"];
        SizeText = d.Size is { } b ? $"{b / (double)(1UL << 30):0.#} GB" : "";
        Detail = d.Kind == "image" ? (d.Default ? s["distro_default"] : "") : s.F("distro_wsl", ("state", d.WslState ?? ""), ("version", d.WslVersion ?? 0));
    }
    public string Name { get; }
    public string Kind { get; }
    public string KindText { get; }
    public string? Path { get; }
    public bool Default { get; }
    public ulong? Size { get; }
    public string SizeText { get; }
    public string Detail { get; }
    public bool IsImage => Kind == "image";
    public bool IsWsl => Kind == "wsl";
}
