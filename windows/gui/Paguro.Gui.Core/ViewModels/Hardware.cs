using System.Collections.ObjectModel;
using Paguro.Api;

namespace Paguro.Gui.ViewModels;

/// <summary>Screen 3: the host export (INTERFACES §11.5) shown before the
/// install — GPU, Wi-Fi, CPU, board — and what the installer will be told.</summary>
public sealed class HardwareViewModel : ObservableObject
{
    readonly Session session;
    public HardwareViewModel(Session session)
    {
        this.session = session;
        Load = new AsyncCommand(LoadAsync);
    }

    public Strings S => session.S;
    public AsyncCommand Load { get; }
    public ObservableCollection<HardwareRow> Rows { get; } = new();
    /// <summary>The modaliases the installer's detection will see.</summary>
    public ObservableCollection<string> Told { get; } = new();
    string? error;
    public string? Error { get => error; private set => Set(ref error, value); }
    HostHardware? export;
    public HostHardware? Export { get => export; private set => Set(ref export, value); }

    public static string ClassOf(string pciClass) => pciClass.Length < 4 ? "other" : pciClass[..4] switch
    {
        "0300" or "0302" or "0380" => "gpu",
        "0280" => "wifi",
        "0200" => "network",
        "0403" or "0401" => "audio",
        "0106" or "0108" => "storage",
        _ => "other",
    };

    public async Task LoadAsync()
    {
        var r = await session.CallAsync<HostHardware>(PaguroMethods.HwExport, new NoParams());
        Error = session.LastError;
        if (r == null) return;
        Export = r.Data;
        Rows.Clear();
        var h = r.Data;
        Rows.Add(new HardwareRow(S["hw_cpu"], $"{h.Cpu.Vendor} · family {h.Cpu.Family}, model {h.Cpu.Model}"));
        Rows.Add(new HardwareRow(S["hw_board"], string.Join(" · ", new[] { h.Dmi.SysVendor, h.Dmi.ProductName, h.Dmi.BoardName }.Where(x => !string.IsNullOrEmpty(x)))));
        foreach (var p in h.Pci)
        {
            var kind = ClassOf(p.Class ?? "");
            if (kind is "gpu" or "wifi" or "network" or "storage")
                Rows.Add(new HardwareRow(S[$"hw_{kind}"], $"{p.Vendor}:{p.Device} (class {p.Class})"));
        }
        foreach (var d in h.Storage)
            Rows.Add(new HardwareRow(S["hw_disk"], $"{d.Model} · {d.Bus} · {(d.Size ?? 0) / 1_000_000_000} GB"));
        var m = await session.CallAsync<Modaliases>(PaguroMethods.HwModalias, new ModaliasParams { Hardware = h });
        Told.Clear();
        foreach (var x in m?.Data.Items ?? []) Told.Add(x);
    }
}

public sealed record HardwareRow(string Kind, string Text);
