using System.Collections.ObjectModel;

namespace Paguro.Gui.ViewModels;

/// <summary>The window: the screens in the order of INTERFACES §11.8, and
/// the connection banner (with the one UAC prompt: installing the service).</summary>
public sealed class MainViewModel : ObservableObject
{
    public MainViewModel(Session session)
    {
        Session = session;
        Checks = new ChecksViewModel(session);
        Distributions = new DistributionsViewModel(session);
        Hardware = new HardwareViewModel(session);
        Protection = new ProtectionViewModel(session);
        SecureBoot = new SecureBootViewModel(session);
        Restart = new RestartViewModel(session);
        Uninstall = new UninstallViewModel(session);
        Setup = new SetupViewModel(session);
        InstallService = new AsyncCommand(async () => { await session.InstallServiceAsync(); await StartAsync(); }, () => session.NoService);
        session.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(Session.State)) InstallService.Refresh(); };
        foreach (var k in PageKeys) Pages.Add(new PageItem(k, S[$"page_{k}"]));
    }

    public static readonly string[] PageKeys = ["checks", "distributions", "hardware", "protection", "secureboot", "restart", "setup", "uninstall"];

    public Session Session { get; }
    public Strings S => Session.S;
    public string Title => S["app_title"];
    public ObservableCollection<PageItem> Pages { get; } = new();
    public ChecksViewModel Checks { get; }
    public DistributionsViewModel Distributions { get; }
    public HardwareViewModel Hardware { get; }
    public ProtectionViewModel Protection { get; }
    public SecureBootViewModel SecureBoot { get; }
    public RestartViewModel Restart { get; }
    public UninstallViewModel Uninstall { get; }
    public SetupViewModel Setup { get; }
    public AsyncCommand InstallService { get; }

    /// <summary>Connect, then the first screen's data.</summary>
    public async Task StartAsync()
    {
        if (await Session.EnsureAsync()) await Checks.LoadAsync();
    }

    /// <summary>Load a screen's data when it is shown.</summary>
    public Task ShowAsync(string key) => key switch
    {
        "checks" => Checks.LoadAsync(),
        "distributions" => Distributions.LoadAsync(),
        "hardware" => Hardware.LoadAsync(),
        "protection" => Protection.LoadAsync(null),
        "secureboot" => SecureBoot.LoadAsync(),
        "restart" => Restart.LoadAsync(),
        "setup" => Setup.LoadAsync(),
        "uninstall" => Uninstall.LoadAsync(),
        _ => Task.CompletedTask,
    };
}

public sealed record PageItem(string Key, string Title);
