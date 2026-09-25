using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;
using Paguro.Gui.Views;

namespace Paguro.Gui;

public sealed partial class MainWindow : Window, INotifyPropertyChanged
{
    public MainViewModel VM => App.Main;
    public bool BannerOpen => VM.Session.Banner.Length > 0;
    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        InitializeComponent();
        Title = VM.Title;
        // 1180×800, or what fits the screen's work area (the CI runner's is 1024×768).
        var work = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Primary).WorkArea;
        AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(work.X, work.Y, Math.Min(1180, work.Width), Math.Min(800, work.Height)));
        VM.Session.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(Session.Banner) || e.PropertyName == nameof(Session.State))
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(BannerOpen)));
        };
        Nav.SelectedItem = Nav.MenuItems[0];
        _ = VM.StartAsync();
    }

    static readonly Dictionary<string, Type> Pages = new()
    {
        ["checks"] = typeof(ChecksPage),
        ["distributions"] = typeof(DistributionsPage),
        ["hardware"] = typeof(HardwarePage),
        ["protection"] = typeof(ProtectionPage),
        ["secureboot"] = typeof(SecureBootPage),
        ["restart"] = typeof(RestartPage),
        ["setup"] = typeof(SetupPage),
        ["uninstall"] = typeof(UninstallPage),
    };

    void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem { Tag: string key } && Pages.TryGetValue(key, out var page))
        {
            PageFrame.Navigate(page);
            if (key != "checks" || VM.Checks.Items.Count > 0) _ = VM.ShowAsync(key);
        }
    }
}
