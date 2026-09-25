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
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1180, 800));
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
