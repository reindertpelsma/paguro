using System.Globalization;
using Microsoft.UI.Xaml;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui;

/// <summary>paguro-gui [--lang en|nl|de|fr|es]. PAGURO_PIPE names another pipe
/// (the UI tests' fake service); PAGURO_LANG sets the language.</summary>
public partial class App : Application
{
    public static MainViewModel Main { get; private set; } = null!;
    public static Strings S => Main.S;
    public static MainWindow? Window { get; private set; }

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var argv = Environment.GetCommandLineArgs();
        var i = Array.IndexOf(argv, "--lang");
        var lang = i >= 0 && i + 1 < argv.Length ? argv[i + 1]
            : Environment.GetEnvironmentVariable("PAGURO_LANG") is { Length: > 0 } l ? l
            : Strings.LanguageFor(CultureInfo.CurrentUICulture);
        var strings = Strings.Load(lang);
        var dialogs = new Dialogs();
        Main = new MainViewModel(new Session(Session.Pipe(), strings, dialogs));
        Window = new MainWindow();
        dialogs.Window = Window;
        Window.Activate();
    }
}
