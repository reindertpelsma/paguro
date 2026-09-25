using System.Diagnostics;
using System.Reflection;
using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Capturing;
using FlaUI.Core.Definitions;
using FlaUI.Core.Input;
using FlaUI.Core.Tools;
using FlaUI.UIA3;
using Paguro.Testing;

namespace Paguro.Gui.UiTests;

[AttributeUsage(AttributeTargets.Assembly)]
public sealed class FixturesAttribute(string dir) : Attribute
{
    public string Dir { get; } = dir;
}

/// <summary>paguro-gui launched against a fake service (the API fixtures, as
/// an administrator by default), with helpers to find, wait, click and
/// capture.</summary>
public sealed class GuiApp : IDisposable
{
    public static string Fixtures => typeof(GuiApp).Assembly.GetCustomAttribute<FixturesAttribute>()!.Dir;
    public static string Exe => Environment.GetEnvironmentVariable("PAGURO_GUI_EXE")
        ?? throw new InvalidOperationException("set PAGURO_GUI_EXE to the built paguro-gui.exe");
    public static string Shots => Environment.GetEnvironmentVariable("PAGURO_SCREENSHOTS") is { Length: > 0 } s ? s : Path.Combine(AppContext.BaseDirectory, "screenshots");

    public FakeServer Server { get; }
    public Application App { get; }
    public UIA3Automation Automation { get; } = new();
    public Window Window { get; }
    public Strings S { get; }
    public string Lang { get; }

    public GuiApp(string lang = "en", Action<FakeServer>? setup = null, string caller = """{"user":"PC\\me","admin":true,"elevated":false}""")
    {
        Lang = lang;
        S = Strings.Load(lang);
        Server = FakeServer.Start();
        Server.LoadFixtures(Fixtures);
        Server.OnData("service.info", $$"""{"api_version":"1.0","service":true,"caller":{{caller}},"methods":[]}""");
        setup?.Invoke(Server);
        var psi = new ProcessStartInfo(Exe) { UseShellExecute = false };
        psi.Environment["PAGURO_PIPE"] = Server.PipeName;
        psi.Environment["PAGURO_LANG"] = lang;
        psi.Environment["PAGURO_GUI_NO_RUN"] = "1";
        psi.Environment["PAGURO_KLID"] = "0000040C";
        App = Application.Launch(psi);
        Window = App.GetMainWindow(Automation, TimeSpan.FromSeconds(60))
            ?? throw new InvalidOperationException("no main window");
        Window.SetForeground();
    }

    public AutomationElement Find(string automationId, int seconds = 20) =>
        Retry.WhileNull(() => Window.FindFirstDescendant(cf => cf.ByAutomationId(automationId)), TimeSpan.FromSeconds(seconds), TimeSpan.FromMilliseconds(200)).Result
        ?? throw new InvalidOperationException($"no element {automationId}");

    public AutomationElement FindName(string name, AutomationElement? under = null, int seconds = 20) =>
        Retry.WhileNull(() => (under ?? Window).FindFirstDescendant(cf => cf.ByName(name)), TimeSpan.FromSeconds(seconds), TimeSpan.FromMilliseconds(200)).Result
        ?? throw new InvalidOperationException($"no element named {name}");

    /// <summary>The open ContentDialog (it lives in a popup under the window).</summary>
    public AutomationElement Dialog(int seconds = 20) =>
        Retry.WhileNull(() => Window.FindFirstDescendant(cf => cf.ByAutomationId("Dialog"))
                ?? Window.FindFirstDescendant(cf => cf.ByClassName("ContentDialog")), TimeSpan.FromSeconds(seconds), TimeSpan.FromMilliseconds(200)).Result
        ?? throw new InvalidOperationException("no dialog");

    public void Go(string page)
    {
        var item = Find("nav_" + page);
        if (item.Patterns.SelectionItem.IsSupported) item.Patterns.SelectionItem.Pattern.Select();
        else item.Click();
        Wait.UntilInputIsProcessed();
    }

    /// <summary>Wait for a call to reach the fake service.</summary>
    public FakeServer.Call Called(string method, int seconds = 20) =>
        Retry.WhileNull(() => Server.Calls.LastOrDefault(c => c.Method == method), TimeSpan.FromSeconds(seconds), TimeSpan.FromMilliseconds(100)).Result
        ?? throw new InvalidOperationException($"{method} was never called; calls: {string.Join(", ", Server.Calls.Select(c => c.Method))}");

    public void Click(AutomationElement e)
    {
        if (e.Patterns.Invoke.IsSupported) e.Patterns.Invoke.Pattern.Invoke();
        else e.Click();
        Wait.UntilInputIsProcessed();
    }

    public void Type(AutomationElement box, string text)
    {
        box.Focus();
        Keyboard.TypeSimultaneously(FlaUI.Core.WindowsAPI.VirtualKeyShort.CONTROL, FlaUI.Core.WindowsAPI.VirtualKeyShort.KEY_A);
        Keyboard.Type(text);
        Wait.UntilInputIsProcessed();
    }

    /// <summary>A screenshot of the window: screenshots/&lt;lang&gt;-&lt;name&gt;.png.</summary>
    public string Shot(string name)
    {
        Directory.CreateDirectory(Shots);
        Thread.Sleep(400);
        var path = Path.Combine(Shots, $"{Lang}-{name}.png");
        Capture.Element(Window).ToFile(path);
        return path;
    }

    public void Dispose()
    {
        try { App.Close(); } catch (Exception) { }
        try { if (!App.HasExited) App.Kill(); } catch (Exception) { }
        Automation.Dispose();
        Server.Dispose();
    }
}
