using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Paguro.Gui;

/// <summary>IDialogs as ContentDialogs. PAGURO_GUI_NO_RUN=1 (UI tests) makes
/// RunAsync record instead of starting programs.</summary>
public sealed class Dialogs : IDialogs
{
    public Window? Window { get; set; }
    XamlRoot Root => Window!.Content.XamlRoot;

    ContentDialog Make(string title, object content, string primary, string? close)
    {
        var d = new ContentDialog
        {
            XamlRoot = Root,
            Title = title,
            Content = content,
            PrimaryButtonText = primary,
            DefaultButton = ContentDialogButton.Primary,
        };
        if (close != null) d.CloseButtonText = close;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(d, "Dialog");
        return d;
    }

    static TextBlock Text(string s) => new() { Text = s, TextWrapping = TextWrapping.Wrap, MaxWidth = 520 };

    public async Task<bool> ConfirmAsync(string title, string message, string yes, string no, bool danger = false)
    {
        var d = Make(title, Text(message), yes, no);
        if (danger) d.DefaultButton = ContentDialogButton.Close;
        return await d.ShowAsync() == ContentDialogResult.Primary;
    }

    public async Task MessageAsync(string title, string message) =>
        await Make(title, Text(message), App.S["ok"], null).ShowAsync();

    public async Task<string?> AskSecretAsync(string title, string prompt, bool confirm)
    {
        var a = new PasswordBox { Header = prompt, Width = 360 };
        var b = new PasswordBox { Header = App.S["again"], Width = 360, Visibility = confirm ? Visibility.Visible : Visibility.Collapsed };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(a, "SecretBox");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(b, "SecretAgainBox");
        var panel = new StackPanel { Spacing = 8, Children = { a, b } };
        while (true)
        {
            if (await Make(title, panel, App.S["ok"], App.S["cancel"]).ShowAsync() != ContentDialogResult.Primary) return null;
            if (!confirm || a.Password == b.Password) return a.Password;
        }
    }

    public async Task<string?> AskTextAsync(string title, string prompt, string initial)
    {
        var box = new TextBox { Header = prompt, Text = initial, Width = 360 };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(box, "TextBox");
        return await Make(title, box, App.S["ok"], App.S["cancel"]).ShowAsync() == ContentDialogResult.Primary ? box.Text : null;
    }

    public static readonly List<string> Ran = new();

    public Task<int> RunAsync(string program, IReadOnlyList<string> args, bool elevated)
    {
        if (Environment.GetEnvironmentVariable("PAGURO_GUI_NO_RUN") == "1")
        {
            Ran.Add(program + " " + string.Join(" ", args));
            return Task.FromResult(0);
        }
        var psi = new ProcessStartInfo(program) { UseShellExecute = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (elevated) psi.Verb = "runas";
        return Task.Run(() =>
        {
            try
            {
                using var p = Process.Start(psi);
                if (p == null) return -1;
                if (elevated) { p.WaitForExit(); return p.ExitCode; }
                return 0;
            }
            catch (System.ComponentModel.Win32Exception) { return -1; }
        });
    }
}
