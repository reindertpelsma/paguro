using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class ProtectionPage : Page
{
    public ProtectionViewModel VM => App.Main.Protection;

    public ProtectionPage()
    {
        InitializeComponent();
        VM.PropertyChanged += Sync;
        Unloaded += (_, _) => VM.PropertyChanged -= Sync;
        Sync(null, new PropertyChangedEventArgs(null));
    }

    /// <summary>Selection, keyboard and checkbox follow the view model (set by Load).</summary>
    void Sync(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is null or nameof(VM.Selected) && ChoiceList.SelectedItem != VM.Selected) ChoiceList.SelectedItem = VM.Selected;
        if (e.PropertyName is null or nameof(VM.Keyboard) && KeyboardBox.SelectedItem != VM.Keyboard) KeyboardBox.SelectedItem = VM.Keyboard;
        if (e.PropertyName is null or nameof(VM.PinBypass)) Bypass.IsChecked = VM.PinBypass;
        if (e.PropertyName == nameof(VM.Secret) && VM.Secret.Length == 0) { Secret.Password = ""; Again.Password = ""; }
    }

    void Choice_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (ChoiceList.SelectedItem is ChoiceItem c) VM.Selected = c;
        if (VM.Selected != ChoiceList.SelectedItem) ChoiceList.SelectedItem = VM.Selected;
    }

    void Keyboard_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (KeyboardBox.SelectedItem is Paguro.Api.KeyboardLayout k) VM.Keyboard = k;
    }

    void Secret_Changed(object sender, RoutedEventArgs e) => VM.Secret = Secret.Password;
    void Again_Changed(object sender, RoutedEventArgs e) => VM.SecretAgain = Again.Password;
    void Bypass_Click(object sender, RoutedEventArgs e) => VM.PinBypass = Bypass.IsChecked == true;
}
