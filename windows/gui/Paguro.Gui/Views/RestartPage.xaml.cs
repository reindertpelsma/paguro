using System.ComponentModel;
using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class RestartPage : Page
{
    public RestartViewModel VM => App.Main.Restart;

    public RestartPage()
    {
        InitializeComponent();
        VM.PropertyChanged += Sync;
        Unloaded += (_, _) => VM.PropertyChanged -= Sync;
        Sync(null, new PropertyChangedEventArgs(null));
    }

    void Sync(object? s, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is null or nameof(VM.Entry) && (EntryBox.SelectedItem as string) != VM.Entry) EntryBox.SelectedItem = VM.Entry;
    }

    void Entry_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (EntryBox.SelectedItem is string s) VM.Entry = s;
    }
}
