using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class DistributionsPage : Page
{
    public DistributionsViewModel VM => App.Main.Distributions;
    public DistributionsPage()
    {
        InitializeComponent();
        ManualBox.IsChecked = VM.Manual;
    }

    static DistroItem Item(object sender) => (DistroItem)((FrameworkElement)sender).Tag;
    void Open_Click(object sender, RoutedEventArgs e) => VM.OpenInContainer.Execute(Item(sender));
    void Rename_Click(object sender, RoutedEventArgs e) => VM.Rename.Execute(Item(sender));
    void Grow_Click(object sender, RoutedEventArgs e) => VM.Grow.Execute(Item(sender));
    void Remove_Click(object sender, RoutedEventArgs e) => VM.Remove.Execute(Item(sender));
    void Bootable_Click(object sender, RoutedEventArgs e) => VM.MakeBootable.Execute(Item(sender));

    void Manual_Click(object sender, RoutedEventArgs e) => VM.Manual = ManualBox.IsChecked == true;

    async void Browse_Click(object sender, RoutedEventArgs e)
    {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        picker.FileTypeFilter.Add(".iso");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window));
        var f = await picker.PickSingleFileAsync();
        if (f != null) VM.IsoPath = f.Path;
    }
}
