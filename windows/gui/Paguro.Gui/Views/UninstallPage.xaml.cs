using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class UninstallPage : Page
{
    public UninstallViewModel VM => App.Main.Uninstall;

    public UninstallPage()
    {
        InitializeComponent();
        ImagesChoice.SelectedIndex = VM.DeleteImages switch { false => 0, true => 1, null => -1 };
    }

    void Images_Changed(object sender, SelectionChangedEventArgs e) =>
        VM.DeleteImages = ImagesChoice.SelectedIndex switch { 0 => false, 1 => true, _ => null };
}
