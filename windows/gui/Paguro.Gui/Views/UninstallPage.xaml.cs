using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class UninstallPage : Page
{
    public UninstallViewModel VM => App.Main.Uninstall;

    public UninstallPage()
    {
        InitializeComponent();
        DeleteBox.IsChecked = VM.DeleteImages;
    }

    void Delete_Click(object sender, RoutedEventArgs e) => VM.DeleteImages = DeleteBox.IsChecked == true;
}
