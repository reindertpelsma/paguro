using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class ChecksPage : Page
{
    public ChecksViewModel VM => App.Main.Checks;
    public ChecksPage() => InitializeComponent();
    void Fix_Click(object sender, RoutedEventArgs e) => VM.Fix.Execute(((FrameworkElement)sender).Tag);
}
