using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class SecureBootPage : Page
{
    public SecureBootViewModel VM => App.Main.SecureBoot;
    public SecureBootPage() => InitializeComponent();
}
