using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class SetupPage : Page
{
    public SetupViewModel VM => App.Main.Setup;
    public SetupPage() => InitializeComponent();
}
