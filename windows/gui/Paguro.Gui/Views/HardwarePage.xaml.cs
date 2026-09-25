using Microsoft.UI.Xaml.Controls;
using Paguro.Gui.ViewModels;

namespace Paguro.Gui.Views;

public sealed partial class HardwarePage : Page
{
    public HardwareViewModel VM => App.Main.Hardware;
    public HardwarePage() => InitializeComponent();
}
