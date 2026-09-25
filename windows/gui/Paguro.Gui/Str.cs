using Microsoft.UI.Xaml.Markup;

namespace Paguro.Gui;

/// <summary>{local:Str Key=checks_title}: a string of the [win] table.</summary>
[MarkupExtensionReturnType(ReturnType = typeof(string))]
public sealed class Str : MarkupExtension
{
    public string Key { get; set; } = "";
    protected override object ProvideValue() => App.S[Key];
}
