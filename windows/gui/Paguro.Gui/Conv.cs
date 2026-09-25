namespace Paguro.Gui;

/// <summary>x:Bind helper functions.</summary>
public static class Conv
{
    public static bool NotNull(object? o) => o != null;
    public static bool Not(bool b) => !b;
    public static bool NotEmpty(string? s) => !string.IsNullOrEmpty(s);
    /// <summary>A choice that is not offered is shown, dimmed, with its reason.</summary>
    public static double Dim(bool offered) => offered ? 1.0 : 0.45;
}
