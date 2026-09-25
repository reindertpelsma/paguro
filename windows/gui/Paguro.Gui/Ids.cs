namespace Paguro.Gui;

/// <summary>AutomationIds built from data (x:Bind functions), for UI tests.</summary>
public static class Ids
{
    public static string Fix(string id) => "fix_" + id;
    public static string Choice(string id) => "choice_" + id;
    public static string Item(string prefix, string id) => prefix + "_" + id;
}
