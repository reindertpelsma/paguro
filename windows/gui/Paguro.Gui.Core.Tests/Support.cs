using System.Reflection;
using Paguro.Api;
using Paguro.Testing;

namespace Paguro.Gui.Tests;

[AttributeUsage(AttributeTargets.Assembly)]
public sealed class PathsAttribute(string fixtures, string gui) : Attribute
{
    public string Fixtures { get; } = fixtures;
    public string Gui { get; } = gui;
}

public static class Paths
{
    static PathsAttribute A => typeof(Paths).Assembly.GetCustomAttribute<PathsAttribute>()!;
    public static string Fixtures => A.Fixtures;
    public static string Gui => A.Gui;
}

/// <summary>Dialogs that answer as told and remember what was asked.</summary>
public sealed class FakeDialogs : IDialogs
{
    public bool Answer = true;
    public string? Secret = "correct horse";
    public string? Text = "renamed";
    public readonly List<string> Asked = new();
    public readonly List<string> Ran = new();

    public Task<bool> ConfirmAsync(string title, string message, string yes, string no, bool danger = false)
    {
        Asked.Add($"confirm:{title}");
        return Task.FromResult(Answer);
    }
    public Task MessageAsync(string title, string message) { Asked.Add($"message:{title}:{message}"); return Task.CompletedTask; }
    public Task<string?> AskSecretAsync(string title, string prompt, bool confirm) { Asked.Add($"secret:{title}"); return Task.FromResult(Secret); }
    public Task<string?> AskTextAsync(string title, string prompt, string initial) { Asked.Add($"text:{title}"); return Task.FromResult(Text); }
    public Task<int> RunAsync(string program, IReadOnlyList<string> args, bool elevated)
    {
        Ran.Add($"{(elevated ? "elevated " : "")}{program} {string.Join(" ", args)}");
        return Task.FromResult(0);
    }
}

/// <summary>A fake service answering from the API fixtures, and a session on it.</summary>
public sealed class Rig : IDisposable
{
    public FakeServer Server { get; } = FakeServer.Start();
    public FakeDialogs Dialogs { get; } = new();
    public Session Session { get; }
    public Strings S { get; } = Strings.Load("en");

    public Rig(string? callerJson = null)
    {
        Server.LoadFixtures(Paths.Fixtures);
        if (callerJson != null)
            Server.OnData("service.info", $$"""{"api_version":"1.0","service":true,"caller":{{callerJson}},"methods":[]}""");
        Session = new Session(Session.Pipe(Server.PipeName), S, Dialogs);
    }

    public FakeServer.Call Last(string method) => Server.Calls.Last(c => c.Method == method);
    public string? P(string method, string name) => Last(method).Params[name]?.ToString();

    public void Dispose() => Server.Dispose();
}
