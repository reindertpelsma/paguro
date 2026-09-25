using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace Paguro.Gui;

/// <summary>INotifyPropertyChanged with a setter helper.</summary>
public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>An async command: disabled while it runs; failures go to <see cref="Failed"/>.</summary>
public sealed class AsyncCommand : ICommand
{
    readonly Func<object?, Task> run;
    readonly Func<object?, bool>? can;
    bool busy;

    public AsyncCommand(Func<Task> run, Func<bool>? can = null) : this(_ => run(), can == null ? null : _ => can()) { }

    public AsyncCommand(Func<object?, Task> run, Func<object?, bool>? can = null)
    {
        this.run = run;
        this.can = can;
    }

    public event EventHandler? CanExecuteChanged;
    /// <summary>An exception the command did not handle.</summary>
    public event Action<Exception>? Failed;

    public bool IsRunning => busy;

    public bool CanExecute(object? parameter) => !busy && (can?.Invoke(parameter) ?? true);

    public async void Execute(object? parameter) => await ExecuteAsync(parameter);

    public async Task ExecuteAsync(object? parameter = null)
    {
        if (!CanExecute(parameter)) return;
        busy = true;
        Refresh();
        try { await run(parameter); }
        catch (Exception e) { Failed?.Invoke(e); }
        finally
        {
            busy = false;
            Refresh();
        }
    }

    public void Refresh() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>What view models ask of the user; the app shows dialogs, tests answer.</summary>
public interface IDialogs
{
    /// <summary>A yes/no question; <paramref name="danger"/> styles the yes button as destructive.</summary>
    Task<bool> ConfirmAsync(string title, string message, string yes, string no, bool danger = false);
    Task MessageAsync(string title, string message);
    /// <summary>A secret typed without echo; null when cancelled.</summary>
    Task<string?> AskSecretAsync(string title, string prompt, bool confirm);
    /// <summary>A line of plain text; null when cancelled.</summary>
    Task<string?> AskTextAsync(string title, string prompt, string initial);
    /// <summary>Run a program (an elevated one when <paramref name="elevated"/>, which prompts UAC).</summary>
    Task<int> RunAsync(string program, IReadOnlyList<string> args, bool elevated);
}
