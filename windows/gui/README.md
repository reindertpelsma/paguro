# paguro-gui

The installer GUI of INTERFACES.md §11.8: **WinUI 3**, unpackaged and
self-contained, unelevated, MVVM, over the paguro service's pipe. Every
action is an API method (`windows/api/paguro-api.json`) that `paguro.exe`
and a PowerShell cmdlet also reach: nothing is GUI-only.

| project | what | builds and runs on |
|---|---|---|
| `Paguro.Gui.Core` | view models, the session (secrets asked back, errors in words), the `[win]` string tables | any OS (net8.0) |
| `Paguro.Gui.Core.Tests` | view models against `Paguro.Testing.FakeServer` through the real pipe client; string-table checks | any OS |
| `Paguro.Gui` | the WinUI 3 views (`paguro-gui.exe`) | Windows, MSBuild |
| `Paguro.Gui.UiTests` | FlaUI (UIA3): launch, checks, protection choice, restart dialog, every screen, five languages; screenshots | Windows |

Screens, in §11.8's order: checks, distributions, hardware, unlocking
(DESIGN §8d's protection choice), Secure Boot, restart into Linux,
uninstall. Strings come from `themes/default/strings/<lang>.toml` (`[win]`),
en/nl/de/fr/es; the language follows Windows' display language
(`--lang xx` or `PAGURO_LANG` override it).

**Why WinUI 3 and not WPF.** A probe built an unpackaged, self-contained
WinUI 3 app and drove it with FlaUI on GitHub's windows-2022 runner, so the
condition for falling back to WPF does not hold. Two consequences: the XAML
compiler is Windows-only, so the view models were kept free of any UI
framework and carry the logic and its tests; and the app is built with
MSBuild (the runner's .NET SDK 10 `dotnet build` fails on the Windows App
SDK's PRI task).

## Build and test

```sh
dotnet test Paguro.Gui.Core.Tests                        # anywhere
msbuild Paguro.Gui/Paguro.Gui.csproj /restore /p:Configuration=Release /p:Platform=x64   # Windows
PAGURO_GUI_EXE=…\paguro-gui.exe PAGURO_SCREENSHOTS=shots dotnet test Paguro.Gui.UiTests
```

`PAGURO_PIPE` points the app at another pipe (the tests' fake service, or
`paguro-service console --mock --pipe NAME` for the demo machine);
`PAGURO_GUI_NO_RUN=1` records instead of starting terminals or UAC.
