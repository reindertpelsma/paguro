# PaguroTools

The PowerShell face of paguro (INTERFACES.md §11.7): a **binary module** (C#,
.NET 8, PowerShell 7.4+) whose cmdlets call the paguro service over
`\\.\pipe\paguro` and return the API's typed objects (`Paguro.Api.*`,
generated from [`windows/api/paguro-api.json`](../api/paguro-api.json)).
Nothing is parsed from text.

```powershell
Get-PaguroDistribution | Where-Object Size -gt 20GB | Start-PaguroLinux
Get-PaguroCheck | Where-Object { $_.Fix.Automatic } | Repair-PaguroCheck -WhatIf
Uninstall-Paguro -WhatIf          # what will and will not be touched
Set-PaguroProtection tpm_pin -Keyboard de      # asks for the PIN
```

- `-WhatIf` runs the method's dry run and returns its plan; destructive
  cmdlets have `ConfirmImpact High`.
- Secrets are `SecureString` parameters (`-Pin`, `-Passphrase`, `-Password`),
  sent only to a pipe owned by SYSTEM or Administrators; when the service
  asks back for one that was not given, the cmdlet prompts.
- Long operations (`Install-PaguroDistro`, `Uninstall-Paguro`) report
  progress with `Write-Progress` (and `-Verbose`).
- Every API method has a cmdlet (`[PaguroMethod]`); a Pester test fails when
  one is missing. Windows PowerShell 5.1 is not supported (.NET 8).

## Build and test

```sh
dotnet publish PaguroTools.csproj -c Release -o bin/module
dotnet build ../dotnet/Paguro.Testing -c Release -o bin/testing
pwsh -c 'Invoke-Pester Tests'     # a fake service answering from the API fixtures
```

With `PAGURO_SERVICE_PIPE` naming a running `paguro service console --mock`
(on Linux: `--unix /tmp/CoreFxPipe_<name>`), the end-to-end block runs the
cmdlets against the real service logic too.
