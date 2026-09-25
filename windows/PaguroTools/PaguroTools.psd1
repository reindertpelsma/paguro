@{
    RootModule        = 'PaguroTools.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '5d0b7c1e-7a0e-4f55-9d3c-2f5e8f0c6a41'
    Author            = 'paguro'
    Description       = 'PowerShell front end for paguro.exe (INTERFACES.md §11.2): a thin script module over `paguro --json` (schema paguro-cli/1).'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @(
        'Invoke-Paguro',
        'Get-PaguroStatus',
        'Export-PaguroHardware',
        'New-PaguroDisk',
        'Get-PaguroDisk',
        'Get-PaguroConfig',
        'Test-PaguroConfig',
        'Set-PaguroConfig',
        'Get-PaguroFirmwareVariable',
        'Get-PaguroBootEntry',
        'New-PaguroBootEntry',
        'Remove-PaguroBootEntry',
        'Set-PaguroBootNext',
        'Install-PaguroEsp',
        'Test-PaguroEsp',
        'Repair-PaguroEsp',
        'Register-PaguroMok',
        'Get-PaguroMok',
        'Test-PaguroPreflight',
        'Restart-PaguroLinux',
        'Request-PaguroSetupTpm',
        'Repair-Paguro',
        'Install-PaguroDistro',
        'Uninstall-Paguro'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('paguro', 'dual-boot', 'uefi') } }
}
