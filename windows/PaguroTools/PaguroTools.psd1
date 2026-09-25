@{
    RootModule           = 'PaguroTools.dll'
    ModuleVersion        = '0.2.0'
    GUID                 = '5d0b7c1e-7a0e-4f55-9d3c-2f5e8f0c6a41'
    Author               = 'paguro'
    Description          = 'PowerShell front end of paguro (INTERFACES.md sec. 11.7): a binary module whose cmdlets call the paguro service over \\.\pipe\paguro and return typed objects.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FormatsToProcess     = @('PaguroTools.format.ps1xml')
    CmdletsToExport      = @(
        'Get-PaguroService', 'Get-PaguroStatus', 'Get-PaguroCheck', 'Repair-PaguroCheck', 'Get-PaguroSecureBoot',
        'Export-PaguroHardware', 'Get-PaguroModalias', 'New-PaguroDisk', 'Get-PaguroDisk',
        'Get-PaguroConfig', 'Test-PaguroConfig', 'Set-PaguroConfig',
        'Get-PaguroFirmwareVariable', 'Set-PaguroFirmwareVariable', 'Remove-PaguroFirmwareVariable',
        'Get-PaguroBootEntry', 'New-PaguroBootEntry', 'Remove-PaguroBootEntry', 'Set-PaguroBootNext',
        'Install-PaguroEsp', 'Test-PaguroEsp', 'Repair-PaguroEsp', 'Register-PaguroMok', 'Get-PaguroMok',
        'Test-PaguroPreflight', 'Restart-PaguroLinux', 'Request-PaguroSetupTpm', 'Repair-Paguro', 'Uninstall-Paguro',
        'Install-Paguro', 'Get-PaguroSetup',
        'Get-PaguroDistribution', 'Rename-PaguroDistribution', 'Remove-PaguroDistribution', 'Resize-PaguroDistribution',
        'Enter-PaguroDistro', 'Dismount-PaguroDistro', 'Install-PaguroDistro', 'Enter-PaguroInstaller',
        'Get-PaguroProtection', 'Set-PaguroProtection', 'Test-PaguroSecret'
    )
    FunctionsToExport    = @()
    VariablesToExport    = @()
    AliasesToExport      = @('Start-PaguroLinux')
    PrivateData          = @{ PSData = @{ Tags = @('paguro', 'dual-boot', 'uefi') } }
}
