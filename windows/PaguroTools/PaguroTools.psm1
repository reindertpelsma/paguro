# ASCII only: Windows PowerShell 5.1 reads BOM-less files as ANSI.
# PaguroTools - a thin script module over `paguro.exe --json`.
#
# Every cmdlet builds a paguro command line, runs it with --json and returns
# the `data` of the paguro-cli/1 envelope (crates/paguro-win/JSON.md). No
# logic lives here: formats, checks and decisions are all in paguro.exe.
#
# - -WhatIf maps to --dry-run; destructive commands ask for confirmation
#   (ConfirmImpact High) and pass --yes only when it was given.
# - A failed command throws; the exception carries the paguro error code,
#   exit code and structured detail in .Data.
# - The Linux passphrase is a [SecureString], written to paguro's standard
#   input (--passphrase-stdin); it never appears on a command line.

Set-StrictMode -Version 3.0

$script:Schema = 'paguro-cli/1'

function Get-PaguroExe {
    if ($env:PAGURO_EXE) { return $env:PAGURO_EXE }
    $here = Join-Path $PSScriptRoot 'paguro.exe'
    if (Test-Path $here) { return $here }
    $cmd = Get-Command paguro.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw 'paguro.exe not found: put it next to the module, on PATH, or in $env:PAGURO_EXE'
}

# The one place a process starts; Pester mocks this.
function Invoke-PaguroProcess {
    param(
        [Parameter(Mandatory)][string[]] $ArgumentList,
        [string] $StandardInput
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = Get-PaguroExe
    if ($psi.PSObject.Properties['ArgumentList']) {
        foreach ($a in $ArgumentList) { [void]$psi.ArgumentList.Add($a) }
    } else {
        # Windows PowerShell 5.1 (.NET Framework): one string, quoted the way
        # the MSVC runtime splits it.
        $psi.Arguments = ($ArgumentList | ForEach-Object { ConvertTo-ArgvQuoted $_ }) -join ' '
    }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $StandardInput) { $p.StandardInput.Write($StandardInput) }
    $p.StandardInput.Close()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $out; StdErr = $err }
}

# CommandLineToArgvW's rules: backslashes are literal except before a quote.
function ConvertTo-ArgvQuoted([string] $a) {
    if ($a -ne '' -and $a -notmatch '[\s"]') { return $a }
    $sb = [System.Text.StringBuilder]::new('"')
    $bs = 0
    foreach ($c in $a.ToCharArray()) {
        if ($c -eq '\') { $bs++; continue }
        if ($c -eq '"') { [void]$sb.Append([char]'\', 2 * $bs + 1).Append('"') }
        else { [void]$sb.Append([char]'\', $bs).Append($c) }
        $bs = 0
    }
    [void]$sb.Append([char]'\', 2 * $bs).Append('"')
    $sb.ToString()
}

function ConvertFrom-SecureStringPlain([securestring] $s) {
    $b = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

<#
.SYNOPSIS
Run paguro.exe with --json and return the envelope's data.
.PARAMETER Arguments
The paguro command line after `paguro` (e.g. 'disk','inspect','C:\x.vhd').
.PARAMETER DryRun
Pass --dry-run.
.PARAMETER Passphrase
Sent on standard input with --passphrase-stdin.
#>
function Invoke-Paguro {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string[]] $Arguments,
        [switch] $DryRun,
        [securestring] $Passphrase,
        [string] $StandardInput
    )
    $argv = @('--json')
    if ($DryRun) { $argv += '--dry-run' }
    $stdin = $StandardInput
    if ($Passphrase) {
        $argv += '--passphrase-stdin'
        $stdin = (ConvertFrom-SecureStringPlain $Passphrase) + "`n"
    }
    $argv += $Arguments
    $r = Invoke-PaguroProcess -ArgumentList $argv -StandardInput $stdin
    $stdin = $null
    $doc = $null
    try { $doc = $r.StdOut | ConvertFrom-Json -ErrorAction Stop } catch { $doc = $null }
    if ($null -eq $doc) {
        # Usage errors (exit 2) come from the argument parser as text.
        $ex = [System.InvalidOperationException]::new("paguro $($Arguments -join ' '): $($r.StdErr.Trim())")
        $ex.Data['exit'] = $r.ExitCode
        $ex.Data['code'] = 'usage'
        throw $ex
    }
    if ($doc.schema -ne $script:Schema) {
        throw "paguro.exe speaks '$($doc.schema)', this module speaks '$script:Schema'"
    }
    if ($doc.PSObject.Properties['warnings']) {
        foreach ($w in @($doc.warnings)) { if ($w) { Write-Warning $w } }
    }
    if (-not $doc.ok) {
        $e = $doc.error
        $ex = [System.InvalidOperationException]::new("paguro $($doc.command): $($e.message)")
        $ex.Data['exit'] = $e.exit
        $ex.Data['code'] = $e.code
        if ($e.PSObject.Properties['data']) { $ex.Data['detail'] = $e.data }
        $cat = switch ($e.code) {
            'not_found' { 'ObjectNotFound' }
            'needs_elevation' { 'PermissionDenied' }
            'refused' { 'InvalidOperation' }
            'check_failed' { 'InvalidResult' }
            default { 'NotSpecified' }
        }
        $rec = [System.Management.Automation.ErrorRecord]::new($ex, "Paguro.$($e.code)", $cat, $doc.command)
        $PSCmdlet.ThrowTerminatingError($rec)
    }
    if ($r.ExitCode -eq 8) {
        Write-Warning "paguro $($doc.command): not finished - restart, then run it again"
    }
    $doc.data
}

function Get-PaguroStatus {
    [CmdletBinding()] param()
    Invoke-Paguro @('status')
}

function Export-PaguroHardware {
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $Path)
    $a = @('hw', 'export')
    if ($Path) { $a += @('--output', $Path) }
    Invoke-Paguro $a -DryRun:($Path -and -not $PSCmdlet.ShouldProcess($Path, 'write host-hardware.json'))
}

function New-PaguroDisk {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Size
    )
    $dry = -not $PSCmdlet.ShouldProcess($Path, "create a $Size fixed VHD")
    Invoke-Paguro @('disk', 'create', '--size', $Size, '--path', $Path) -DryRun:$dry
}

function Get-PaguroDisk {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string] $Path)
    process { Invoke-Paguro @('disk', 'inspect', $Path) }
}

function Get-PaguroConfig {
    [CmdletBinding()] param()
    Invoke-Paguro @('config', 'show')
}

function Test-PaguroConfig {
    [CmdletBinding()] param()
    try { $null = Invoke-Paguro @('config', 'validate'); $true }
    catch {
        if ($_.Exception.Data['code'] -eq 'check_failed') { Write-Verbose $_.Exception.Message; $false }
        else { throw }
    }
}

function Set-PaguroConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string] $Entry,
        [string] $Volume,
        [string] $Root,
        [string] $EfiDisk,
        [string] $Efi,
        [string] $EfiFile,
        [string] $Default,
        [string] $RemoveEntry,
        [Nullable[bool]] $Tpm,
        [Nullable[bool]] $SetupTpm,
        [Nullable[bool]] $Passphrase,
        [ValidateSet('dark', 'light', 'dark-contrast', 'light-contrast')][string] $Theme,
        [ValidateSet('auto', 'graphics', 'text')][string] $Mode
    )
    $a = @('config', 'set')
    $map = [ordered]@{
        Entry = '--entry'; Volume = '--volume'; Root = '--root'; EfiDisk = '--efi-disk'; Efi = '--efi'
        EfiFile = '--efi-file'; Default = '--default'; RemoveEntry = '--remove-entry'; Theme = '--theme'; Mode = '--mode'
    }
    foreach ($k in $map.Keys) {
        if ($PSBoundParameters.ContainsKey($k)) { $a += @($map[$k], [string]$PSBoundParameters[$k]) }
    }
    foreach ($k in @('Tpm', 'SetupTpm', 'Passphrase')) {
        if ($PSBoundParameters.ContainsKey($k)) {
            $flag = @{ Tpm = '--tpm'; SetupTpm = '--setup-tpm'; Passphrase = '--passphrase' }[$k]
            $a += @($flag, $(if ($PSBoundParameters[$k]) { '1' } else { '0' }))
        }
    }
    Invoke-Paguro $a -DryRun:(-not $PSCmdlet.ShouldProcess('paguro.ini', 'write'))
}

function Get-PaguroFirmwareVariable {
    [CmdletBinding()]
    param([string] $Name)
    if ($Name) { Invoke-Paguro @('efi', 'vars', 'get', $Name) }
    else { (Invoke-Paguro @('efi', 'vars', 'list')).variables }
}

function Get-PaguroBootEntry {
    [CmdletBinding()] param()
    Invoke-Paguro @('efi', 'boot-entry', 'list')
}

function New-PaguroBootEntry {
    [CmdletBinding(SupportsShouldProcess)] param()
    Invoke-Paguro @('efi', 'boot-entry', 'create') -DryRun:(-not $PSCmdlet.ShouldProcess('firmware', "create or repair paguro's Boot#### entry"))
}

function Remove-PaguroBootEntry {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string] $Entry)
    Invoke-Paguro @('efi', 'boot-entry', 'delete', $Entry) -DryRun:(-not $PSCmdlet.ShouldProcess($Entry, 'delete'))
}

function Set-PaguroBootNext {
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $Entry, [switch] $Clear)
    $a = @('efi', 'bootnext')
    if ($Entry) { $a += $Entry }
    if ($Clear) { $a += '--clear' }
    Invoke-Paguro $a -DryRun:(-not $PSCmdlet.ShouldProcess('BootNext', 'set'))
}

function Install-PaguroEsp {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $Shim,
        [Parameter(Mandatory)][string] $MokManager,
        [Parameter(Mandatory)][string] $Loader
    )
    Invoke-Paguro @('esp', 'install', '--shim', $Shim, '--mm', $MokManager, '--loader', $Loader) `
        -DryRun:(-not $PSCmdlet.ShouldProcess('\EFI\paguro', 'install'))
}

function Test-PaguroEsp {
    [CmdletBinding()] param()
    try { $null = Invoke-Paguro @('esp', 'verify'); $true }
    catch {
        if ($_.Exception.Data['code'] -eq 'check_failed') { Write-Verbose $_.Exception.Message; $false }
        else { throw }
    }
}

function Repair-PaguroEsp {
    [CmdletBinding(SupportsShouldProcess)] param()
    Invoke-Paguro @('esp', 'repair') -DryRun:(-not $PSCmdlet.ShouldProcess('\EFI\paguro', 'restore from the saved copies'))
}

function Register-PaguroMok {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string] $Certificate)
    Invoke-Paguro @('mok', 'enroll', '--cert', $Certificate) -DryRun:(-not $PSCmdlet.ShouldProcess($Certificate, 'request MOK enrolment'))
}

function Get-PaguroMok {
    [CmdletBinding()] param([string] $Certificate)
    $a = @('mok', 'status')
    if ($Certificate) { $a += @('--cert', $Certificate) }
    Invoke-Paguro $a
}

function Test-PaguroPreflight {
    [CmdletBinding()] param([switch] $Repair)
    $a = @('preflight')
    if ($Repair) { $a += '--repair' }
    try { Invoke-Paguro $a }
    catch {
        if ($_.Exception.Data['code'] -eq 'check_failed') { $_.Exception.Data['detail'] }
        else { throw }
    }
}

function Restart-PaguroLinux {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([securestring] $Passphrase, [switch] $NoRestart)
    $go = $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'restart into Linux')
    $a = @('restart-linux')
    if ($go -and -not $NoRestart) { $a += '--yes' }
    Invoke-Paguro $a -DryRun:(-not $go) -Passphrase $Passphrase
}

function Request-PaguroSetupTpm {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][securestring] $Passphrase)
    Invoke-Paguro @('stage-setup') -Passphrase $Passphrase -DryRun:(-not $PSCmdlet.ShouldProcess('next boot', 'stage setupTPM'))
}

function Repair-Paguro {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch] $Stage, [switch] $Bootstrap, [securestring] $Passphrase)
    $a = @('repair')
    if ($Stage) { $a += '--stage' }
    if ($Bootstrap) { $a += '--bootstrap' }
    Invoke-Paguro $a -Passphrase $Passphrase -DryRun:(-not $PSCmdlet.ShouldProcess('paguro', 'repair'))
}

function Install-PaguroDistro {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)][string] $Name,
        [Parameter(Mandatory)][string] $Path,
        [string] $Size = '32G',
        [string] $Script,
        [string] $Shim,
        [string] $MokManager,
        [string] $Loader,
        [string] $MokCertificate,
        [securestring] $Passphrase,
        [switch] $Restart
    )
    $a = @('install', $Name, '--path', $Path, '--size', $Size)
    foreach ($p in @(@('Script', '--script'), @('Shim', '--shim'), @('MokManager', '--mm'), @('Loader', '--loader'), @('MokCertificate', '--mok-cert'))) {
        if ($PSBoundParameters.ContainsKey($p[0])) { $a += @($p[1], [string]$PSBoundParameters[$p[0]]) }
    }
    $go = $PSCmdlet.ShouldProcess($Name, 'install')
    if ($go -and $Restart) { $a += '--yes' }
    Invoke-Paguro $a -Passphrase $Passphrase -DryRun:(-not $go)
}

function Uninstall-Paguro {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([switch] $DeleteImages, [switch] $SkipFinalBoot)
    $go = $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'uninstall paguro')
    $a = @('uninstall')
    if ($go) { $a += '--yes' }
    if ($DeleteImages) { $a += '--delete-images' }
    if ($SkipFinalBoot) { $a += '--skip-final-boot' }
    Invoke-Paguro $a -DryRun:(-not $go)
}

Export-ModuleMember -Function @(
    'Invoke-Paguro', 'Get-PaguroStatus', 'Export-PaguroHardware', 'New-PaguroDisk', 'Get-PaguroDisk',
    'Get-PaguroConfig', 'Test-PaguroConfig', 'Set-PaguroConfig', 'Get-PaguroFirmwareVariable',
    'Get-PaguroBootEntry', 'New-PaguroBootEntry', 'Remove-PaguroBootEntry', 'Set-PaguroBootNext',
    'Install-PaguroEsp', 'Test-PaguroEsp', 'Repair-PaguroEsp', 'Register-PaguroMok', 'Get-PaguroMok',
    'Test-PaguroPreflight', 'Restart-PaguroLinux', 'Request-PaguroSetupTpm', 'Repair-Paguro',
    'Install-PaguroDistro', 'Uninstall-Paguro'
)
