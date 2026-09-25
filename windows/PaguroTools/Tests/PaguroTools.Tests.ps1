# Pester 5+ tests for PaguroTools.
#
# The module is a thin layer, so what is tested is the layer: the command
# line each cmdlet builds, -WhatIf -> --dry-run, confirmation -> --yes, the
# passphrase on stdin and never in argv, the envelope's errors and warnings.
# The process is mocked (Invoke-PaguroProcess), so these run anywhere pwsh
# runs. When $env:PAGURO_EXE names a built paguro.exe (CI on Windows), the
# 'real binary' block runs read-only and dry-run commands against it.

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'PaguroTools.psd1') -Force
    function New-Envelope($Command, $Data, [string[]] $Warnings = @()) {
        [pscustomobject]@{
            ExitCode = 0
            StdOut   = (@{ schema = 'paguro-cli/1'; command = $Command; ok = $true; dry_run = $false; data = $Data; warnings = $Warnings } | ConvertTo-Json -Depth 10)
            StdErr   = ''
        }
    }
    function New-Failure($Command, $Code, $Exit, $Message, $Data = $null) {
        $err = @{ code = $Code; message = $Message; exit = $Exit }
        if ($null -ne $Data) { $err.data = $Data }
        [pscustomobject]@{
            ExitCode = $Exit
            StdOut   = (@{ schema = 'paguro-cli/1'; command = $Command; ok = $false; dry_run = $false; error = $err } | ConvertTo-Json -Depth 10)
            StdErr   = ''
        }
    }
}

Describe 'PaguroTools module' {
    It 'exports the documented cmdlets' {
        $names = (Get-Command -Module PaguroTools).Name
        foreach ($n in 'Get-PaguroStatus', 'Export-PaguroHardware', 'New-PaguroDisk', 'Install-PaguroDistro',
            'Restart-PaguroLinux', 'Set-PaguroConfig', 'Repair-Paguro', 'Uninstall-Paguro') {
            $names | Should -Contain $n
        }
    }
}

Describe 'command lines' {
    BeforeEach {
        $script:calls = [System.Collections.Generic.List[object]]::new()
        Mock -ModuleName PaguroTools Invoke-PaguroProcess {
            $script:calls.Add([pscustomobject]@{ Args = $ArgumentList; Stdin = $StandardInput })
            New-Envelope 'x' @{ ok = 1 }
        }
    }

    It 'Get-PaguroStatus runs status with --json' {
        Get-PaguroStatus | Out-Null
        $script:calls[0].Args | Should -Be @('--json', 'status')
    }

    It 'New-PaguroDisk maps -WhatIf to --dry-run' {
        New-PaguroDisk -Path 'C:\paguro\a.vhd' -Size 20G -WhatIf | Out-Null
        $script:calls[0].Args | Should -Be @('--json', '--dry-run', 'disk', 'create', '--size', '20G', '--path', 'C:\paguro\a.vhd')
        New-PaguroDisk -Path 'C:\paguro\a.vhd' -Size 20G | Out-Null
        $script:calls[1].Args | Should -Not -Contain '--dry-run'
    }

    It 'Set-PaguroConfig passes only bound parameters, booleans as 0/1' {
        Set-PaguroConfig -Entry debian -Root 'C:\paguro\debian.vhd' -Tpm $false -Theme light | Out-Null
        $script:calls[0].Args | Should -Be @('--json', 'config', 'set', '--entry', 'debian', '--root', 'C:\paguro\debian.vhd', '--theme', 'light', '--tpm', '0')
    }

    It 'Restart-PaguroLinux passes --yes only when confirmed, and the passphrase only on stdin' {
        $pw = ConvertTo-SecureString 'correct horse' -AsPlainText -Force
        Restart-PaguroLinux -Passphrase $pw -Confirm:$false | Out-Null
        $c = $script:calls[0]
        $c.Args | Should -Contain '--yes'
        $c.Args | Should -Contain '--passphrase-stdin'
        ($c.Args -join ' ') | Should -Not -Match 'correct horse'
        $c.Stdin | Should -Be "correct horse`n"
        Restart-PaguroLinux -WhatIf | Out-Null
        $script:calls[1].Args | Should -Be @('--json', '--dry-run', 'restart-linux')
    }

    It 'Restart-PaguroLinux -NoRestart prepares without --yes' {
        Restart-PaguroLinux -NoRestart -Confirm:$false | Out-Null
        $script:calls[0].Args | Should -Not -Contain '--yes'
    }

    It 'Install-PaguroDistro builds the install command' {
        $pw = ConvertTo-SecureString 'pw' -AsPlainText -Force
        Install-PaguroDistro debian -Path 'C:\paguro\debian.vhd' -Size 40G -Script 'C:\s.sh' -Shim 'C:\in\shimx64.efi' `
            -MokManager 'C:\in\mmx64.efi' -Loader 'C:\in\paguro.efi' -Passphrase $pw -Confirm:$false | Out-Null
        $script:calls[0].Args | Should -Be @('--json', '--passphrase-stdin', 'install', 'debian', '--path', 'C:\paguro\debian.vhd',
            '--size', '40G', '--script', 'C:\s.sh', '--shim', 'C:\in\shimx64.efi', '--mm', 'C:\in\mmx64.efi', '--loader', 'C:\in\paguro.efi')
    }

    It 'Uninstall-Paguro needs confirmation for --yes' {
        Uninstall-Paguro -DeleteImages -Confirm:$false | Out-Null
        $script:calls[0].Args | Should -Be @('--json', 'uninstall', '--yes', '--delete-images')
        Uninstall-Paguro -WhatIf | Out-Null
        $script:calls[1].Args | Should -Be @('--json', '--dry-run', 'uninstall')
    }

    It 'Repair-Paguro and Request-PaguroSetupTpm' {
        $pw = ConvertTo-SecureString 'pw' -AsPlainText -Force
        Repair-Paguro -Stage -Passphrase $pw | Out-Null
        $script:calls[0].Args | Should -Be @('--json', '--passphrase-stdin', 'repair', '--stage')
        Request-PaguroSetupTpm -Passphrase $pw | Out-Null
        $script:calls[1].Args | Should -Be @('--json', '--passphrase-stdin', 'stage-setup')
    }

    It 'efi, esp and mok cmdlets' {
        Get-PaguroFirmwareVariable -Name PaguroConfigHash | Out-Null
        Set-PaguroBootNext -Clear | Out-Null
        Remove-PaguroBootEntry -Entry 0003 -Confirm:$false | Out-Null
        Install-PaguroEsp -Shim a -MokManager b -Loader c | Out-Null
        Register-PaguroMok -Certificate 'C:\k\mok.der' | Out-Null
        Export-PaguroHardware -Path 'C:\h.json' | Out-Null
        $script:calls[0].Args | Should -Be @('--json', 'efi', 'vars', 'get', 'PaguroConfigHash')
        $script:calls[1].Args | Should -Be @('--json', 'efi', 'bootnext', '--clear')
        $script:calls[2].Args | Should -Be @('--json', 'efi', 'boot-entry', 'delete', '0003')
        $script:calls[3].Args | Should -Be @('--json', 'esp', 'install', '--shim', 'a', '--mm', 'b', '--loader', 'c')
        $script:calls[4].Args | Should -Be @('--json', 'mok', 'enroll', '--cert', 'C:\k\mok.der')
        $script:calls[5].Args | Should -Be @('--json', 'hw', 'export', '--output', 'C:\h.json')
    }
}

Describe 'the envelope' {
    It 'returns data' {
        Mock -ModuleName PaguroTools Invoke-PaguroProcess { New-Envelope 'status' @{ uefi = $true } }
        (Get-PaguroStatus).uefi | Should -BeTrue
    }

    It 'throws a structured error on ok=false' {
        Mock -ModuleName PaguroTools Invoke-PaguroProcess { New-Failure 'disk create' 'refused' 3 'already exists' }
        $e = { New-PaguroDisk -Path x.vhd -Size 1G } | Should -Throw -PassThru
        $e.Exception.Message | Should -Match 'already exists'
        $e.Exception.Data['exit'] | Should -Be 3
        $e.Exception.Data['code'] | Should -Be 'refused'
        $e.CategoryInfo.Category | Should -Be 'InvalidOperation'
    }

    It 'turns check_failed into $false for the Test- cmdlets' {
        Mock -ModuleName PaguroTools Invoke-PaguroProcess { New-Failure 'esp verify' 'check_failed' 6 'modified' @{ files = @() } }
        Test-PaguroEsp | Should -BeFalse
        Test-PaguroConfig | Should -BeFalse
        Test-PaguroPreflight | Should -Not -BeNullOrEmpty -Because 'the failing checks are returned'
    }

    It 'surfaces warnings' {
        Mock -ModuleName PaguroTools Invoke-PaguroProcess { New-Envelope 'config set' @{} @('the TPM seal no longer matches') }
        Set-PaguroConfig -Tpm $true -WarningVariable w -WarningAction SilentlyContinue | Out-Null
        $w | Should -Match 'TPM seal'
    }

    It 'refuses another schema' {
        Mock -ModuleName PaguroTools Invoke-PaguroProcess {
            [pscustomobject]@{ ExitCode = 0; StdOut = '{"schema":"paguro-cli/2","ok":true,"data":{}}'; StdErr = '' }
        }
        { Get-PaguroStatus } | Should -Throw '*paguro-cli/2*'
    }

    It 'reports usage errors from the parser' {
        Mock -ModuleName PaguroTools Invoke-PaguroProcess { [pscustomobject]@{ ExitCode = 2; StdOut = ''; StdErr = 'error: unexpected argument' } }
        $e = { Invoke-Paguro @('nonsense') } | Should -Throw -PassThru
        $e.Exception.Data['exit'] | Should -Be 2
    }

    It 'warns when an operation is pending a restart (exit 8)' {
        Mock -ModuleName PaguroTools Invoke-PaguroProcess {
            $r = New-Envelope 'uninstall' @{ finished = $false }
            $r.ExitCode = 8
            $r
        }
        Uninstall-Paguro -Confirm:$false -WarningVariable w -WarningAction SilentlyContinue | Out-Null
        $w | Should -Match 'restart'
    }
}

Describe 'real binary' -Skip:(-not $env:PAGURO_EXE) {
    It 'status speaks paguro-cli/1' {
        $s = Get-PaguroStatus
        $s.PSObject.Properties.Name | Should -Contain 'uefi'
    }
    It 'a dry-run disk creation changes nothing' -Skip:($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        $p = Join-Path ([System.IO.Path]::GetTempPath()) "paguro-pester-$PID.vhd"
        $r = New-PaguroDisk -Path $p -Size 1G -WhatIf
        $r.format | Should -Be 'fixed_vhd'
        Test-Path $p | Should -BeFalse
    }
    It 'the hardware export has version 1' {
        (Export-PaguroHardware).version | Should -Be 1
    }
    It 'a bad argument is a usage error' {
        $e = { Invoke-Paguro @('frobnicate') } | Should -Throw -PassThru
        $e.Exception.Data['exit'] | Should -Be 2
    }
}
