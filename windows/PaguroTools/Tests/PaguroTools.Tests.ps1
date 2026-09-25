# Pester 5+ tests for the PaguroTools binary module: every cmdlet, against a
# fake paguro service (Paguro.Testing.FakeServer) that answers from the API
# fixtures (windows/api/fixtures, made by the Rust side from the real
# methods) and records each call. Runs wherever pwsh 7.4+ runs: .NET's
# named pipes are Unix sockets on Linux.
#
#   $env:PAGURO_MODULE       PaguroTools.psd1 of a build (default: ../bin/module)
#   $env:PAGURO_TESTING_DLL  Paguro.Testing.dll (default: ../bin/testing)

Describe 'PaguroTools' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $module = if ($env:PAGURO_MODULE) { $env:PAGURO_MODULE } else { Join-Path $root 'bin/module/PaguroTools.psd1' }
        $testing = if ($env:PAGURO_TESTING_DLL) { $env:PAGURO_TESTING_DLL } else { Join-Path $root 'bin/testing/Paguro.Testing.dll' }
        $script:fixtures = Join-Path $root '../api/fixtures'
        Add-Type -Path $testing
        Import-Module $module -Force
        $script:srv = [Paguro.Testing.FakeServer]::Start()
        $srv.LoadFixtures($fixtures)
        $env:PAGURO_PIPE = $srv.PipeName
        $env:PAGURO_SHELL = if ($IsWindows) { 'hostname.exe' } else { 'true' }

        # These tests check what reaches the service; a command error the fixture
    # answers with (the demo machine has no Boot0001, no mok.der) is written,
    # not thrown, even under the CI shell's $ErrorActionPreference = 'Stop'.
    $global:PSDefaultParameterValues['*-Paguro*:ErrorAction'] = 'SilentlyContinue'
    function script:Last { $srv.Calls[$srv.Calls.Count - 1] }
        function script:P([string] $name) {
            $n = (Last).Params[$name]
            if ($null -eq $n) { return $null }
            $n.GetValue[object]().ToString()
        }
        function script:Secure([string] $s) { ConvertTo-SecureString $s -AsPlainText -Force }
        # A stand-in paguro.exe: logs its arguments, writes a --json envelope
        # to the --report file (as the real one does).
        $script:FakeLog = Join-Path ([IO.Path]::GetTempPath()) "paguro-fake-$PID.log"
        Remove-Item $script:FakeLog -ErrorAction SilentlyContinue
        $data = '{"schema":"paguro-cli/1","command":"x","ok":true,"dry_run":false,"warnings":[],"data":{"finished":true,"steps":[],"state":{"installed":true,"version":"0","install_dir":"x","setup_copy":true,"app":true,"apps_and_features":true,"service":true}}}'
        if ($IsWindows) {
            $script:FakeExe = Join-Path ([IO.Path]::GetTempPath()) "paguro-fake-$PID.cmd"
            Set-Content $script:FakeExe -Encoding ascii -Value @(
                '@echo off', "echo %*>>`"$script:FakeLog`"", ':loop', 'if "%~1"=="" goto done',
                'if "%~1"=="--report" set "R=%~2"', 'shift', 'goto loop', ':done', ">`"%R%`" echo $data")
        } else {
            $script:FakeExe = Join-Path ([IO.Path]::GetTempPath()) "paguro-fake-$PID.sh"
            Set-Content $script:FakeExe -Value @('#!/bin/sh', "echo `"`$*`" >> '$script:FakeLog'",
                'while [ $# -gt 0 ]; do [ "$1" = --report ] && R="$2"; shift; done', "printf '%s' '$data' > `"`$R`"")
            chmod +x $script:FakeExe
        }
    }

    AfterAll {
        $srv.Dispose()
        Remove-Item env:PAGURO_PIPE, env:PAGURO_SHELL -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $srv.ClearCalls()
        $srv.LoadFixtures($fixtures)
    }

    Describe 'the module' {
        It 'exports a cmdlet for every API method (nothing is GUI-only)' {
            $exported = @((Get-Command -Module PaguroTools).Name)
            $asm = (Get-Command Get-PaguroStatus).ImplementingType.Assembly
            $covered = $asm.GetTypes() |
                Where-Object { $_.IsSubclassOf([System.Management.Automation.PSCmdlet]) -and -not $_.IsAbstract } |
                ForEach-Object { $_.GetCustomAttributes([Paguro.PowerShell.PaguroMethodAttribute], $false).Method } |
                Sort-Object -Unique
            foreach ($m in [Paguro.Api.PaguroMethods]::All) {
                $covered | Should -Contain $m.Name -Because "$($m.Name) needs a cmdlet"
                foreach ($c in $m.Cmdlets) { $exported | Should -Contain $c -Because "the schema names $c for $($m.Name)" }
            }
        }

        It 'fails with a clear error when the service is not there' {
            $old = $env:PAGURO_PIPE
            try {
                $env:PAGURO_PIPE = 'paguro-nobody-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
                { Get-PaguroStatus -ErrorAction Stop } | Should -Throw -ErrorId 'paguro.no_service*'
            } finally { $env:PAGURO_PIPE = $old }
        }

        It 'turns a command error into an ErrorRecord with its category' {
            $srv.OnError('status', 'needs_elevation', 7, 'status needs an administrator')
            Get-PaguroStatus -ErrorAction SilentlyContinue -ErrorVariable e | Should -BeNullOrEmpty
            $e[0].FullyQualifiedErrorId | Should -BeLike 'paguro.needs_elevation*'
            $e[0].CategoryInfo.Category | Should -Be 'PermissionDenied'
            $e[0].Exception.Exit | Should -Be 7
        }
    }

    Describe 'status and checks' {
        It 'Get-PaguroService' {
            $s = Get-PaguroService
            $s | Should -BeOfType [Paguro.Api.ServiceInfo]
            $s.ApiVersion | Should -Be '1.1'
            (Last).Method | Should -Be 'service.info'
        }
        It 'Get-PaguroStatus' {
            $s = Get-PaguroStatus
            $s | Should -BeOfType [Paguro.Api.Status]
            $s.Uefi | Should -BeTrue
            $s.Arch | Should -Be 'x64'
        }
        It 'Get-PaguroCheck returns one typed object per check, filterable' {
            $all = @(Get-PaguroCheck)
            $all.Count | Should -Be 8
            $all[0] | Should -BeOfType [Paguro.Api.SystemCheck]
            @(Get-PaguroCheck fast_startup).State | Should -Be 'warn'
        }
        It 'Repair-PaguroCheck takes checks from the pipeline; -WhatIf is the dry run' {
            Get-PaguroCheck | Where-Object { $_.Fix.Automatic } | Repair-PaguroCheck -WhatIf | Out-Null
            (Last).Method | Should -Be 'checks.fix'
            P 'id' | Should -Be 'fast_startup'
            P 'dry_run' | Should -Be 'True'
            Repair-PaguroCheck fast_startup -Confirm:$false | Out-Null
            P 'dry_run' | Should -BeNullOrEmpty
        }
        It 'Get-PaguroSecureBoot' {
            $s = Get-PaguroSecureBoot
            $s | Should -BeOfType [Paguro.Api.SecureBootStatus]
            $s.SecureBoot | Should -BeTrue
        }
    }

    Describe 'hardware and disks' {
        It 'Export-PaguroHardware writes the file itself and returns the object' {
            $f = Join-Path ([IO.Path]::GetTempPath()) "hw-$([guid]::NewGuid()).json"
            try {
                $h = Export-PaguroHardware -Path $f
                $h | Should -BeOfType [Paguro.Api.HostHardware]
                (Get-Content $f -Raw | ConvertFrom-Json).version | Should -Be 1
            } finally { Remove-Item $f -ErrorAction SilentlyContinue }
        }
        It 'Get-PaguroModalias takes an export from the pipeline or a file' {
            $m = @(Export-PaguroHardware | Get-PaguroModalias)
            (Last).Method | Should -Be 'hw.modalias'
            (Last).Params['hardware']['version'].GetValue[int]() | Should -Be 1
            $m | Should -Contain 'pci:v000010DEd000028A0sv00001043sd00001F3Abc03sc00i00'
        }
        It 'New-PaguroDisk sends an absolute path and bytes from 20GB; -WhatIf is the dry run' {
            $d = New-PaguroDisk -Path 'rel.vhd' -Size 20GB -WhatIf
            $d | Should -BeOfType [Paguro.Api.DiskInfo]
            P 'size' | Should -Be '21474836480'
            [IO.Path]::IsPathRooted((P 'path')) | Should -BeTrue
            P 'dry_run' | Should -Be 'True'
            New-PaguroDisk -Path 'C:\x.vhd' -Size 32G | Out-Null
            P 'size' | Should -Be '32G'
        }
        It 'Get-PaguroDisk accepts paths from the pipeline' {
            @('a.vhd', 'b.vhd') | Get-PaguroDisk | Should -HaveCount 2
            $srv.Calls.Count | Should -Be 2
            (Last).Method | Should -Be 'disk.inspect'
        }
    }

    Describe 'configuration' {
        It 'Get-PaguroConfig' {
            (Get-PaguroConfig).Config.Default | Should -Be 'debian'
        }
        It 'Test-PaguroConfig' {
            (Test-PaguroConfig).File.Valid | Should -BeTrue
        }
        It 'Set-PaguroConfig sends only what was given' {
            Set-PaguroConfig -Keyboard de -Tpm $false -Confirm:$false | Out-Null
            (Last).Method | Should -Be 'config.set'
            P 'keyboard' | Should -Be 'de'
            P 'tpm' | Should -Be 'False'
            (Last).Params.ContainsKey('root') | Should -BeFalse
        }
    }

    Describe 'firmware' {
        It 'Get-PaguroFirmwareVariable lists, or gets one by -Name' {
            @(Get-PaguroFirmwareVariable).Count | Should -BeGreaterThan 3
            (Last).Method | Should -Be 'efi.vars.list'
            (Get-PaguroFirmwareVariable PaguroConfigHash).Present | Should -BeTrue
            (Last).Method | Should -Be 'efi.vars.get'
        }
        It 'Set-PaguroFirmwareVariable' {
            Set-PaguroFirmwareVariable PaguroTpmBroken 01 -Confirm:$false | Out-Null
            (Last).Method | Should -Be 'efi.vars.set'
            P 'hex' | Should -Be '01'
        }
        It 'Remove-PaguroFirmwareVariable -WhatIf' {
            Remove-PaguroFirmwareVariable PaguroSetup -WhatIf | Out-Null
            (Last).Method | Should -Be 'efi.vars.delete'
            P 'dry_run' | Should -Be 'True'
        }
        It 'Get-PaguroBootEntry' {
            $e = @(Get-PaguroBootEntry)
            $e[0] | Should -BeOfType [Paguro.Api.FirmwareBootEntry]
            $e[0].Description | Should -Be 'Windows Boot Manager'
            @(Get-PaguroBootEntry -Ours).Count | Should -Be 0
        }
        It 'New-PaguroBootEntry' {
            New-PaguroBootEntry -Confirm:$false | Out-Null
            (Last).Method | Should -Be 'efi.boot-entry.create'
        }
        It 'Remove-PaguroBootEntry takes entries from the pipeline' {
            [pscustomobject]@{ Name = 'Boot0003' } | Remove-PaguroBootEntry -Confirm:$false | Out-Null
            P 'entry' | Should -Be 'Boot0003'
        }
        It 'Set-PaguroBootNext -Clear' {
            Set-PaguroBootNext -Clear -Confirm:$false | Out-Null
            P 'clear' | Should -Be 'True'
        }
    }

    Describe 'ESP and MOK' {
        It 'Install-PaguroEsp' {
            Install-PaguroEsp -Shim s.efi -MokManager m.efi -Loader l.efi -WhatIf | Out-Null
            (Last).Method | Should -Be 'esp.install'
            [IO.Path]::IsPathRooted((P 'mm')) | Should -BeTrue
        }
        It 'Test-PaguroEsp' {
            (Test-PaguroEsp).Files.Count | Should -Be 4
        }
        It 'Repair-PaguroEsp' {
            Repair-PaguroEsp -Confirm:$false | Out-Null
            (Last).Method | Should -Be 'esp.repair'
        }
        It 'Register-PaguroMok sends a chosen password as a secret' {
            Register-PaguroMok -Certificate c.der -Password (Secure 'hunter2') -Confirm:$false | Out-Null
            (Last).Method | Should -Be 'mok.enroll'
            P 'mok_password' | Should -Be 'hunter2'
        }
        It 'Get-PaguroMok' {
            (Get-PaguroMok).Enrolled | Should -BeFalse
        }
    }

    Describe 'the way into Linux' {
        It 'Test-PaguroPreflight' {
            $p = Test-PaguroPreflight
            $p | Should -BeOfType [Paguro.Api.Preflight]
            $p.Checks.Count | Should -BeGreaterThan 5
            (Last).Params.ContainsKey('repair') | Should -BeFalse
            Test-PaguroPreflight -Repair | Out-Null
            P 'repair' | Should -Be 'True'
        }
        It 'Get-PaguroDistribution | Where Size -gt 20GB | Start-PaguroLinux' {
            Get-PaguroDistribution | Where-Object Size -gt 20GB | Start-PaguroLinux -Confirm:$false | Out-Null
            (Last).Method | Should -Be 'restart-linux'
            P 'entry' | Should -Be 'debian'
            P 'yes' | Should -Be 'True'
        }
        It 'Restart-PaguroLinux -NoRestart, -WhatIf' {
            Restart-PaguroLinux -NoRestart -Confirm:$false | Out-Null
            (Last).Params.ContainsKey('yes') | Should -BeFalse
            Restart-PaguroLinux -WhatIf | Out-Null
            P 'dry_run' | Should -Be 'True'
        }
        It 'Request-PaguroSetupTpm answers the passphrase the service asks for' {
            $srv.OnNeedsInput('stage-setup', 'linux_passphrase', 'Linux passphrase', $true, '{"volume":"v","seal":"s","variable":"PaguroSetup"}')
            $r = Request-PaguroSetupTpm -Passphrase (Secure 'correct horse') -Confirm:$false
            $r.Variable | Should -Be 'PaguroSetup'
            # Always needed: sent with the first call.
            $srv.Calls.Count | Should -Be 1
            (Last).Params['linux_passphrase'].GetValue[string]() | Should -Be 'correct horse'
        }
        It 'Restart-PaguroLinux answers a passphrase only when the service asks back for it' {
            $srv.OnNeedsInput('restart-linux', 'linux_passphrase', 'Linux passphrase', $true, '{"checks":[],"secure_boot":true,"staged":{}}')
            Restart-PaguroLinux -NoRestart -Passphrase (Secure 'pw') -Confirm:$false | Out-Null
            $srv.Calls.Count | Should -Be 2
            $srv.Calls[0].Params.ContainsKey('linux_passphrase') | Should -BeFalse
            (Last).Params['linux_passphrase'].GetValue[string]() | Should -Be 'pw'
        }
        It 'Request-PaguroSetupTpm without a passphrase and nobody to ask fails' {
            $srv.OnNeedsInput('stage-setup', 'linux_passphrase', 'Linux passphrase', $true, '{}')
            Request-PaguroSetupTpm -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable e | Out-Null
            $e[0].FullyQualifiedErrorId | Should -BeLike 'paguro.refused*'
        }
        It 'Repair-Paguro -Stage' {
            Repair-Paguro -Stage -Confirm:$false | Out-Null
            P 'stage' | Should -Be 'True'
        }
        It 'Uninstall-Paguro -WhatIf is the summary of what is and is not touched' {
            $u = Uninstall-Paguro -KeepImages -WhatIf
            $u.Steps.Count | Should -BeGreaterThan 3
            P 'dry_run' | Should -Be 'True'
        }
        It 'Uninstall-Paguro needs a choice about the images' {
            { Uninstall-Paguro -Confirm:$false -ErrorAction Stop } | Should -Throw
        }
        It 'Uninstall-Paguro and Install-Paguro run paguro.exe itself, not the service' {
            $env:PAGURO_EXE = $script:FakeExe
            try {
                $srv.ClearCalls()
                $u = Uninstall-Paguro -DeleteImages -Confirm:$false
                $u.Finished | Should -BeTrue
                $i = Install-Paguro -Confirm:$false
                $i.State.Installed | Should -BeTrue
                $srv.Calls.Count | Should -Be 0
                $log = Get-Content $script:FakeLog
                $log[0] | Should -BeLike 'uninstall --yes --delete-images --json --direct --report *'
                $log[1] | Should -BeLike 'install --json --direct --report *'
            } finally { Remove-Item env:PAGURO_EXE }
        }
        It 'Get-PaguroSetup' {
            (Get-PaguroSetup).Installed | Should -BeFalse
            (Last).Method | Should -Be 'setup.status'
        }
        It 'Repair-Paguro -AppOnly' {
            Repair-Paguro -AppOnly -Confirm:$false | Out-Null
            P 'app_only' | Should -Be 'True'
        }
    }

    Describe 'distributions' {
        It 'Get-PaguroDistribution filters by name and kind' {
            @(Get-PaguroDistribution).Count | Should -Be 2
            @(Get-PaguroDistribution -Kind wsl).Name | Should -Be 'Ubuntu'
            @(Get-PaguroDistribution deb*).Name | Should -Be 'debian'
            (Get-PaguroDistribution debian).Size | Should -BeGreaterThan 30GB
        }
        It 'Rename-PaguroDistribution' {
            Rename-PaguroDistribution debian deb -Confirm:$false | Out-Null
            P 'new_name' | Should -Be 'deb'
        }
        It 'Remove-PaguroDistribution -DeleteImage consents for the image' {
            Get-PaguroDistribution debian | Remove-PaguroDistribution -DeleteImage -Confirm:$false | Out-Null
            P 'name' | Should -Be 'debian'
            P 'yes' | Should -Be 'True'
        }
        It 'Resize-PaguroDistribution is a stub and says so' {
            Resize-PaguroDistribution debian 64GB -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable e | Out-Null
            $e[0].Exception.Message | Should -BeLike '*STUB*'
            P 'size' | Should -Be '68719476736'
        }
        It 'Enter-PaguroDistro attaches, runs the shell, detaches' {
            $r = Enter-PaguroDistro debian
            $r.ShellExit | Should -Be 0
            $srv.Calls.Method | Should -Be @('distro.enter', 'distro.leave')
        }
        It 'Dismount-PaguroDistro -Path' {
            Dismount-PaguroDistro -Path 'C:\paguro\debian.vhd' | Out-Null
            (Last).Method | Should -Be 'distro.leave'
        }
        It 'Install-PaguroDistro -Iso shows progress and reports the stub' {
            $fx = Get-Content (Join-Path $fixtures 'install.1.json') -Raw
            $srv.On('install', [Paguro.Testing.FakeServer]::FromFixture($fx))
            $out = Install-PaguroDistro fedora 'C:\paguro\fedora.vhd' -Iso 'C:\iso\fedora.iso' -Confirm:$false -Verbose -ErrorAction SilentlyContinue -ErrorVariable e 4>&1
            ($out | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] }).Message | Should -Contain '[1/9] host: running'
            $e[0].Exception.Message | Should -BeLike '*STUB*'
            P 'source' | Should -Be 'iso'
        }
        It 'Install-PaguroDistro -FromWsl, -Finish' {
            Install-PaguroDistro deb2 'C:\d.vhd' -FromWsl Ubuntu -WhatIf | Out-Null
            P 'wsl_distro' | Should -Be 'Ubuntu'
            Install-PaguroDistro deb2 'C:\d.vhd' -Finish -WhatIf | Out-Null
            P 'finish' | Should -Be 'True'
        }
        It 'Enter-PaguroInstaller runs the shell the service names' {
            $srv.OnData('install', '{"steps":[{"id":"build","state":"awaiting_user"}],"shell":["wsl.exe","--user","root"]}', 'pending', [string[]]@())
            $j = Enter-PaguroInstaller fedora 'C:\f.vhd' -Iso 'C:\f.iso' -Confirm:$false -WarningAction SilentlyContinue
            P 'shell' | Should -Be 'True'
            $j.ShellExit | Should -Be 0
        }
    }

    Describe 'protection' {
        It 'Get-PaguroProtection' {
            $p = Get-PaguroProtection -Klid 00000407
            $p | Should -BeOfType [Paguro.Api.ProtectionOptions]
            # The demo machine's BitLocker is TPM-only, so TPM-only is offered too.
            ($p.Choices | Where-Object Id -eq 'tpm_only').Offered | Should -BeTrue
            ($p.Choices | Where-Object Recommended).Id | Should -Be 'tpm_pin'
            P 'klid' | Should -Be '00000407'
        }
        It 'Set-PaguroProtection sends the PIN as a secret' {
            Set-PaguroProtection tpm_pin -Keyboard de -Pin (Secure '4711') -Confirm:$false | Out-Null
            (Last).Method | Should -Be 'protection.set'
            P 'pin' | Should -Be '4711'
            P 'pin_bypass' | Should -Be 'True'
            Set-PaguroProtection passphrase -Pin (Secure 'x') -NoPinBypass -Confirm:$false | Out-Null
            P 'pin_bypass' | Should -Be 'False'
        }
        It 'Test-PaguroSecret returns the refusal as its answer' {
            $srv.OnError('protection.check', 'refused', 3, '1 character(s) cannot be typed at boot',
                '{"ok":false,"keyboard":"fr","length":2,"refused":[{"char":"ê","position":1,"reason":"needs a dead key"}]}')
            $r = Test-PaguroSecret (Secure 'aê') -Keyboard fr
            P 'pin' | Should -Be 'aê'
            $r.Ok | Should -BeFalse
            $r.Refused[0].Char | Should -Be 'ê'
        }
    }
}

# The same cmdlets against the real service logic: `paguro service console
# --mock` (the demo machine) on the pipe named by $env:PAGURO_SERVICE_PIPE.
Describe 'PaguroTools against paguro service console --mock' -Skip:(-not $env:PAGURO_SERVICE_PIPE) {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $module = if ($env:PAGURO_MODULE) { $env:PAGURO_MODULE } else { Join-Path $root 'bin/module/PaguroTools.psd1' }
        Import-Module $module -Force
        $script:pipe = $env:PAGURO_SERVICE_PIPE
    }
    It 'reads through the service' {
        (Get-PaguroService -PipeName $pipe).Service | Should -BeTrue
        $d = @(Get-PaguroDistribution -PipeName $pipe)
        ($d | Where-Object Kind -eq image).Name | Should -Be 'debian'
        (Get-PaguroDistribution -PipeName $pipe | Where-Object Size -gt 20GB).Name | Should -Be 'debian'
        @(Get-PaguroCheck -PipeName $pipe).Count | Should -Be 8
    }
    It 'plans with -WhatIf and refuses what the layout cannot type' {
        (Uninstall-Paguro -PipeName $pipe -KeepImages -WhatIf).Steps.Count | Should -BeGreaterThan 3
        $r = Test-PaguroSecret -PipeName $pipe (ConvertTo-SecureString 'aê' -AsPlainText -Force) -Keyboard fr
        $r.Ok | Should -BeFalse
        Set-PaguroProtection -PipeName $pipe passphrase -Keyboard fr -Pin (ConvertTo-SecureString 'azerty' -AsPlainText -Force) -WhatIf |
            Select-Object -ExpandProperty Choice | Should -Be 'passphrase'
    }
    It 'streams install progress and reports the stub' {
        $out = Install-PaguroDistro -PipeName $pipe fedora 'C:\paguro\fedora.vhd' -Iso 'C:\iso\fedora.iso' -Confirm:$false -Verbose -ErrorAction SilentlyContinue -ErrorVariable e 4>&1
        ($out | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] }).Message | Should -Contain '[1/9] host: running'
        $e[0].Exception.Message | Should -BeLike '*STUB*'
    }
}
