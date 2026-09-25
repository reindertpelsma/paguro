# First-logon setup for the local Windows test VM (test/winvm). Runs once,
# elevated, from autounattend.xml's FirstLogonCommands with the config ISO's
# drive as $args[0]. Progress goes to C:\winvm\setup.log and to COM1 (the host
# tees it to $WINVM_DIR/logs/). The last step powers the VM off; `winvm build`
# waits for that.
$ErrorActionPreference = 'Continue'
$cfg = $args[0]
New-Item -ItemType Directory -Force C:\winvm | Out-Null
$com = $null
try { $com = New-Object System.IO.Ports.SerialPort COM1, 115200; $com.Open() } catch { $com = $null }
function Log($m) {
    $l = "[winvm-setup $(Get-Date -Format HH:mm:ss)] $m"
    Add-Content C:\winvm\setup.log $l
    if ($com) { try { $com.WriteLine($l) } catch {} }
}
Log "start, config media $cfg"

# --- power / UI: never sleep, no lock screen, no hibernation file
powercfg /h off
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' /v NoLockScreen /t REG_DWORD /d 1 /f | Out-Null
reg add 'HKCU\Control Panel\Desktop' /v ScreenSaveActive /t REG_SZ /d 0 /f | Out-Null
reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f | Out-Null
# UAC stays on (WinUI/packaged apps need it) but admins elevate without a prompt
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f | Out-Null
# password never expires for the test account
net accounts /maxpwage:unlimited | Out-Null
# Defender: keep it, but do not scan the build/test trees
try { Add-MpPreference -ExclusionPath 'C:\winvm', 'C:\Users\paguro' -ErrorAction Stop; Log 'defender exclusions set' } catch { Log "defender exclusions: $_" }
Log 'power/ui done'

# --- OpenSSH Server (Win32-OpenSSH MSI from the config ISO; no Windows Update needed)
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$cfg\payload\OpenSSH-Win64.msi`" /qn /norestart"
Log "openssh msi exit $($p.ExitCode)"
$keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
New-Item -ItemType Directory -Force C:\ProgramData\ssh | Out-Null
Copy-Item "$cfg\authorized_keys" $keys -Force
icacls $keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
if (-not (Get-NetFirewallRule -Name 'winvm-sshd' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'winvm-sshd' -DisplayName 'OpenSSH Server (winvm)' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
}
Log "sshd $((Get-Service sshd).Status)"

# --- .NET 8 SDK
$p = Start-Process "$cfg\payload\dotnet-sdk-8.0.425-win-x64.exe" -Wait -PassThru -ArgumentList '/install /quiet /norestart'
Log ".NET SDK exit $($p.ExitCode)"
[Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT', '1', 'Machine')
[Environment]::SetEnvironmentVariable('DOTNET_NOLOGO', '1', 'Machine')

# --- Windows App SDK runtime (WinUI 3)
$p = Start-Process "$cfg\payload\windowsappruntimeinstall-x64.exe" -Wait -PassThru -ArgumentList '--quiet'
Log "Windows App SDK runtime exit $($p.ExitCode)"

# --- test signing. Refused while Secure Boot is on; `winvm build` sets it
# again in its second (Secure Boot off) boot. Logged either way.
$o = bcdedit /set testsigning on 2>&1
Log "bcdedit testsigning: $o"

# --- shrink what the base image carries, then release freed blocks to qcow2
Remove-Item -Recurse -Force "$env:TEMP\*" -ErrorAction SilentlyContinue
try { Optimize-Volume -DriveLetter C -ReTrim -ErrorAction Stop; Log 'retrim done' } catch { Log "retrim: $_" }

Set-Content C:\winvm\setup-done (Get-Date -Format o)
Log 'done, powering off'
if ($com) { $com.Close() }
shutdown /s /t 5 /f
