# Runs on the VM (winvm smoke.sh copies it with the `paguro-minifilter` CI
# artifact to C:\winvm\mf). Same sequence as the `driver` job of
# .github/workflows/windows.yml: install the test-signed Release package, load
# it INERT and run `pgflt_test inert`, stop it; then load the Debug build
# ACTIVE (ForceVmMode=1) and run `pgflt_test active`. Exit code = failures.
param([string]$Dir = 'C:\winvm\mf')
$ErrorActionPreference = 'Continue'
Set-Location $Dir
$fail = 0
function Step($m) { "=== $m" }

Step 'trust the CI test certificate (taken from the driver signature)'
$sig = Get-AuthenticodeSignature pkg\Release\paguro_flt.sys
"signature: $($sig.Status) by $($sig.SignerCertificate.Subject)"
Export-Certificate -Cert $sig.SignerCertificate -FilePath paguro-test.cer | Out-Null
# certutil, not Import-Certificate: over SSH (an S4U logon) the latter fails
# with E_ACCESSDENIED on LocalMachine\Root
certutil -f -addstore Root paguro-test.cer | Select-String 'completed|already'
certutil -f -addstore TrustedPublisher paguro-test.cer | Select-String 'completed|already'

bcdedit /enum | Select-String testsigning

Step 'install Release, load INERT (no paguro-vm/1 marker)'
pnputil /add-driver pkg\Release\paguro_flt.inf /install
if ($LASTEXITCODE) {
    "pnputil: $LASTEXITCODE; InstallHinfSection instead"
    rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 132 "$Dir\pkg\Release\paguro_flt.inf"
    Start-Sleep 3
}
sc.exe qc PaguroFlt
sc.exe start PaguroFlt
if ($LASTEXITCODE) { "FAIL sc start: $LASTEXITCODE"; $fail++ }
fltmc filters
if ((fltmc filters) -match 'PaguroFlt') { 'FAIL inert driver registered a filter'; $fail++ }
test\pgflt_test.exe inert
if ($LASTEXITCODE) { "FAIL pgflt_test inert: $LASTEXITCODE"; $fail++ }
sc.exe stop PaguroFlt | Out-Null
Start-Sleep 2
if (-not ((sc.exe query PaguroFlt | Out-String) -match 'STOPPED')) { 'FAIL inert driver did not stop'; $fail++ }

Step 'load Debug ACTIVE (Parameters\ForceVmMode=1), every deny path'
$svc = 'HKLM:\SYSTEM\CurrentControlSet\Services\PaguroFlt'
New-Item "$svc\Parameters" -Force | Out-Null
New-ItemProperty "$svc\Parameters" -Name ForceVmMode -PropertyType DWord -Value 1 -Force | Out-Null
$sys = (Resolve-Path pkg\Debug\paguro_flt.sys).Path
Set-ItemProperty $svc -Name ImagePath -Value "\??\$sys"
fltmc load PaguroFlt
if ($LASTEXITCODE) { "FAIL fltmc load: $LASTEXITCODE"; $fail++ }
fltmc filters
$t = Join-Path $env:SystemDrive 'pgflt-test'
New-Item -ItemType Directory -Force $t | Out-Null
test\pgflt_test.exe active $t
if ($LASTEXITCODE) { "FAIL pgflt_test active: $LASTEXITCODE failure(s)"; $fail++ }
fltmc filters

"=== failures: $fail"
exit $fail
