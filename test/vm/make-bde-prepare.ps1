# make-bde-image.sh, first boot: everything BitLocker should seal over.
param([int]$SizeGiB = 21)
$ErrorActionPreference = 'Stop'
Set-Location C:\bde

'shrink C: (keeps the copy, and view B, small)'
$c = Get-Partition -DriveLetter C
$want = [int64]$SizeGiB * 1GB
if ($c.Size -gt $want) { Resize-Partition -DriveLetter C -Size $want }
"C: $((Get-Partition -DriveLetter C).Size / 1GB) GiB"

'NetKVM (the VM''s network adapters)'
pnputil /add-driver NetKVM\w11\amd64\netkvm.inf /install | Out-Null

'the test certificate and the minifilter (boot-start)'
# certutil, not Import-Certificate: over SSH (an S4U logon) the latter fails.
certutil -f -addstore Root minifilter\paguro-test.cer | Out-Null
certutil -f -addstore TrustedPublisher minifilter\paguro-test.cer | Out-Null
pnputil /add-driver minifilter\pkg\Release\paguro_flt.inf /install | Out-Null
if ($LASTEXITCODE) {
    rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 132 "C:\bde\minifilter\pkg\Release\paguro_flt.inf"
    Start-Sleep 3
}
(sc.exe qc PaguroFlt | Select-String 'START_TYPE') -join ''

'C:\paguro\linux.img: 64 MiB, allocated, valid data to the end (not sparse)'
New-Item -ItemType Directory -Force C:\paguro | Out-Null
$img = 'C:\paguro\linux.img'
if (-not (Test-Path $img)) {
    fsutil file createnew $img 67108864 | Out-Null
    fsutil file setvaliddata $img 67108864 | Out-Null
}
fsutil file queryextents $img

'testsigning off natively (the VM''s synthetic ESP turns it on for the session)'
bcdedit /set testsigning off | Out-Null
bcdedit /enum '{current}' | Select-String testsigning
