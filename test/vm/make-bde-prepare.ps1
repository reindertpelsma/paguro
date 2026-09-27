# make-bde-image.sh, first boot: everything BitLocker should seal over.
param([int]$SizeGiB = 21)
$ErrorActionPreference = 'Stop'
Set-Location C:\bde

'shrink C: (keeps the copy, and view B, small)'
$c = Get-Partition -DriveLetter C
$want = [int64]$SizeGiB * 1GB
if ($c.Size -gt $want) { Resize-Partition -DriveLetter C -Size $want }
"C: $((Get-Partition -DriveLetter C).Size / 1GB) GiB"

'virtio drivers: NetKVM (network), vioserial (the agent port), viosock (vsock)'
foreach ($d in 'NetKVM\w11\amd64\netkvm.inf', 'vioserial\w11\amd64\vioser.inf', 'viosock\w11\amd64\viosock.inf') {
    if (Test-Path $d) { pnputil /add-driver $d /install | Out-Null; "  $d" } else { "  missing $d" }
}

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

if (Test-Path paguro\paguro.exe) {
    'the paguro service, and paguro.ini listing the image (the VM arms through the real service)'
    $dir = 'C:\Program Files\paguro'
    New-Item -ItemType Directory -Force $dir | Out-Null
    Copy-Item paguro\paguro.exe "$dir\paguro.exe" -Force
    # An entry needs a UEFI image; the loader is never booted from this image.
    if (-not (Test-Path C:\paguro\linux.efi)) { Set-Content -Path C:\paguro\linux.efi -Value 'MZ' -NoNewline }
    & "$dir\paguro.exe" --direct config set --entry linux --root $img --efi-file C:\paguro\linux.efi
    if ($LASTEXITCODE) { throw "paguro config set: $LASTEXITCODE" }
    & "$dir\paguro.exe" --direct service install
    if ($LASTEXITCODE) { throw "paguro service install: $LASTEXITCODE" }
    (sc.exe qc paguro | Select-String 'START_TYPE|BINARY') -join ' '
}
