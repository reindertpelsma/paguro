# make-bde-image.sh, second boot: BitLocker on C:, full encryption, to 100%.
$ErrorActionPreference = 'Stop'
if ((manage-bde -status C:) -match 'Fully Decrypted') {
    manage-bde -on C: -RecoveryPassword -SkipHardwareTest | Out-Null
}
do {
    Start-Sleep 20
    $p = (manage-bde -status C: | Select-String 'Percentage Encrypted') -replace '.*:\s*', ''
    "encrypted: $p"
} until ($p -match '^100(\.0)?%')
manage-bde -status C: | Select-String 'Protection Status|Encryption Method|Conversion Status'
$rp = (Get-BitLockerVolume -MountPoint C:).KeyProtector |
    Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -First 1
'BDE_RECOVERY ' + $rp.RecoveryPassword
'BDE_GUID ' + ((Get-Partition -DriveLetter C).Guid -replace '[{}]', '')
