# Runs in the Windows VM booted through the paguro disk stack
# (test/vm/split-e2e.sh copies it in). Prints facts, one per line, as
# "CHECK <name>: <value>"; the host decides what passes.
$ErrorActionPreference = 'Continue'
function Check($n, $v) { "CHECK ${n}: $v" }

$bl = Get-BitLockerVolume -MountPoint C:
Check 'bitlocker.protection' $bl.ProtectionStatus
Check 'bitlocker.status' $bl.VolumeStatus
Check 'bitlocker.protectors' (($bl.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)=$($_.KeyProtectorId)" }) -join ',')
Check 'bcd.testsigning' ((bcdedit /enum '{current}' | Select-String testsigning) -replace '\s+', ' ')
Check 'minifilter' ((fltmc filters | Select-String PaguroFlt) -replace '\s+', ' ')
Check 'minifilter.service' ((sc.exe query PaguroFlt | Select-String STATE) -replace '\s+', ' ')

# Everything else is: a file written now reaches the disk.
$stamp = Get-Date -Format o
Set-Content -Path C:\paguro\written-in-vm.txt -Value "paguro-vm $stamp"
Check 'write.file' (Get-Content C:\paguro\written-in-vm.txt)

# Identity passthrough (DESIGN §4.5).
$p = Get-CimInstance Win32_ComputerSystemProduct
Check 'smbios.uuid' $p.UUID
Check 'smbios.vendor' "$($p.Vendor) / $($p.Name)"
Check 'smbios.oemstrings' ((Get-CimInstance Win32_ComputerSystem).OEMStringArray -join ',')
Check 'cpu' (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
Check 'hypervisor.present' (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
Get-NetAdapter | ForEach-Object { Check "nic.$($_.Name)" "$($_.InterfaceDescription) $($_.MacAddress) $($_.Status)" }
Get-Disk | ForEach-Object { Check "disk.$($_.Number)" "serial=$($_.SerialNumber) size=$($_.Size) guid=$($_.Guid)" }
Get-Partition -DiskNumber 0 | ForEach-Object { Check "partition.$($_.PartitionNumber)" "$($_.DriveLetter) $($_.Type) offset=$($_.Offset) size=$($_.Size) guid=$($_.Guid)" }
Check 'winre' ((reagentc /info | Select-String 'Windows RE status') -replace '\s+', ' ')
Check 'tpm' ((Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm Win32_Tpm -ErrorAction SilentlyContinue | Measure-Object).Count)
Check 'secureboot' $(try { Confirm-SecureBootUEFI } catch { 'unsupported' })
Check 'activation' ((Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" | Select-Object -First 1).LicenseStatus)
Check 'disk.errors' ((Get-WinEvent -FilterHashtable @{LogName='System'; Id=7,153,55,98,140} -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.ProviderName)/$($_.Id)" }) -join ',')
