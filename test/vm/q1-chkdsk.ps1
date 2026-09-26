# After a boot-time `chkdsk C: /r` in the session (split-e2e.sh,
# PAGURO_Q1_CHKDSK=1): autochk's own report, and the image as NTFS now maps it.
param([string]$Image = 'C:\paguro\linux.img')
# autochk's report is an Application-log event (source Wininit, 1001).
$e = Get-WinEvent -LogName Application -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -in 'Wininit', 'Chkdsk' -and $_.Id -eq 1001 } | Select-Object -First 1
"CHECK ck.when: $(if ($e) { $e.TimeCreated.ToString('o') } else { 'no Wininit event' })"
if ($e) { $e.Message -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { "LOG $_" } }
"CHECK ck.extents: $((fsutil file queryextents $Image) -join ' ')"
"CHECK ck.length: $((Get-Item $Image -ErrorAction SilentlyContinue).Length)"
"CHECK ck.dirty: $((fsutil dirty query C:) -join ' ')"
# Newer builds also keep the full log beside the volume's metadata.
Get-ChildItem 'C:\System Volume Information\Chkdsk' -ErrorAction SilentlyContinue |
    ForEach-Object { "CHECK ck.logfile: $($_.Name) $($_.Length)" }
# It is readable only with backup semantics: copy it out and print it.
$tmp = Join-Path $env:TEMP 'ck'
robocopy 'C:\System Volume Information\Chkdsk' $tmp *.log /B /NFL /NDL /NJH /NJS | Out-Null
Get-ChildItem $tmp -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1 |
    ForEach-Object { Get-Content $_.FullName | Where-Object { $_.Trim() } | ForEach-Object { "LOG $_" } }
