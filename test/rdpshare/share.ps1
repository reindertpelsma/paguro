# Prototype (DESIGN.md §5c, "paguro's own RDP server"): Microsoft's Desktop
# Sharing API (RDPSRAPI, rdpencom.dll) as the server, in the user's session.
# Writes the invitation's connection string; grants input control to the
# attendee without any prompt; optionally shares only the windows of one app.
#   share.ps1 -Out C:\rdpshare\inv.txt -Password <token> [-App notepad] [-Port 3391]
param([string]$Out = 'C:\rdpshare\inv.txt', [Parameter(Mandatory)][string]$Password,
      [string]$App = '', [int]$Port = 3391)
$ErrorActionPreference = 'Stop'
$log = [IO.Path]::ChangeExtension($Out, '.log')
function Log($m) { "$(Get-Date -Format o) $m" | Add-Content $log }
try {
    $s = New-Object -ComObject RDPSRAPI.RDPSession
    Log "RDPSession created"
    $s.Properties.Item('PortId') = $Port
    # CTRL_LEVEL_INTERACTIVE = 3: whoever holds the invitation drives.
    # Event actions run in their own scope: the log path travels as MessageData.
    Register-ObjectEvent -InputObject $s -EventName OnAttendeeConnected -MessageData $log -Action {
        $a = $Event.SourceArgs[0]; $a.ControlLevel = 3
        "$(Get-Date -Format o) attendee connected: $($a.RemoteName)" | Add-Content $Event.MessageData
    } | Out-Null
    Register-ObjectEvent -InputObject $s -EventName OnControlLevelChangeRequest -MessageData $log -Action {
        $a = $Event.SourceArgs[0]; $a.ControlLevel = 3
        "$(Get-Date -Format o) control requested: granted" | Add-Content $Event.MessageData
    } | Out-Null
    if ($App) {
        $f = $s.ApplicationFilter
        $f.Enabled = $true
        foreach ($ap in $f.Applications) {
            $ap.Shared = ($ap.Name -match $App)
            Log "app $($ap.Name): shared=$($ap.Shared)"
        }
    }
    $s.Open()
    $inv = $s.Invitations.CreateInvitation('paguro', 'paguro', $Password, 1)
    Set-Content -Path $Out -Value $inv.ConnectionString -Encoding ascii
    Log "open on port $Port; invitation written"
    while ($true) { Start-Sleep -Seconds 1 }
} catch {
    Log "ERROR $($_.Exception.Message)"
    throw
}
