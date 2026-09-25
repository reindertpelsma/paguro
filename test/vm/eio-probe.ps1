# View B from inside the guest (DESIGN.md §4.3): the Linux image's clusters
# return EIO. One 4 KiB read at the start of the file, timed, then the same
# of an ordinary file. Without the paguro service no PROTECT reaches the
# minifilter, so nothing refuses the open: this is the raw error path.
param([string]$Image = 'C:\paguro\linux.img')
function Probe($path) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $f = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $buf = New-Object byte[] 4096
        $n = $f.Read($buf, 0, 4096)
        $f.Close()
        $r = "read $n bytes: " + [Text.Encoding]::ASCII.GetString($buf, 0, 28)
    } catch {
        $r = 'error: ' + $_.Exception.GetBaseException().Message
    }
    "CHECK eio.$([IO.Path]::GetFileName($path)): $r ($([int]$sw.Elapsed.TotalSeconds) s)"
}
Probe 'C:\Windows\System32\drivers\etc\hosts'
Probe $Image
