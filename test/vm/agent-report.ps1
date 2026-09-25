# Stands in for the minifilter's report (DESIGN.md §4.4): one agent frame
# (INTERFACES.md §11.3: u32 length, JSON) on the virtio-serial port
# org.paguro.agent.0, sent once the driver is seen attached. The launcher's
# gate stops the VM when no such report arrives in time.
$ErrorActionPreference = 'Stop'
if (-not ((fltmc filters) -match 'PaguroFlt')) { 'agent: PaguroFlt not attached, no report'; exit 1 }
# A device, not a file: FileStream needs a handle from CreateFile.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class PgPort {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
}
'@
$GENERIC_READ_WRITE = [uint32]'0xC0000000'
$OPEN_EXISTING = 3
$h = [PgPort]::CreateFile('\\.\Global\org.paguro.agent.0', $GENERIC_READ_WRITE, 0, [IntPtr]::Zero,
    $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($h.IsInvalid) { throw "agent: CreateFile: error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
$f = New-Object IO.FileStream($h, [IO.FileAccess]::ReadWrite)
$body = [Text.Encoding]::UTF8.GetBytes('{"type":"driver","state":"ok","driver":"PaguroFlt"}')
$f.Write([BitConverter]::GetBytes([uint32]$body.Length), 0, 4)
$f.Write($body, 0, $body.Length)
$f.Flush()
$f.Close()
'agent: driver reported'
