# Stands in for the minifilter's report (DESIGN.md §4.4): one agent frame
# (INTERFACES.md §11.3: u32 length, JSON) on the virtio-serial port
# org.paguro.agent.0, sent once the driver is seen attached. The launcher's
# gate stops the VM when no such report arrives in time.
$ErrorActionPreference = 'Stop'
if (-not ((fltmc filters) -match 'PaguroFlt')) { 'agent: PaguroFlt not attached, no report'; exit 1 }
$port = '\\.\Global\org.paguro.agent.0'
$f = [IO.File]::Open($port, 'Open', 'ReadWrite')
$body = [Text.Encoding]::UTF8.GetBytes('{"type":"driver","state":"ok","driver":"PaguroFlt"}')
$f.Write([BitConverter]::GetBytes([uint32]$body.Length), 0, 4)
$f.Write($body, 0, $body.Length)
$f.Flush()
$f.Close()
'agent: driver reported'
