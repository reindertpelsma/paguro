# DESIGN.md §11 Q1-Q3 from inside the guest: what NTFS does when writes
# into the image, and a relocation of it, meet view B's refusal. Nothing
# here needs to succeed; every step reports what Windows answered, and the
# before/after extents, dirty bit, bad-cluster count and event log are the
# evidence. On-disk integrity is checked from Linux (split-e2e.sh).
#
# Without the paguro service no PROTECT reaches the minifilter, so the
# opens below are not refused: this is the raw path the minifilter normally
# closes (§4.4), which is exactly what Q1-Q3 are about.
param([string]$Image = 'C:\paguro\linux.img', [int]$LazyWait = 90, [int]$DefragBudget = 600)
$ErrorActionPreference = 'Continue'
$t0 = Get-Date

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Q1 {
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_READ_ATTRIBUTES = 0x80;
    const uint SHARE_ALL = 7, OPEN_EXISTING = 3;
    const uint FLAG_NO_BUFFERING = 0x20000000, FLAG_WRITE_THROUGH = 0x80000000;
    const uint FSCTL_GET_VOLUME_BITMAP = 0x9006F, FSCTL_MOVE_FILE = 0x90074;
    const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x90073;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa,
        uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inBuf, int inLen,
        byte[] outBuf, int outLen, out int returned, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(SafeFileHandle h, IntPtr buf, int len, out int written, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushFileBuffers(SafeFileHandle h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(SafeFileHandle h, long dist, out long newPos, uint method);
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr size, uint type, uint prot);

    static string Err(int e) { return "win32 " + e + " (" + new Win32Exception(e).Message + ")"; }

    static SafeFileHandle Open(string p, uint access, uint flags) {
        SafeFileHandle h = CreateFileW(p, access, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
        if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        return h;
    }

    // One write of `len` bytes (a page-aligned buffer) at `off`, then an
    // optional FlushFileBuffers; reports each call's own result.
    public static string Write(string p, long off, int len, string mode, bool flush) {
        uint flags = mode == "unbuffered" ? FLAG_NO_BUFFERING | FLAG_WRITE_THROUGH
                   : mode == "writethrough" ? FLAG_WRITE_THROUGH : 0;
        SafeFileHandle h;
        try { h = Open(p, GENERIC_READ | GENERIC_WRITE, flags); }
        catch (Win32Exception e) { return "open: " + Err(e.NativeErrorCode); }
        using (h) {
            IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)(uint)len, 0x3000, 4);
            byte[] pat = new byte[len];
            for (int i = 0; i < len; i++) pat[i] = 0x51;   // 'Q'
            Marshal.Copy(pat, 0, buf, len);
            long np;
            SetFilePointerEx(h, off, out np, 0);
            int n;
            string r = WriteFile(h, buf, len, out n, IntPtr.Zero)
                ? "write ok (" + n + ")" : "write: " + Err(Marshal.GetLastWin32Error());
            if (flush)
                r += FlushFileBuffers(h) ? "; flush ok" : "; flush: " + Err(Marshal.GetLastWin32Error());
            return r;
        }
    }

    // The file's extents as "vcn:lcn+len" pairs (FSCTL_GET_RETRIEVAL_POINTERS).
    public static string Extents(string p) {
        SafeFileHandle h;
        try { h = Open(p, FILE_READ_ATTRIBUTES, 0); }
        catch (Win32Exception e) { return "open: " + Err(e.NativeErrorCode); }
        using (h) {
            byte[] inb = new byte[8], outb = new byte[1 << 16];
            int n;
            if (!DeviceIoControl(h, FSCTL_GET_RETRIEVAL_POINTERS, inb, 8, outb, outb.Length, out n, IntPtr.Zero))
                return "error: " + Err(Marshal.GetLastWin32Error());
            int count = BitConverter.ToInt32(outb, 0);
            long vcn = BitConverter.ToInt64(outb, 8);
            string s = "";
            for (int i = 0; i < count; i++) {
                long next = BitConverter.ToInt64(outb, 16 + i * 16);
                long lcn = BitConverter.ToInt64(outb, 24 + i * 16);
                s += (s.Length > 0 ? " " : "") + vcn + ":" + lcn + "+" + (next - vcn);
                vcn = next;
            }
            return s;
        }
    }

    // A free run of `n` clusters on the volume, searching from `from`.
    static long FreeRun(SafeFileHandle vol, long from, int n) {
        byte[] inb = BitConverter.GetBytes(from), outb = new byte[1 << 20];
        int got;
        DeviceIoControl(vol, FSCTL_GET_VOLUME_BITMAP, inb, 8, outb, outb.Length, out got, IntPtr.Zero);
        long start = BitConverter.ToInt64(outb, 0);
        long bits = Math.Min(BitConverter.ToInt64(outb, 8), (long)(got - 16) * 8);
        int run = 0;
        for (long i = 0; i < bits; i++) {
            bool used = (outb[16 + i / 8] & (1 << (int)(i % 8))) != 0;
            run = used ? 0 : run + 1;
            if (run == n) return start + i - n + 1;
        }
        return -1;
    }

    // FSCTL_MOVE_FILE of the file's first `n` clusters to free space: what
    // defrag and the optimiser issue, and the relocation Q1-Q3 are about.
    public static string Move(string p, int n) {
        SafeFileHandle vol, f;
        try { vol = Open(@"\\.\" + Path.GetPathRoot(p).TrimEnd('\\'), GENERIC_READ, 0); }
        catch (Win32Exception e) { return "volume open: " + Err(e.NativeErrorCode); }
        using (vol) {
            try { f = Open(p, FILE_READ_ATTRIBUTES, 0); }
            catch (Win32Exception e) { return "open: " + Err(e.NativeErrorCode); }
            using (f) {
                long target = FreeRun(vol, 1L << 16, n);
                if (target < 0) return "no free run of " + n;
                // MOVE_FILE_DATA: HANDLE, LARGE_INTEGER StartingVcn, LARGE_INTEGER StartingLcn, DWORD ClusterCount
                byte[] inb = new byte[32];
                BitConverter.GetBytes((long)f.DangerousGetHandle()).CopyTo(inb, 0);
                BitConverter.GetBytes(0L).CopyTo(inb, 8);
                BitConverter.GetBytes(target).CopyTo(inb, 16);
                BitConverter.GetBytes(n).CopyTo(inb, 24);
                int got;
                return DeviceIoControl(vol, FSCTL_MOVE_FILE, inb, inb.Length, null, 0, out got, IntPtr.Zero)
                    ? "moved to lcn " + target : "to lcn " + target + ": " + Err(Marshal.GetLastWin32Error());
            }
        }
    }
}
'@

function Step($name, [scriptblock]$b) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { $r = & $b } catch { $r = 'exception: ' + $_.Exception.GetBaseException().Message }
    "CHECK q1.${name}: $r ($([math]::Round($sw.Elapsed.TotalSeconds, 1)) s)"
}
function Bad() {
    # chkdsk /scan is online and read-only; its summary carries the bad-sector count.
    $o = chkdsk C: /scan 2>&1 | Out-String
    $m = [regex]::Match($o, '([\d,.]+ [KMG]?B) in bad sectors')
    $v = [regex]::Match($o, '(found no problems|found problems|errors found|Windows has scanned[^\r\n]*)')
    "$(if ($m.Success) { $m.Groups[1].Value } else { '?' }) in bad sectors; $($v.Value)"
}

$extBefore = [Q1]::Extents($Image)
"CHECK q1.extents-before: $extBefore"
Step 'dirty-before' { (fsutil dirty query C:) -join ' ' }
Step 'chkdsk-before' { Bad }

# Q1: writes into the image, in each form NTFS can issue them.
Step 'write-buffered-flush' { [Q1]::Write($Image, 1MB, 64KB, 'buffered', $true) }
Step 'write-writethrough' { [Q1]::Write($Image, 2MB, 64KB, 'writethrough', $false) }
Step 'write-unbuffered' { [Q1]::Write($Image, 3MB, 64KB, 'unbuffered', $false) }
# Left to the lazy writer: no flush, the handle closed, then wait for it.
Step 'write-buffered-lazy' { [Q1]::Write($Image, 4MB, 64KB, 'buffered', $false) }
Start-Sleep -Seconds $LazyWait

# Q2: a relocation, with whatever the writes above left in the cache.
Step 'move-first-16' { [Q1]::Move($Image, 16) }
Step 'move-first-1' { [Q1]::Move($Image, 1) }

$extAfter = [Q1]::Extents($Image)
"CHECK q1.extents-after: $extAfter"
"CHECK q1.extents-unchanged: $(if ($extAfter -eq $extBefore) { 'yes' } else { 'NO' })"
Step 'dirty-after' { (fsutil dirty query C:) -join ' ' }
Step 'chkdsk-after' { Bad }

# What NTFS and the disk stack logged meanwhile.
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $t0 } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Ntfs|disk|volmgr|storahci|stornvme|partmgr|Defrag' }
"CHECK q1.events: $(@($ev).Count)"
$ev | Group-Object ProviderName, Id | ForEach-Object {
    $e = $_.Group[0]
    $msg = ($e.Message -split "`n")[0].Trim()
    "EVENT $($e.ProviderName) $($e.Id) x$($_.Count): $msg"
}

# The optimiser on the whole volume (what the scheduled task runs), last and
# time-boxed: every file whose clusters it cannot read costs it a round of
# retried I/O errors, and on its own it can run for longer than the session.
$job = Start-Job { defrag C: /D /U 2>&1 | Select-Object -Last 3 }
if (Wait-Job $job -Timeout $DefragBudget) {
    "CHECK q1.defrag: $((Receive-Job $job) -join ' | ')"
} else {
    Stop-Job $job
    Get-Process defrag -ErrorAction SilentlyContinue | Stop-Process -Force
    "CHECK q1.defrag: still running after $DefragBudget s, stopped"
}
$extDefrag = [Q1]::Extents($Image)
"CHECK q1.extents-after-defrag: $extDefrag"
"CHECK q1.extents-unchanged-after-defrag: $(if ($extDefrag -eq $extBefore) { 'yes' } else { 'NO' })"
Step 'dirty-after-defrag' { (fsutil dirty query C:) -join ' ' }
