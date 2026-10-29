# End-to-end smoke test: start server + 2 GUI clients, exchange E2EE messages,
# then verify delivery by reading each client's own per-peer chat log.
# ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class W32 {
    public delegate bool EnumProc(IntPtr h, IntPtr l);

    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int idx);

    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr SendStr(IntPtr h, uint msg, IntPtr w, string l);

    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr Send(IntPtr h, uint msg, IntPtr w, IntPtr l);

    public static List<IntPtr> Edits(IntPtr parent) {
        var res = new List<IntPtr>();
        EnumChildWindows(parent, (h, l) => {
            var cn = new StringBuilder(64);
            GetClassName(h, cn, 64);
            if (cn.ToString() == "Edit") res.Add(h);
            return true;
        }, IntPtr.Zero);
        return res;
    }

    public static string Text(IntPtr h) {
        int n = GetWindowTextLength(h);
        if (n <= 0) return "";
        var sb = new StringBuilder(n + 2);
        GetWindowText(h, sb, n + 2);
        return sb.ToString();
    }
}
"@

$ROOT = "D:\ECDHE-Secured Chat System\build\Debug"
$CHATDIR = Join-Path $env:APPDATA "ECDHE_Chat\chats"

# 1. clean
Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name Server_App   -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
Remove-Item $CHATDIR -Recurse -Force -ErrorAction SilentlyContinue

# 2. start server
$server = Start-Process -FilePath "$ROOT\Server_App.exe" -RedirectStandardOutput "$env:TEMP\srv.log" -PassThru
Start-Sleep -Milliseconds 800

# 3. start two clients
$c1 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -PassThru
Start-Sleep -Milliseconds 700
$c2 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -PassThru
Start-Sleep -Seconds 3

# 4. locate windows / controls (client ID from title, controls from style bits)
$windows = @()
foreach ($p in (Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue)) {
    $p.Refresh()
    if ($p.MainWindowHandle -ne 0) { $windows += $p.MainWindowHandle }
}
Write-Host "client windows: $($windows.Count)"

$info = @{}
foreach ($w in $windows) {
    $title = [W32]::Text($w)
    if ($title -notmatch '([0-9]+)\s*$') { Write-Host "  skip window (no id): $title"; continue }
    $id = [int]$Matches[1]

    $chat = $null; $target = $null; $input = $null
    foreach ($e in [W32]::Edits($w)) {
        $style = [W32]::GetWindowLong($e, -16)
        if ($style -band 0x800) { $chat = $e }            # ES_READONLY    -> chat log
        elseif ($style -band 0x2000) { $target = $e }     # ES_NUMBER      -> target id
        elseif ($style -band 0x80) { $input = $e }        # ES_AUTOHSCROLL -> input
    }
    Write-Host "  window -> client ID $id (chat=$chat target=$target input=$input)"
    $info[$id] = @{ Wnd = $w; Chat = $chat; Target = $target; Input = $input }
}

if ($info.Count -lt 2) { Write-Host "!! need two clients"; exit 1 }

# 5. client 1 -> client 2
[void][W32]::SendStr($info[1].Target, 0x000C, [IntPtr]::Zero, "2")
[void][W32]::SendStr($info[1].Input,  0x000C, [IntPtr]::Zero, "hello-from-client-1")
[void][W32]::Send($info[1].Wnd, 0x0111, [IntPtr]1, [IntPtr]::Zero)
Start-Sleep -Seconds 2

# 6. client 2 -> client 1
[void][W32]::SendStr($info[2].Target, 0x000C, [IntPtr]::Zero, "1")
[void][W32]::SendStr($info[2].Input,  0x000C, [IntPtr]::Zero, "ack-from-client-2")
[void][W32]::Send($info[2].Wnd, 0x0111, [IntPtr]1, [IntPtr]::Zero)
Start-Sleep -Seconds 2

# 7. verify: client 2 stored "received from 1" in chats\2\1.log ; client 1 stored "received from 2" in chats\1\2.log
$f12 = Join-Path $CHATDIR "2\1.log"
$f21 = Join-Path $CHATDIR "1\2.log"

function Wait-Log([string]$path, [string]$needle) {
    for ($i = 0; $i -lt 10; $i++) {
        if (Test-Path $path) {
            $c = Get-Content $path -Encoding UTF8 -Raw
            if ($c -match $needle) { return $c }
        }
        Start-Sleep -Milliseconds 500
    }
    if (Test-Path $path) { return (Get-Content $path -Encoding UTF8 -Raw) }
    return ""
}

Write-Host "`n===== chats\2\1.log (client 2 view) ====="
$log12 = Wait-Log $f12 "hello-from-client-1"
Write-Host $log12
Write-Host "`n===== chats\1\2.log (client 1 view) ====="
$log21 = Wait-Log $f21 "ack-from-client-2"
Write-Host $log21

Write-Host "`n===== checks ====="
if ($log12 -match "(?m)`t0`thello-from-client-1") { Write-Host "  [OK] client 2 decrypted message 1" } else { Write-Host "  [FAIL] client 2 did not get message 1" }
if ($log21 -match "(?m)`t0`tack-from-client-2")   { Write-Host "  [OK] client 1 decrypted message 2" } else { Write-Host "  [FAIL] client 1 did not get message 2" }
if ($log21 -match "(?m)`t1`thello-from-client-1") { Write-Host "  [OK] outgoing message persisted" } else { Write-Host "  [FAIL] outgoing message not persisted" }

Write-Host "`n===== server log ====="
if (Test-Path "$env:TEMP\srv.log") { Get-Content "$env:TEMP\srv.log" -Encoding UTF8 }

Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name Server_App   -ErrorAction SilentlyContinue | Stop-Process -Force
