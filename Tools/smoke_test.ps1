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
$OUTDIR = Join-Path $env:TEMP "chat_smoke"
$PROF1 = Join-Path $env:APPDATA "ECDHE_Chat\profiles\p1"
$PROF2 = Join-Path $env:APPDATA "ECDHE_Chat\profiles\p2"

# 1. clean
Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name Server_App   -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
Remove-Item $PROF1,$PROF2 -Recurse -Force -ErrorAction SilentlyContinue

# 2. start server
$server = Start-Process -FilePath "$ROOT\Server_App.exe" -RedirectStandardOutput "$env:TEMP\srv.log" -PassThru
Start-Sleep -Milliseconds 800

# 3. start two clients
$c1 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList "--profile","p1" -PassThru
Start-Sleep -Milliseconds 700
$c2 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList "--profile","p2" -PassThru
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

# 7. 聊天记录已加密存储：先关掉客户端，再用 --dump 导出解密后的明文进行校验
Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 600

$dump2 = Join-Path $OUTDIR "p2_dump.txt"
$dump1 = Join-Path $OUTDIR "p1_dump.txt"
Remove-Item $dump1,$dump2 -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $OUTDIR | Out-Null

Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList @("--profile","p2","--dump",$dump2) -Wait
Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList @("--profile","p1","--dump",$dump1) -Wait
Start-Sleep -Milliseconds 500

function Read-Dump([string]$path) {
    if (Test-Path $path) { return (Get-Content $path -Encoding UTF8 -Raw) }
    return ""
}
$log12 = Read-Dump $dump2
$log21 = Read-Dump $dump1

Write-Host "`n===== exported history (client 2 view) ====="
Write-Host $log12
Write-Host "`n===== exported history (client 1 view) ====="
Write-Host $log21

Write-Host "`n===== checks ====="
if ($log12 -match "(?m)^1`t0`thello-from-client-1") { Write-Host "  [OK] client 2 decrypted message 1" } else { Write-Host "  [FAIL] client 2 did not get message 1" }
if ($log21 -match "(?m)^2`t0`tack-from-client-2")   { Write-Host "  [OK] client 1 decrypted message 2" } else { Write-Host "  [FAIL] client 1 did not get message 2" }
if ($log21 -match "(?m)^2`t1`thello-from-client-1") { Write-Host "  [OK] outgoing message persisted" } else { Write-Host "  [FAIL] outgoing message not persisted" }

# 磁盘上的记录文件必须是密文（不应出现明文）
$stored = Get-ChildItem -Path (Join-Path $PROF2 "chats") -Recurse -Filter "1.log" -ErrorAction SilentlyContinue |
          Select-Object -First 1
if ($stored) {
    $raw = Get-Content $stored.FullName -Encoding UTF8 -Raw
    if ($raw -match "hello-from-client-1") {
        Write-Host "  [FAIL] chat log stored in plaintext"
    } else {
        Write-Host "  [OK] chat log encrypted at rest"
        Write-Host ("         " + $raw.Substring(0, [Math]::Min(64, $raw.Length)) + "...")
    }
} else {
    Write-Host "  [SKIP] chat log not found"
}

Write-Host "`n===== server log ====="
if (Test-Path "$env:TEMP\srv.log") { Get-Content "$env:TEMP\srv.log" -Encoding UTF8 }

Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name Server_App   -ErrorAction SilentlyContinue | Stop-Process -Force
