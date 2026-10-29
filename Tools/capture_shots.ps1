# ============================================================================
#  capture_shots.ps1 -- take real screenshots used by the report figures
#
#  Flow: server -> two GUI clients -> exchange messages (crossing the DH
#        ratchet interval) -> screenshot both windows -> message an offline
#        user -> screenshot the warning -> kill the server -> screenshot the
#        reconnect hint -> dump a ciphertext sample for the report.
#
#  ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).
# ============================================================================
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class C32 {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }

    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int idx);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr SendStr(IntPtr h, uint m, IntPtr w, string l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr Send(IntPtr h, uint m, IntPtr w, IntPtr l);

    public static List<IntPtr> Edits(IntPtr parent) {
        var res = new List<IntPtr>();
        EnumChildWindows(parent, (h, l) => {
            var cn = new StringBuilder(64); GetClassName(h, cn, 64);
            if (cn.ToString() == "Edit") res.Add(h);
            return true;
        }, IntPtr.Zero);
        return res;
    }
    public static IntPtr FirstOfClass(IntPtr parent, string want) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(parent, (h, l) => {
            var cn = new StringBuilder(64); GetClassName(h, cn, 64);
            if (cn.ToString() == want) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static string Text(IntPtr h) {
        int n = GetWindowTextLength(h);
        if (n <= 0) return "";
        var sb = new StringBuilder(n + 2); GetWindowText(h, sb, n + 2);
        return sb.ToString();
    }
    // 状态栏文本（含“安全码”的那一行）；用 \u 转义避开 ps1 的 ANSI 编码问题
    public static string StatusText(IntPtr parent) {
        string found = "";
        EnumChildWindows(parent, (h, l) => {
            int n = GetWindowTextLength(h);
            if (n <= 0) return true;
            var sb = new StringBuilder(n + 2);
            GetWindowText(h, sb, n + 2);
            var s = sb.ToString();
            if (s.Contains("\u5b89\u5168\u7801")) { found = s; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@

$ROOT   = "D:\ECDHE-Secured Chat System\build\Debug"
$OUT    = Join-Path $env:TEMP "shots"
$PROF1  = Join-Path $env:APPDATA "ECDHE_Chat\profiles\p1"
$PROF2  = Join-Path $env:APPDATA "ECDHE_Chat\profiles\p2"

Get-Process -Name ClientGUI_App,Server_App,MitmRelay -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
Remove-Item $PROF1,$PROF2 -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $OUT -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $OUT | Out-Null

# 固定窗口尺寸并置前；只 PrintWindow 一次，全图与状态栏裁剪复用同一张位图
function Shot([IntPtr]$h, [string]$full, [string]$status, [int]$x = 60, [int]$y = 60) {
    [void][C32]::ShowWindow($h, 9)
    [void][C32]::SetWindowPos($h, [IntPtr]::Zero, $x, $y, 900, 620, 0x0040)
    [void][C32]::SetForegroundWindow($h)
    Start-Sleep -Milliseconds 900

    $r = New-Object C32+RECT
    [void][C32]::GetWindowRect($h, [ref]$r)
    $w = $r.R - $r.L; $hh = $r.B - $r.T
    $bmp = New-Object System.Drawing.Bitmap $w, $hh
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    [void][C32]::PrintWindow($h, $hdc, 2)
    $g.ReleaseHdc($hdc)
    if ($full) { $bmp.Save($full, [System.Drawing.Imaging.ImageFormat]::Png); Write-Host "  saved $full" }
    if ($status) {
        $crop = 58
        $strip = New-Object System.Drawing.Bitmap $w, $crop
        $g2 = [System.Drawing.Graphics]::FromImage($strip)
        $dst = New-Object System.Drawing.Rectangle 0, 0, $w, $crop
        $src = New-Object System.Drawing.Rectangle 0, ($hh - $crop), $w, $crop
        $g2.DrawImage($bmp, $dst, $src, [System.Drawing.GraphicsUnit]::Pixel)
        $strip.Save($status, [System.Drawing.Imaging.ImageFormat]::Png)
        $g2.Dispose(); $strip.Dispose()
        Write-Host "  saved $status"
    }
    $g.Dispose(); $bmp.Dispose()
}

# ---------------------------------------------------------------- 1. start --
$server = Start-Process -FilePath "$ROOT\Server_App.exe" `
          -RedirectStandardOutput (Join-Path $OUT "server.log") -PassThru
Start-Sleep -Milliseconds 900

$c1 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList "--profile","p1" -PassThru
Start-Sleep -Milliseconds 700
$c2 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList "--profile","p2" -PassThru
Start-Sleep -Seconds 3

# ---------------------------------------------------- 2. locate the windows --
$info = @{}
foreach ($p in (Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue)) {
    $p.Refresh()
    if ($p.MainWindowHandle -eq 0) { continue }
    $w = $p.MainWindowHandle
    $t = [C32]::Text($w)
    if ($t -notmatch '([0-9]+)\s*$') { continue }
    $id = [int]$Matches[1]
    $chat = $null; $target = $null; $input = $null
    foreach ($e in [C32]::Edits($w)) {
        $st = [C32]::GetWindowLong($e, -16)
        if     ($st -band 0x800)  { $chat = $e }
        elseif ($st -band 0x2000) { $target = $e }
        elseif ($st -band 0x80)   { $input = $e }
    }
    $info[$id] = @{ Wnd = $w; Chat = $chat; Target = $target; Input = $input }
    Write-Host "  client $id -> $w"
}

if ($info.Count -lt 2) {
    Write-Host "!! need two clients"
    Get-Process -Name ClientGUI_App,Server_App -ErrorAction SilentlyContinue | Stop-Process -Force
    exit 1
}

function Send-Msg([int]$from, [string]$target, [string]$text) {
    [void][C32]::SendStr($info[$from].Target, 0x000C, [IntPtr]::Zero, $target)
    [void][C32]::SendStr($info[$from].Input,  0x000C, [IntPtr]::Zero, $text)
    [void][C32]::Send($info[$from].Wnd, 0x0111, [IntPtr]1, [IntPtr]::Zero)
}

# 在会话列表里单击第 index 项（切换当前会话，使提示出现在聊天区）
function Click-Item([int]$client, [int]$index) {
    $lb = [C32]::FirstOfClass($info[$client].Wnd, "ListBox")
    if ($lb -eq [IntPtr]::Zero) { Write-Host "  !! listbox not found"; return }
    $ih = [int][C32]::Send($lb, 0x01A1, [IntPtr]::Zero, [IntPtr]::Zero)   # LB_GETITEMHEIGHT
    if ($ih -le 0) { $ih = 18 }
    $y  = $ih * $index + [int]($ih / 2)
    $lp = [IntPtr](($y -shl 16) -bor 20)
    [void][C32]::Send($lb, 0x0201, [IntPtr]1, $lp)                        # WM_LBUTTONDOWN
    [void][C32]::Send($lb, 0x0202, [IntPtr]0, $lp)                        # WM_LBUTTONUP
    Start-Sleep -Milliseconds 500
}

# ---------------------------------------- 3. conversation (x25519 session) --
Send-Msg 1 "2" "hello-from-client-1"
Start-Sleep -Milliseconds 900
Send-Msg 2 "1" "ack-from-client-2"
Start-Sleep -Milliseconds 700
Send-Msg 1 "2" "handshake-uses-x25519-ecdhe"
Start-Sleep -Milliseconds 700
Send-Msg 2 "1" "safe-code-matched"
Start-Sleep -Milliseconds 700

# ---- 4. keep sending: the 8th message triggers the DH ratchet (REKEY) ------
for ($i = 1; $i -le 9; $i++) {
    Send-Msg 1 "2" ("ratchet-{0:d2}" -f $i)
    Start-Sleep -Milliseconds 260
}
Start-Sleep -Seconds 2

Shot $info[1].Wnd (Join-Path $OUT "chat_1.png") (Join-Path $OUT "status_1.png") 40 40
Shot $info[2].Wnd (Join-Path $OUT "chat_2.png") (Join-Path $OUT "status_2.png") 40 40

# 把两端状态栏的真实文本写出来，供报告引用（避免手写数值与截图不一致）
$s1 = [C32]::StatusText($info[1].Wnd)
$s2 = [C32]::StatusText($info[2].Wnd)
Set-Content -Path (Join-Path $OUT "sas.txt") -Value @("c1=$s1", "c2=$s2") -Encoding UTF8
Write-Host "  status1: $s1"
Write-Host "  status2: $s2"

# ------------------------------------------- 5. message a user who is away --
Send-Msg 1 "9" "anyone-there"
Start-Sleep -Milliseconds 1500
Click-Item 1 1
Shot $info[1].Wnd (Join-Path $OUT "offline.png") $null 40 40

# --------------------------------------- 6. kill the server -> reconnect ----
Stop-Process -Id $server.Id -Force
Start-Sleep -Seconds 18
Shot $info[1].Wnd (Join-Path $OUT "disconnect.png") (Join-Path $OUT "disconnect_status.png") 40 40

# ------------------------------------------- 7. ciphertext sample on disk ---
$logf = Get-ChildItem -Path (Join-Path $PROF2 "chats") -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
        Select-Object -First 1
$txt = Join-Path $OUT "ciphertext.txt"
if ($logf) {
    # NOTE: keep this file ASCII-only -- PowerShell 5.1 reads .ps1 as ANSI,
    #       Chinese literals here would be corrupted. Chinese labels are added
    #       later by Tools\make_figures.py.
    $lines = Get-Content $logf.FullName -Encoding UTF8 -TotalCount 3
    $rel = $logf.FullName.Replace($env:APPDATA + "\ECDHE_Chat\", "")
    $all = @()
    $all += "file: " + $rel
    $all += "records: " + (Get-Content $logf.FullName -Encoding UTF8).Count
    $all += ""
    foreach ($l in $lines) { $all += $l }
    $all += ""
    $plain = Get-Content $logf.FullName -Encoding UTF8 -Raw
    if ($plain -match "hello-from-client-1") { $all += "PLAINTEXT-FOUND hello-from-client-1" }
    else { $all += "PLAINTEXT-NOT-FOUND hello-from-client-1" }
    Set-Content -Path $txt -Value $all -Encoding UTF8
    Write-Host "  ciphertext sample -> $txt"
}

Get-Process -Name ClientGUI_App,Server_App -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "`nall screenshots in $OUT"
