# ============================================================================
#  MITM 中间人演示 + 抓包对比截图
#
#  流程：启动 MitmRelay（冒充中继服务器，监听 9000）→ 启动两个客户端
#        → 自动互发消息 → 打印 MITM 解密出的明文 / 密文抓包 / 双方安全码差异
#        → 同时把两个客户端窗口截图保存为 PNG
#
#  ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).
# ============================================================================
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class M32 {
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
$OUTDIR = Join-Path $env:TEMP "mitm_demo"
$LOG    = Join-Path $OUTDIR "mitm.log"
$PROF1  = Join-Path $env:APPDATA "ECDHE_Chat\profiles\p1"
$PROF2  = Join-Path $env:APPDATA "ECDHE_Chat\profiles\p2"

Get-Process -Name ClientGUI_App,MitmRelay,Server_App -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# 清空历史与指纹固定，模拟“第一次与对方通信”
Remove-Item $PROF1,$PROF2 -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $OUTDIR | Out-Null

# 1. 启动 MITM 中继（冒充服务器）
$mitm = Start-Process -FilePath "$ROOT\MitmRelay.exe" -RedirectStandardOutput $LOG -PassThru
Start-Sleep -Milliseconds 900

# 2. 启动两个客户端（它们并不知道连的是中间人）
$c1 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList "--profile","p1" -PassThru
Start-Sleep -Milliseconds 700
$c2 = Start-Process -FilePath "$ROOT\ClientGUI_App.exe" -ArgumentList "--profile","p2" -PassThru
Start-Sleep -Seconds 3

# 3. 定位窗口与控件
$wins = @()
foreach ($p in (Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue)) {
    $p.Refresh()
    if ($p.MainWindowHandle -ne 0) { $wins += $p.MainWindowHandle }
}

$info = @{}
foreach ($w in $wins) {
    $t = [M32]::Text($w)
    if ($t -notmatch '([0-9]+)\s*$') { continue }
    $id = [int]$Matches[1]
    $chat = $null; $target = $null; $input = $null
    foreach ($e in [M32]::Edits($w)) {
        $st = [M32]::GetWindowLong($e, -16)
        if ($st -band 0x800)       { $chat = $e }
        elseif ($st -band 0x2000)  { $target = $e }
        elseif ($st -band 0x80)    { $input = $e }
    }
    $info[$id] = @{ Wnd = $w; Chat = $chat; Target = $target; Input = $input }
}

if ($info.Count -lt 2) {
    Write-Host "!! need two clients (got $($info.Count))"
    Get-Process -Name ClientGUI_App,MitmRelay -ErrorAction SilentlyContinue | Stop-Process -Force
    exit 1
}

Write-Host "clients: $($info.Keys -join ', ')"

# 4. 互发消息（内容为可识别的“敏感信息”）
[void][M32]::SendStr($info[1].Target, 0x000C, [IntPtr]::Zero, "2")
[void][M32]::SendStr($info[1].Input,  0x000C, [IntPtr]::Zero, "card-password-is-123456")
[void][M32]::Send($info[1].Wnd, 0x0111, [IntPtr]1, [IntPtr]::Zero)
Start-Sleep -Seconds 2

[void][M32]::SendStr($info[2].Target, 0x000C, [IntPtr]::Zero, "1")
[void][M32]::SendStr($info[2].Input,  0x000C, [IntPtr]::Zero, "received-ok-meet-at-8pm")
[void][M32]::Send($info[2].Wnd, 0x0111, [IntPtr]1, [IntPtr]::Zero)
Start-Sleep -Seconds 2

# 5. 截图两个客户端（证明它们认为会话正常）
function Grab([IntPtr]$h) {
    [void][M32]::ShowWindow($h, 9)
    [void][M32]::SetWindowPos($h, [IntPtr]::Zero, 40, 40, 900, 620, 0x0040)
    [void][M32]::SetForegroundWindow($h)
    Start-Sleep -Milliseconds 600
    $r = New-Object M32+RECT
    [void][M32]::GetWindowRect($h, [ref]$r)
    $bmp = New-Object System.Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    [void][M32]::PrintWindow($h, $hdc, 2)
    $g.ReleaseHdc($hdc)
    return $bmp
}

function Capture([IntPtr]$h, [string]$path, [string]$statusPath) {
    $bmp = Grab $h
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    if ($statusPath) {
        $crop = 56
        $strip = New-Object System.Drawing.Bitmap $bmp.Width, $crop
        $g2 = [System.Drawing.Graphics]::FromImage($strip)
        $dst = New-Object System.Drawing.Rectangle 0, 0, $bmp.Width, $crop
        $src = New-Object System.Drawing.Rectangle 0, ($bmp.Height - $crop), $bmp.Width, $crop
        $g2.DrawImage($bmp, $dst, $src, [System.Drawing.GraphicsUnit]::Pixel)
        $strip.Save($statusPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $g2.Dispose(); $strip.Dispose()
    }
    $bmp.Dispose()
}

Capture $info[1].Wnd (Join-Path $OUTDIR "client_1.png") (Join-Path $OUTDIR "status_1.png")
Capture $info[2].Wnd (Join-Path $OUTDIR "client_2.png") (Join-Path $OUTDIR "status_2.png")

$s1 = [M32]::StatusText($info[1].Wnd)
$s2 = [M32]::StatusText($info[2].Wnd)
Set-Content -Path (Join-Path $OUTDIR "sas.txt") -Value @("c1=$s1", "c2=$s2") -Encoding UTF8

Get-Process -Name ClientGUI_App,MitmRelay -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 300

# 清理本次演示写入的指纹（否则下次连真服务器会因指纹不一致而被阻断）
Remove-Item $PROF1,$PROF2 -Recurse -Force -ErrorAction SilentlyContinue

# 6. 展示 MITM 视角
Write-Host "`n================= MITM view (what the attacker sees) ================="
Get-Content $LOG -Encoding UTF8
Write-Host "`nScreenshots saved:"
Write-Host "  $OUTDIR\client_1.png"
Write-Host "  $OUTDIR\client_2.png"
