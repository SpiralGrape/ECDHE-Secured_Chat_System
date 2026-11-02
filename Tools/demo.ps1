# ============================================================================
#  ECDHE 前向保密即时通信系统 —— 演示控制台
#
#  用法（在项目根目录打开 PowerShell）：
#      powershell -ExecutionPolicy Bypass -File Tools\demo.ps1
#
#  说明：
#    1. 菜单驱动：每一步都需要手动输入编号触发，执行完毕后按回车键返回主菜单，
#       演示节奏由操作者掌握，不会自动连续执行；
#    2. 每一步开头给出该步骤的目的，结束给出可以观察到的结论；
#    3. 演示使用独立档案（demo-*），与日常使用的身份和聊天记录相互隔离，
#       第 12 步可一键清理。
# ============================================================================

param(
    [string]$RunApp   = "",
    [string]$RunLog   = "",
    [string]$RunTitle = ""
)

$ErrorActionPreference = "Stop"

# 子进程（CryptoTest / Server_App / MitmRelay）输出 UTF-8，这里让控制台按 UTF-8 解码
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

# ---------------------------------------------------------------- 子进程模式
# 以 -RunApp 启动时，本脚本只做一件事：运行指定的程序，把它的输出同时显示在
# 本窗口（演示时可以直接看到中继/攻击程序的实时输出）并写入日志文件（供后续核对）。
if ($RunApp) {
    if ($RunTitle) { try { $Host.UI.RawUI.WindowTitle = $RunTitle } catch { } }
    Write-Host ""
    Write-Host ("  " + $RunTitle) -ForegroundColor Cyan
    Write-Host ("  " + ("-" * 62)) -ForegroundColor DarkGray
    if (Test-Path $RunLog) { Remove-Item $RunLog -Force -ErrorAction SilentlyContinue }
    & $RunApp 2>&1 | ForEach-Object {
        Write-Host $_
        try { Add-Content -Path $RunLog -Value $_ -Encoding UTF8 } catch { }
    }
    Write-Host ""
    Write-Host "  程序已退出。" -ForegroundColor DarkGray
    exit 0
}

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class D32 {
    public delegate bool EnumProc(IntPtr h, IntPtr l);

    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int idx);

    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr SendStr(IntPtr h, uint m, IntPtr w, string l);

    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr Send(IntPtr h, uint m, IntPtr w, IntPtr l);

    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr SendBuf(IntPtr h, uint m, IntPtr w, StringBuilder l);

    // 跨进程读 Edit 控件的文字：必须发 WM_GETTEXT（GetWindowText 只返回窗口标题）
    public static string EditText(IntPtr h) {
        int n = (int)Send(h, 0x000E, IntPtr.Zero, IntPtr.Zero);   // WM_GETTEXTLENGTH
        if (n <= 0) return "";
        var sb = new StringBuilder(n + 2);
        SendBuf(h, 0x000D, (IntPtr)(n + 1), sb);                  // WM_GETTEXT
        return sb.ToString();
    }

    public static List<IntPtr> Children(IntPtr parent, string cls) {
        var res = new List<IntPtr>();
        EnumChildWindows(parent, (h, l) => {
            var cn = new StringBuilder(64); GetClassName(h, cn, 64);
            if (cn.ToString() == cls) res.Add(h);
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
}
"@

$HERE = Split-Path -Parent $PSScriptRoot
$EXE  = Join-Path $HERE "build\Debug"
$APPD = Join-Path $env:APPDATA "ECDHE_Chat\profiles"
$TMPD = Join-Path $env:TEMP "ecdhe_demo"

$PROF_A   = "demo-a"
$PROF_B   = "demo-b"
$PROF_M1  = "demo-m1"
$PROF_M2  = "demo-m2"
$PROF_ALL = @("demo-a", "demo-b", "demo-c", "demo-d", "demo-m1", "demo-m2")

$script:Srv    = $null
$script:CA     = $null
$script:CB     = $null
$script:Mitm   = $null
$script:UProcs = @()

# ============================================================ 输出格式 ====

function Write-Title([string]$t) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host ("  " + $t) -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

function Write-Purpose([string]$text) {
    Write-Host ""
    Write-Host ("  目的：" + $text) -ForegroundColor Cyan
}

function Write-Step([int]$n, [string]$text) {
    Write-Host ""
    Write-Host ("  (" + $n + ") " + $text) -ForegroundColor White
}

function Write-Conclusion([string[]]$lines) {
    Write-Host ""
    Write-Host "  【本步结论】" -ForegroundColor Yellow
    foreach ($l in $lines) { Write-Host ("   · " + $l) -ForegroundColor Gray }
}

function Write-Ok([string]$s)   { Write-Host ("  [通过] " + $s) -ForegroundColor Green }
function Write-Bad([string]$s)  { Write-Host ("  [注意] " + $s) -ForegroundColor Red }
function Write-Info([string]$s) { Write-Host ("  " + $s) -ForegroundColor Gray }

function Pause-Step([string]$msg) {
    Write-Host ""
    [void](Read-Host ("  —— " + $msg + "，按回车键继续 ——"))
}

function Wait-Menu {
    Write-Host ""
    [void](Read-Host "  —— 按回车键返回主菜单 ——")
}

# ============================================================ 基础操作 ====

function Get-Proc([string]$name) {
    return (Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Stop-All {
    Get-Process -Name ClientGUI_App,MitmRelay,Server_App -ErrorAction SilentlyContinue | Stop-Process -Force
    # 一并关闭承载输出的控制台窗口（本脚本的子进程模式）
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine -like '*-RunApp*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch { }
    Start-Sleep -Milliseconds 600
    $script:Srv    = $null
    $script:CA     = $null
    $script:CB     = $null
    $script:Mitm   = $null
    $script:UProcs = @()
}

function Remove-Profile([string]$name) {
    Remove-Item (Join-Path $APPD $name) -Recurse -Force -ErrorAction SilentlyContinue
}

# 在独立控制台窗口中运行一个程序：窗口里实时显示它的输出，同时写入日志文件。
# 直接用 -RedirectStandardOutput 会导致窗口里什么都不显示（只有一个黑框）。
function Start-VisibleApp([string]$exePath, [string]$logPath, [string]$title) {
    New-Item -ItemType Directory -Force -Path $TMPD | Out-Null
    if (Test-Path $logPath) { Remove-Item $logPath -Force -ErrorAction SilentlyContinue }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'),
                 '-RunApp', ('"' + $exePath + '"'), '-RunLog', ('"' + $logPath + '"'),
                 '-RunTitle', ('"' + $title + '"'))
    return Start-Process -FilePath "powershell" -ArgumentList $argList -PassThru
}

function Test-Port9000 {
    try {
        return (@(Get-NetTCPConnection -LocalPort 9000 -State Listen -ErrorAction SilentlyContinue).Count -gt 0)
    } catch {
        return ((netstat -ano | Select-String ":9000\s" -Quiet) -eq $true)
    }
}

function Start-Server {
    $log = Join-Path $TMPD "server.log"
    $null = Start-VisibleApp (Join-Path $EXE "Server_App.exe") $log "中继服务器 Server_App（演示期间可观察转发日志）"
    Start-Sleep -Milliseconds 1200
    return $log
}

# 扫描当前所有客户端窗口，返回「服务器 ID -> 控件句柄」的哈希表
function Get-Clients {
    $res = @{}
    foreach ($p in (Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue)) {
        $p.Refresh()
        if ($p.MainWindowHandle -eq 0) { continue }
        $w = $p.MainWindowHandle
        $title = [D32]::Text($w)
        if ($title -notmatch '([0-9]+)\s*$') { continue }
        $id = [int]$Matches[1]

        $chat = $null; $target = $null; $input = $null
        foreach ($e in [D32]::Children($w, "Edit")) {
            $st = [D32]::GetWindowLong($e, -16)
            if     ($st -band 0x800)  { $chat = $e }      # ES_READONLY    -> 聊天区
            elseif ($st -band 0x2000) { $target = $e }    # ES_NUMBER      -> 收件人 ID
            elseif ($st -band 0x80)   { $input = $e }     # ES_AUTOHSCROLL -> 输入框
        }
        $res[$id] = @{ Wnd = $w; Chat = $chat; Target = $target; Input = $input; ProcId = $p.Id }
    }
    return $res
}

function Get-IdByProc([hashtable]$info, $procObj) {
    if (-not $procObj) { return 0 }
    foreach ($k in $info.Keys) {
        if ($info[$k].ProcId -eq $procObj.Id) { return $k }
    }
    return 0
}

# 状态栏文本（「收件人 ID:」是静态标签，其余 Static 均为状态栏内容）
function Get-StatusLines($wnd) {
    $lines = @()
    foreach ($s in [D32]::Children($wnd, "Static")) {
        $t = [D32]::Text($s)
        if ($t -and $t -notmatch '^\s*收件人\s*ID') { $lines += $t }
    }
    return $lines
}

function Read-Chat($wnd) {
    $box = $null
    foreach ($e in [D32]::Children($wnd, "Edit")) {
        $st = [D32]::GetWindowLong($e, -16)
        if ($st -band 0x800) { $box = $e }
    }
    if (-not $box) { return "" }
    return [D32]::EditText($box)
}

# 让客户端窗口选中会话列表中的第一项，使收到的消息直接显示在聊天区
function Select-FirstSession($wnd) {
    $lb = $null
    foreach ($c in [D32]::Children($wnd, "ListBox")) { $lb = $c }
    if (-not $lb) { return $false }
    $cnt = [int][D32]::Send($lb, 0x018B, [IntPtr]::Zero, [IntPtr]::Zero)      # LB_GETCOUNT
    if ($cnt -le 0) { return $false }
    [void][D32]::Send($lb, 0x0186, [IntPtr]::Zero, [IntPtr]::Zero)            # LB_SETCURSEL 0
    $wparam = [IntPtr](((1 -shl 16) -bor 101))                                # LBN_SELCHANGE + IDC_SESSION_LIST
    [void][D32]::Send($wnd, 0x0111, $wparam, $lb)                             # WM_COMMAND
    Start-Sleep -Milliseconds 300
    return $true
}

function Send-Chat([hashtable]$info, [int]$fromId, [int]$toId, [string]$text) {
    if (-not $info.ContainsKey($fromId)) { return $false }
    [void][D32]::SendStr($info[$fromId].Target, 0x000C, [IntPtr]::Zero, "$toId")
    [void][D32]::SendStr($info[$fromId].Input,  0x000C, [IntPtr]::Zero, $text)
    [void][D32]::Send($info[$fromId].Wnd, 0x0111, [IntPtr]1, [IntPtr]::Zero)
    return $true
}

function Dump-History([string]$profile, [string]$tag) {
    New-Item -ItemType Directory -Force -Path $TMPD | Out-Null
    $file = Join-Path $TMPD ("dump_" + $tag + ".txt")
    Remove-Item $file -Force -ErrorAction SilentlyContinue
    & (Join-Path $EXE "ClientGUI_App.exe") --profile $profile --dump $file
    Start-Sleep -Milliseconds 300
    if (Test-Path $file) {
        return @(Get-Content $file -Encoding UTF8 | Where-Object { $_ -match '\S' })
    }
    return @()
}

function Show-Header {
    $srv  = Get-Proc "Server_App"
    $mitm = Get-Proc "MitmRelay"
    $ids = @()
    foreach ($p in (Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue)) {
        $p.Refresh()
        if ($p.MainWindowHandle -eq 0) { continue }
        $t = [D32]::Text($p.MainWindowHandle)
        if ($t -match '([0-9]+)\s*$') { $ids += $Matches[1] }
    }

    $s1 = if ($srv)  { "中继服务器：运行中" } else { "中继服务器：未启动" }
    $s2 = if ($mitm) { "攻击模拟：运行中" }   else { "攻击模拟：未启动" }
    $s3 = if ($ids.Count -gt 0) { "客户端 ID：" + ($ids -join "、") } else { "客户端：未启动" }

    Write-Host ""
    Write-Host ("  当前状态：" + $s1 + " ｜ " + $s2 + " ｜ " + $s3) -ForegroundColor DarkCyan
}

# ============================================================ 各步骤 ====

function Step-Env {
    Write-Title "1 / 环境自检"
    Write-Purpose "确认演示所需的四个程序、通信端口与进程状态。"

    $need = @("Server_App.exe", "ClientGUI_App.exe", "CryptoTest.exe", "MitmRelay.exe")
    $missing = 0
    foreach ($n in $need) {
        if (Test-Path (Join-Path $EXE $n)) { Write-Ok $n }
        else { Write-Bad ("缺少 " + $n); $missing++ }
    }
    if ($missing -gt 0) {
        Write-Host ""
        Write-Bad "请先执行第 2 步编译，或确认 build\Debug 目录存在"
        return
    }

    $busy = $false
    try {
        $busy = @(Get-NetTCPConnection -LocalPort 9000 -State Listen -ErrorAction SilentlyContinue).Count -gt 0
    } catch {
        $busy = ((netstat -ano | Select-String ":9000\s" -Quiet) -eq $true)
    }
    if ($busy) { Write-Bad "端口 9000 已被占用，可执行第 12 步清理后重试" }
    else       { Write-Ok "端口 9000 空闲" }

    $left = @(Get-Process -Name ClientGUI_App,MitmRelay,Server_App -ErrorAction SilentlyContinue)
    if ($left.Count -gt 0) { Write-Bad ("存在 " + $left.Count + " 个残留进程，建议先执行第 12 步清理") }
    else                   { Write-Ok "无残留进程" }

    Write-Conclusion @(
        "四个程序分别对应中继服务器、图形客户端、密码学自测与中间人演示工具。",
        "客户端以 --profile 区分身份，因此同一台计算机可以模拟多个用户同时在线。"
    )
}

function Step-Build {
    Write-Title "2 / 编译工程"
    Write-Purpose "从源码构建全部目标程序，验证工程可完整复现。"
    Write-Info "命令：cmake --build build --config Debug"
    Write-Host ""
    Push-Location $HERE
    try {
        & cmake --build build --config Debug 2>&1 | Select-Object -Last 10 | ForEach-Object { Write-Host ("  " + $_) }
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    Write-Host ""
    if ($code -eq 0) { Write-Ok "编译成功" } else { Write-Bad ("编译失败，退出码 " + $code) }

    Write-Conclusion @(
        "依赖由 vcpkg 统一管理（OpenSSL 3.x、Boost.Asio），避免手工配置第三方库。",
        "源码统一以 /utf-8 编译，界面层全部使用宽字符接口，构建产物位于 build\Debug。"
    )
}

function Step-Crypto {
    Write-Title "3 / 密码学与协议自测"
    Write-Purpose "验证密码学原语与协议实现的正确性（28 项断言）。"
    Write-Info "程序：CryptoTest.exe"
    Write-Host ""

    $out = & (Join-Path $EXE "CryptoTest.exe") 2>&1
    foreach ($line in $out) { Write-Host ("  " + $line) }

    $all = ($out -join "`n")
    Write-Host ""
    if ($all -match "通过\s*(\d+)\s*项[，,]\s*失败\s*(\d+)\s*项") {
        if ($Matches[2] -eq "0") { Write-Ok ("全部断言通过：通过 " + $Matches[1] + " 项，失败 0 项") }
        else                     { Write-Bad ("存在 " + $Matches[2] + " 项失败") }
    } else {
        Write-Bad "未解析到结果行，请人工确认输出"
    }

    Write-Conclusion @(
        "覆盖 X25519 密钥交换、HKDF-SHA256 派生、AES-256-GCM 加解密、Ed25519 签名验签、两类棘轮与完整握手流程。",
        "其中「篡改 AAD、篡改密文、使用错误密钥必须解密失败」一项，用于证明认证加密确实生效。",
        "「完整握手 + 20 条消息 + 自动轮换」用例验证了前向保密与后向恢复的工程实现，而非仅停留在设计层面。"
    )
}

function Step-Server {
    Write-Title "4 / 启动中继服务器"
    Write-Purpose "启动只做转发、不持有任何密钥的中继服务器。"

    if (Get-Proc "MitmRelay") {
        Write-Bad "攻击模拟程序正在占用 9000 端口，请先完成第 11 步或执行第 12 步清理"
        return
    }
    if (Get-Proc "Server_App") {
        Write-Info "中继服务器已在运行，无需重复启动"
        return
    }

    $log = Start-Server
    $srvProc = Get-Proc "Server_App"
    if (-not $srvProc -or -not (Test-Port9000)) {
        Write-Bad "中继服务器启动失败，请确认 9000 端口未被占用"
        return
    }
    Write-Ok ("中继服务器已启动，PID " + $srvProc.Id + "，监听 9000 端口")
    Write-Info "已弹出中继服务器窗口，窗口内会实时打印每一次转发（只有字节数）"
    Write-Info ("日志文件：" + $log)

    Write-Conclusion @(
        "服务器不参与任何密钥运算，只按帧头中的目标 ID 转发，日志中仅记录转发字节数。",
        "因此即使服务器被完全控制，也无法获得会话密钥或消息明文。"
    )
}

function Step-Clients {
    Write-Title "5 / 启动两个客户端"
    Write-Purpose "启动两个客户端，建立各自的长期身份并接入服务器。"

    if (-not (Get-Proc "Server_App")) {
        Write-Bad "请先执行第 4 步启动中继服务器"
        return
    }
    if (Get-Proc "ClientGUI_App") {
        Write-Bad "已有客户端在运行，请先执行第 12 步清理"
        return
    }

    Remove-Profile $PROF_A
    Remove-Profile $PROF_B

    Write-Step 1 "启动客户端 A"
    $script:CA = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_A -PassThru
    Start-Sleep -Milliseconds 800
    Write-Step 2 "启动客户端 B"
    $script:CB = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_B -PassThru
    Start-Sleep -Seconds 3

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB

    Write-Host ""
    if ($idA -gt 0) { Write-Ok ("客户端 A 已接入，服务器分配的 ID = " + $idA) } else { Write-Bad "客户端 A 未就绪" }
    if ($idB -gt 0) { Write-Ok ("客户端 B 已接入，服务器分配的 ID = " + $idB) } else { Write-Bad "客户端 B 未就绪" }
    if ($idA -gt 0 -and $idB -gt 0) {
        Write-Info ("后续操作中，A 的收件人 ID 填 " + $idB + "，B 的收件人 ID 填 " + $idA)
    }

    Write-Conclusion @(
        "客户端 ID 由服务器按接入顺序分配，仅用于路由，不代表用户身份。",
        "每个 --profile 拥有独立的 Ed25519 身份密钥，首次运行时自动生成并保存在本地。"
    )
}

function Step-Send {
    Write-Title "6 / 发送一条消息"
    Write-Purpose "演示一次完整的端到端加密通信过程。"

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "请先执行第 5 步启动两个客户端"
        return
    }

    $text = "这是一条端到端加密的消息"
    Write-Step 1 ("客户端 A 向用户 " + $idB + " 发送消息：" + $text)
    [void](Send-Chat $info $idA $idB $text)
    Start-Sleep -Seconds 2
    [void](Select-FirstSession $info[$idB].Wnd)   # 接收方选中会话，让消息直接显示出来
    Start-Sleep -Milliseconds 500

    Write-Host ""
    Write-Host "  ── 客户端 A 的聊天区 ──" -ForegroundColor DarkGray
    (Read-Chat $info[$idA].Wnd) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host ("    " + $_) }
    Write-Host "  ── 客户端 B 的聊天区 ──" -ForegroundColor DarkGray
    (Read-Chat $info[$idB].Wnd) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host ("    " + $_) }

    Write-Conclusion @(
        "发送方首次通信时客户端自动完成三报文握手，业务层无需感知密钥协商过程。",
        "消息在本机加密、在对端解密，中继只转发密文，B 的聊天区不会出现任何来自服务器的明文。"
    )
}

function Step-Sas {
    Write-Title "7 / 会话安全码与密钥指纹"
    Write-Purpose "核对通信双方各自派生的会话安全码是否一致。"

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "请先执行第 5、6 步，让两个客户端建立会话"
        return
    }

    $sA = (Get-StatusLines $info[$idA].Wnd) -join " "
    $sB = (Get-StatusLines $info[$idB].Wnd) -join " "

    Write-Host "  客户端 A 的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sA)
    Write-Host "  客户端 B 的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sB)

    $sasA = ""; $sasB = ""
    if ($sA -match "安全码\s*(\d{6})") { $sasA = $Matches[1] }
    if ($sB -match "安全码\s*(\d{6})") { $sasB = $Matches[1] }

    Write-Host ""
    if ($sasA -and $sasB) {
        if ($sasA -eq $sasB) { Write-Ok ("两端安全码一致：" + $sasA + "，说明双方看到的握手内容完全相同") }
        else                 { Write-Bad ("两端安全码不一致：" + $sasA + " / " + $sasB + "，存在中间人") }
    } else {
        Write-Bad "尚未建立会话，请先执行第 6 步发送一条消息"
    }

    Write-Conclusion @(
        "安全码由双方握手报文的哈希得到，两端一致说明没有第三方介入。",
        "若存在中间人，两次握手的报文不同，安全码必然不同，第 11 步将给出该情形。"
    )
}

function Step-Cipher {
    Write-Title "8 / 本地存储密文取证"
    Write-Purpose "验证聊天记录在磁盘上同样以密文形式保存。"

    $chatDir = Join-Path (Join-Path $APPD $PROF_A) "chats"
    $logs = @(Get-ChildItem -Path $chatDir -Recurse -Filter *.log -ErrorAction SilentlyContinue)
    if ($logs.Count -eq 0) {
        Write-Bad "未找到聊天记录，请先执行第 6 步发送一条消息"
        return
    }

    Write-Step 1 "查看磁盘上的记录文件"
    foreach ($f in $logs) { Write-Host ("    " + $f.FullName) }

    $raw   = Get-Content $logs[0].FullName -Encoding UTF8 -Raw
    $first = ($raw -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1)
    Write-Host ""
    Write-Host "  文件第一行内容（十六进制，无任何明文）：" -ForegroundColor DarkGray
    Write-Host ("    " + $first.Substring(0, [Math]::Min(96, $first.Length)) + " ...")

    if ($raw -match "端到端加密") { Write-Bad "文件中出现明文，存储加密失效" }
    else                          { Write-Ok "文件中检索不到明文，落盘内容为密文" }

    Write-Step 2 "使用受控导出接口解密"
    Write-Info "解密需要本机身份私钥（受 Windows DPAPI 保护）"
    foreach ($l in (Dump-History $PROF_A "a")) { Write-Host ("    " + $l) }

    Write-Conclusion @(
        "同一条消息在磁盘上是 AES-256-GCM 密文，只有持有本机存储密钥的程序才能解出明文。",
        "存储密钥由身份私钥经 HKDF 派生，与传输用的会话密钥相互独立，属于不同的密钥域。",
        "身份私钥经 DPAPI 加密，复制到其他账户或计算机后无法解密，聊天记录同样无法打开。"
    )
}

function Step-Reconnect {
    Write-Title "9 / 掉线重连：ID 变化后历史仍连续"
    Write-Purpose "验证服务器重新分配 ID 之后，本地聊天记录不会被拆分。"

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "请先执行第 5、6 步"
        return
    }

    Write-Step 1 ("关闭客户端 B（当前 ID = " + $idB + "），模拟掉线")
    Stop-Process -Id $script:CB.Id -Force
    Start-Sleep -Milliseconds 900

    Write-Step 2 "以同一档案重新启动客户端 B"
    $script:CB = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_B -PassThru
    Start-Sleep -Seconds 3

    $info = Get-Clients
    $idB2 = Get-IdByProc $info $script:CB
    if ($idB2 -le 0) { Write-Bad "客户端 B 未能重新接入"; return }

    if ($idB2 -ne $idB) { Write-Info ("客户端 B 重新接入后，服务器分配了新 ID：" + $idB + " → " + $idB2) }
    else                { Write-Info ("客户端 B 重新接入，ID 仍为 " + $idB2) }

    Write-Step 3 ("客户端 A 向新 ID " + $idB2 + " 再发送一条消息")
    [void](Send-Chat $info $idA $idB2 "重连之后我还在")
    Start-Sleep -Seconds 2
    [void](Select-FirstSession $info[$idB2].Wnd)

    Write-Step 4 "导出客户端 A 的完整历史"
    $dumpA = Dump-History $PROF_A "a"
    foreach ($l in $dumpA) { Write-Host ("    " + $l) }

    $peers = @($dumpA | ForEach-Object { ($_ -split "`t")[0] } | Select-Object -Unique)
    Write-Host ""
    if ($peers.Count -eq 1) {
        Write-Ok ("两条消息归在同一个联系人下（对端列 = " + ($peers -join "、") + "），历史未被打断")
    } else {
        Write-Bad ("历史被拆分为多个联系人：" + ($peers -join "、"))
    }

    Write-Conclusion @(
        "服务器按接入顺序分配号码，同一用户重连后号码会变化，这是系统的既有前提。",
        "本地记录除文件名中的号码外，密文内部还保存了对端身份指纹，载入时按指纹合并，因此历史不会被拆成两段。",
        "之所以不直接改用指纹作文件名，是因为记录的认证数据（AAD）绑定了对端号码，改名会导致旧记录无法解密。"
    )
}

function Step-Multi {
    Write-Title "10 / 多用户并发测试（四人同时在线）"
    Write-Purpose "验证多个用户同时在线时，消息按目标精确投递、互不串扰。"

    Write-Step 1 "清理环境并启动中继服务器"
    Stop-All
    foreach ($p in @("demo-a", "demo-b", "demo-c", "demo-d")) { Remove-Profile $p }
    $null = Start-Server
    $srvProc = Get-Proc "Server_App"
    if (-not $srvProc -or -not (Test-Port9000)) {
        Write-Bad "中继服务器启动失败，请确认 9000 端口未被占用后重试"
        return
    }
    Write-Ok ("中继服务器已启动，PID " + $srvProc.Id)

    Write-Step 2 "依次启动 4 个客户端"
    $profiles = @("demo-a", "demo-b", "demo-c", "demo-d")
    $script:UProcs = @()
    $n = 0
    foreach ($pf in $profiles) {
        $n++
        $proc = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                              -ArgumentList "--profile", $pf -PassThru
        $script:UProcs += @{ Profile = $pf; Proc = $proc }
        Write-Info ("已启动第 " + $n + " 个客户端（档案 " + $pf + "）")
        Start-Sleep -Milliseconds 900
    }
    Start-Sleep -Seconds 3

    $info = Get-Clients
    $map = @{}
    $tagOf = @{ "demo-a" = "A"; "demo-b" = "B"; "demo-c" = "C"; "demo-d" = "D" }
    Write-Host ""
    foreach ($u in $script:UProcs) {
        $id = Get-IdByProc $info $u.Proc
        $map[$u.Profile] = $id
        if ($id -gt 0) { Write-Ok ("用户 " + $tagOf[$u.Profile] + "（档案 " + $u.Profile + "）已接入，服务器分配的 ID = " + $id) }
        else           { Write-Bad ("用户 " + $tagOf[$u.Profile] + "（档案 " + $u.Profile + "）未就绪") }
    }
    $bad = @($map.Values | Where-Object { $_ -le 0 })
    if ($bad.Count -gt 0) {
        Write-Bad "有客户端未能接入，请执行第 12 步清理后重试本步骤"
        return
    }

    Pause-Step "四个客户端均已接入，请注意屏幕上的四个窗口，按回车键开始交叉发送"

    Write-Step 3 "按不同组合交叉发送消息"
    # 发送前再确认一次号码：万一有客户端中途重连，按新号码继续，避免发到旧号
    $info = Get-Clients
    $changed = @()
    foreach ($u in $script:UProcs) {
        $cur = Get-IdByProc $info $u.Proc
        if ($cur -gt 0 -and $cur -ne $map[$u.Profile]) {
            $changed += ($tagOf[$u.Profile] + "：" + $map[$u.Profile] + " → " + $cur)
            $map[$u.Profile] = $cur
        }
    }
    if ($changed.Count -gt 0) {
        Write-Info ("检测到客户端重新连接，已按新号码继续：" + ($changed -join "，"))
    }

    $flows = @(
        @("demo-a", "demo-b", "多用户测试：A 发给 B"),
        @("demo-a", "demo-c", "多用户测试：A 发给 C"),
        @("demo-a", "demo-d", "多用户测试：A 发给 D"),
        @("demo-b", "demo-c", "多用户测试：B 发给 C"),
        @("demo-c", "demo-d", "多用户测试：C 发给 D"),
        @("demo-d", "demo-a", "多用户测试：D 发给 A")
    )
    foreach ($f in $flows) {
        $from = $map[$f[0]]
        $to   = $map[$f[1]]
        Write-Info ("用户 " + $from + " → 用户 " + $to + "：" + $f[2])
        [void](Send-Chat $info $from $to $f[2])
        Start-Sleep -Milliseconds 900
    }
    Start-Sleep -Seconds 2

    Write-Step 4 "逐一导出各客户端的聊天记录并核对归属"
    $expSent = @{}; $expRecv = @{}
    foreach ($pf in $profiles) { $expSent[$pf] = @(); $expRecv[$pf] = @() }
    foreach ($f in $flows) {
        $expSent[$f[0]] += $map[$f[1]]
        $expRecv[$f[1]] += $map[$f[0]]
    }

    Write-Host ""
    Write-Host ("    " + "客户端".PadRight(10) + "发送".PadRight(8) + "接收".PadRight(8) + "涉及对端 ID".PadRight(18) + "结论") -ForegroundColor DarkGray
    $allOk = $true
    foreach ($pf in $profiles) {
        $lines = Dump-History $pf $pf
        $sent = 0; $recv = 0; $peers = @{}
        foreach ($l in $lines) {
            $parts = $l -split "`t"
            if ($parts.Count -lt 3) { continue }
            if ($parts[1] -eq "1") { $sent++ } else { $recv++ }
            $peers[$parts[0]] = $true
        }
        $expectPeers = @(($expSent[$pf] + $expRecv[$pf]) | Sort-Object -Unique)
        $actualPeers = @($peers.Keys | Sort-Object)
        $ok = ($sent -eq $expSent[$pf].Count) -and ($recv -eq $expRecv[$pf].Count) -and
              (($actualPeers -join ",") -eq ($expectPeers -join ","))
        if (-not $ok) { $allOk = $false }

        $row = "    " + ($tagOf[$pf] + "（ID " + $map[$pf] + "）").PadRight(10) +
               ("$sent").PadRight(8) + ("$recv").PadRight(8) +
               ($actualPeers -join "、").PadRight(18) +
               $(if ($ok) { "与预期一致" } else { "与预期不符" })
        if ($ok) { Write-Host $row -ForegroundColor Green } else { Write-Host $row -ForegroundColor Red }
    }

    Write-Step 5 "查看中继服务器日志"
    $srvLog = Join-Path $TMPD "server.log"
    if (Test-Path $srvLog) {
        $srvLines = @(Get-Content $srvLog -Encoding UTF8)
        Write-Info ("日志共 " + $srvLines.Count + " 行，以下为最后 8 行：")
        $srvLines | Select-Object -Last 8 | ForEach-Object { Write-Host ("    " + $_) }
        if (($srvLines -join "`n") -match "多用户测试") { Write-Bad "服务器日志中出现明文" }
        else                                            { Write-Ok "服务器日志中只有字节数，无任何明文" }
    }

    $summary = "6 条交叉消息的发送、接收与涉及对端全部与预期一致。"
    if (-not $allOk) { $summary = "存在与预期不符的记录，请检查上面表格中标记为红色的一行。" }
    Write-Conclusion @(
        "四个用户两两建立独立会话，每一对通信使用各自协商的会话密钥，密钥不共享。",
        "导出结果中不存在不属于该用户会话的记录，说明中继按目标 ID 精确转发，未发生串话。",
        $summary
    )
}

function Step-Mitm {
    Write-Title "11 / 中间人攻击演示"
    Write-Purpose "演示中间人攻击为何可行，以及它的可检测点在哪里。"

    Write-Step 1 "停止正常服务，由攻击模拟程序占用 9000 端口"
    Stop-All
    Remove-Profile $PROF_M1
    Remove-Profile $PROF_M2

    if (Test-Port9000) {
        Write-Bad "9000 端口仍被占用（可能是之前遗留的进程），请执行第 12 步清理后重试"
        return
    }

    $log = Join-Path $TMPD "mitm.log"
    $null = Start-VisibleApp (Join-Path $EXE "MitmRelay.exe") $log "中间人攻击程序 MitmRelay（演示期间可观察截获内容）"
    Start-Sleep -Milliseconds 1200

    if (-not (Get-Proc "MitmRelay") -or -not (Test-Port9000)) {
        Write-Bad "攻击程序未能启动（端口占用或已被关闭），请执行第 12 步清理后重试"
        return
    }
    Write-Info "攻击程序已就位，并已弹出它自己的窗口；它会对两端分别发起一次握手。"

    Write-Step 2 "启动两个客户端（它们连接的是攻击程序，界面上没有异常）"
    $script:CA = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_M1 -PassThru
    Start-Sleep -Milliseconds 800
    $script:CB = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_M2 -PassThru
    Start-Sleep -Seconds 3

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "客户端未能接入，请执行第 12 步清理后重试本步骤"
        Stop-All
        return
    }
    Write-Ok ("两个客户端均显示正常连接：A 的 ID = " + $idA + "，B 的 ID = " + $idB)

    Pause-Step "请先观察两个窗口的标题与状态栏，按回车键继续发送消息"

    # 暂停期间若客户端重新连接，按新号码继续
    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "客户端已断开，请执行第 12 步清理后重试本步骤"
        Stop-All
        return
    }

    Write-Step 3 "发送两条消息"
    $sensitive = "card-password-is-123456"
    Write-Info ("用户 " + $idA + " 发送敏感内容：" + $sensitive)
    [void](Send-Chat $info $idA $idB $sensitive)
    Start-Sleep -Seconds 3
    Write-Info ("用户 " + $idB + " 回复：received-ok-meet-at-8pm")
    [void](Send-Chat $info $idB $idA "received-ok-meet-at-8pm")
    Start-Sleep -Seconds 3
    [void](Select-FirstSession $info[$idA].Wnd)
    [void](Select-FirstSession $info[$idB].Wnd)
    Start-Sleep -Milliseconds 500

    Write-Host ""
    Write-Host "  ── 客户端 A 的聊天区（消息正常显示） ──" -ForegroundColor DarkGray
    (Read-Chat $info[$idA].Wnd) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host ("    " + $_) }
    Write-Host "  ── 客户端 B 的聊天区（消息正常显示） ──" -ForegroundColor DarkGray
    (Read-Chat $info[$idB].Wnd) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host ("    " + $_) }
    Write-Info "两端都能正常收发，界面上没有任何告警。"

    Pause-Step "消息已正常送达，按回车键查看攻击者看到的内容"

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "客户端已断开，请执行第 12 步清理后重试本步骤"
        Stop-All
        return
    }

    Write-Step 4 "攻击程序视角：它解出的明文"
    $shown = 0
    if (Test-Path $log) {
        $lines = @(Get-Content $log -Encoding UTF8)
        $shown = $lines.Count
        $lines | ForEach-Object { Write-Host ("    " + $_) }
    } else {
        Write-Bad "未获取到攻击日志"
    }

    Write-Step 5 "唯一的破绽：两端的会话安全码不同"
    $sA = (Get-StatusLines $info[$idA].Wnd) -join " "
    $sB = (Get-StatusLines $info[$idB].Wnd) -join " "
    $sasA = ""; $sasB = ""
    if ($sA -match "安全码\s*(\d{6})") { $sasA = $Matches[1] }
    if ($sB -match "安全码\s*(\d{6})") { $sasB = $Matches[1] }

    Write-Host "  客户端 A 的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sA)
    Write-Host "  客户端 B 的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sB)
    Write-Host ""
    if ($sasA -and $sasB) {
        if ($sasA -ne $sasB) {
            Write-Ok ("两端安全码不同：A 看到 " + $sasA + "，B 看到 " + $sasB + "，核对一次即可发现攻击")
        } else {
            Write-Bad "两端安全码相同，演示环境异常，请执行第 12 步清理后重试"
        }
    } else {
        Write-Bad "未能读取到安全码，请确认两个客户端已完成握手"
    }

    Pause-Step "以上为本步骤的全部现象，按回车键结束演示并清理环境"

    Write-Step 6 "结束演示，清理环境"
    Stop-All
    Start-Sleep -Milliseconds 300

    if (Test-Path $log) {
        $lines2 = @(Get-Content $log -Encoding UTF8)
        if ($lines2.Count -gt $shown) {
            Write-Info "攻击日志补充输出："
            $lines2 | Select-Object -Skip $shown | ForEach-Object { Write-Host ("    " + $_) }
        }
    }

    # 演示用的指纹目录必须删除，否则下次连接正常服务器会因指纹不一致而被阻断
    Remove-Profile $PROF_M1
    Remove-Profile $PROF_M2
    $script:CA   = $null
    $script:CB   = $null
    $script:Mitm = $null
    Write-Ok "攻击模拟已结束，演示档案已清理"

    Write-Conclusion @(
        "中间人分别与两端完成握手，因此同时持有两把会话密钥，可以完整解密并转发，两端界面不会出现异常。",
        "唯一破绽是两次握手产生的报文不同，两端的安全码必然不同，核对一次即可发现。",
        "这说明加密与认证机制本身有效，剩余风险在于「对端是否为本人」，需要带外核对安全码（TOFU 信任模型）。"
    )
}

function Step-Clean {
    Write-Title "12 / 清理演示环境"
    Write-Purpose "结束后台进程并删除演示产生的身份与聊天记录。"
    Stop-All
    foreach ($p in $PROF_ALL) { Remove-Profile $p }
    Write-Ok "客户端与服务器进程已结束"
    Write-Ok "演示档案（demo-*）已删除，其他档案不受影响"
    Write-Info "若仍有个别窗口未关闭，可再次执行本步骤"
}

# ============================================================ 主循环 ====

function Show-Menu {
    Write-Host ""
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "    1   环境自检（程序文件 / 端口 / 进程状态）" -ForegroundColor White
    Write-Host "    2   编译工程" -ForegroundColor White
    Write-Host "    3   密码学与协议自测（28 项断言）" -ForegroundColor White
    Write-Host "    4   启动中继服务器" -ForegroundColor White
    Write-Host "    5   启动两个客户端" -ForegroundColor White
    Write-Host "    6   发送一条消息" -ForegroundColor White
    Write-Host "    7   查看会话安全码与密钥指纹" -ForegroundColor White
    Write-Host "    8   本地存储密文取证" -ForegroundColor White
    Write-Host "    9   掉线重连（ID 变化后历史仍连续）" -ForegroundColor White
    Write-Host "   10   多用户并发测试（四人同时在线）" -ForegroundColor White
    Write-Host "   11   中间人攻击演示" -ForegroundColor White
    Write-Host "   12   清理演示环境" -ForegroundColor White
    Write-Host "    0   退出" -ForegroundColor White
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  ECDHE 前向保密即时通信系统 —— 演示控制台" -ForegroundColor Cyan
Write-Host "  本控制台包含 12 个演示步骤，可按顺序执行，也可单独演示其中某一步。" -ForegroundColor DarkGray
Write-Host "  每一步执行完毕后按回车键返回主菜单，节奏由操作者掌握。" -ForegroundColor DarkGray
Write-Host "  建议演示顺序：1 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12" -ForegroundColor DarkGray

:menu while ($true) {
    Show-Header
    Show-Menu
    $choice = Read-Host "  请选择要执行的步骤编号"
    $choice = "$choice".Trim()

    switch ($choice) {
        "1"  { Step-Env;       Wait-Menu }
        "2"  { Step-Build;     Wait-Menu }
        "3"  { Step-Crypto;    Wait-Menu }
        "4"  { Step-Server;    Wait-Menu }
        "5"  { Step-Clients;   Wait-Menu }
        "6"  { Step-Send;      Wait-Menu }
        "7"  { Step-Sas;       Wait-Menu }
        "8"  { Step-Cipher;    Wait-Menu }
        "9"  { Step-Reconnect; Wait-Menu }
        "10" { Step-Multi;     Wait-Menu }
        "11" { Step-Mitm;      Wait-Menu }
        "12" { Step-Clean;     Wait-Menu }
        "0"  { break menu }
        default { Write-Host "  （无此编号，请输入 0 到 12 之间的数字）" -ForegroundColor DarkYellow }
    }
}

Write-Host ""
Write-Host "  已退出。若仍有后台进程，重新运行后执行第 12 步清理即可。" -ForegroundColor DarkGray
