# ============================================================================
#  ECDHE 前向保密聊天系统 —— 演示控制台
#
#  用法（在项目根目录打开 PowerShell）：
#      powershell -ExecutionPolicy Bypass -File Tools\demo.ps1
#
#  设计原则：
#    1. 菜单驱动：每一步都要手动输入编号触发，讲完一步按回车回到菜单，
#       节奏完全由讲解人控制，不会自动往下跑；
#    2. 每一步结束都打印「讲解要点」，提示这一步要展示什么、容易被打断时补哪句话；
#    3. 演示一律使用独立档案（demo-a / demo-b / demo-m1 / demo-m2），
#       不会碰你平时用的身份与聊天记录；菜单 11 可一键清理。
# ============================================================================

$ErrorActionPreference = "Stop"

# 子进程（CryptoTest / Server_App / MitmRelay）输出的是 UTF-8，这里让控制台按 UTF-8 解码
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

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

$PROF_A  = "demo-a"
$PROF_B  = "demo-b"
$PROF_M1 = "demo-m1"
$PROF_M2 = "demo-m2"

$script:Srv  = $null
$script:CA   = $null
$script:CB   = $null
$script:Mitm = $null

# ============================================================ 基础工具 ====

function Write-Title([string]$t) {
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor DarkGray
    Write-Host ("  " + $t) -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor DarkGray
}

function Write-Tip([string[]]$lines) {
    Write-Host ""
    Write-Host "  【讲解要点】" -ForegroundColor Yellow
    foreach ($l in $lines) { Write-Host ("   - " + $l) -ForegroundColor Gray }
}

function Write-Ok([string]$s)   { Write-Host ("  [OK]   " + $s) -ForegroundColor Green }
function Write-Bad([string]$s)  { Write-Host ("  [注意] " + $s) -ForegroundColor Red }
function Write-Info([string]$s) { Write-Host ("  " + $s) -ForegroundColor Gray }

function Wait-Menu {
    Write-Host ""
    [void](Read-Host "  —— 按回车返回菜单 ——")
}

function Get-Proc([string]$name) {
    return (Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Stop-All {
    Get-Process -Name ClientGUI_App,MitmRelay,Server_App -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 600
    $script:Srv  = $null
    $script:CA   = $null
    $script:CB   = $null
    $script:Mitm = $null
}

function Remove-Profile([string]$name) {
    $p = Join-Path $APPD $name
    Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
}

# 扫描当前所有客户端窗口，返回 "服务器ID -> 控件句柄" 的哈希表
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
            if     ($st -band 0x800)  { $chat = $e }      # ES_READONLY  -> 聊天区
            elseif ($st -band 0x2000) { $target = $e }    # ES_NUMBER    -> 收件人 ID
            elseif ($st -band 0x80)   { $input = $e }     # ES_AUTOHSCROLL -> 输入框
        }
        $res[$id] = @{ Wnd = $w; Chat = $chat; Target = $target; Input = $input; ProcId = $p.Id }
    }
    return $res
}

# 按进程 ID 找回该客户端当前的服务器 ID
function Get-IdByProc([hashtable]$info, $procObj) {
    if (-not $procObj) { return 0 }
    foreach ($k in $info.Keys) {
        if ($info[$k].ProcId -eq $procObj.Id) { return $k }
    }
    return 0
}

# 状态栏文本（「收件人 ID:」是静态标签，其余 Static 都是状态栏内容）
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
    return [D32]::Text($box)
}

# 在 fromId 的窗口里，把消息发给 toId 并点击「发送」
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
    if (Test-Path $file) { return (Get-Content $file -Encoding UTF8) }
    return @()
}

function Show-Header {
    $srv = Get-Proc "Server_App"
    $mitm = Get-Proc "MitmRelay"
    $ids = @()
    foreach ($p in (Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue)) {
        $p.Refresh()
        if ($p.MainWindowHandle -eq 0) { continue }
        $t = [D32]::Text($p.MainWindowHandle)
        if ($t -match '([0-9]+)\s*$') { $ids += $Matches[1] }
    }

    $s1 = if ($srv)  { "服务器 运行中" } else { "服务器 未启动" }
    $s2 = if ($mitm) { "MITM 运行中" }   else { "MITM 未启动" }
    $s3 = if ($ids.Count -gt 0) { "客户端 ID: " + ($ids -join ", ") } else { "客户端 未启动" }

    Write-Host ""
    Write-Host ("  当前状态：" + $s1 + " | " + $s2 + " | " + $s3) -ForegroundColor DarkCyan
}

# ============================================================ 各步骤 ====

function Step-Env {
    Write-Title "1 / 环境自检"

    $need = @("Server_App.exe", "ClientGUI_App.exe", "CryptoTest.exe", "MitmRelay.exe")
    $missing = 0
    foreach ($n in $need) {
        if (Test-Path (Join-Path $EXE $n)) { Write-Ok $n }
        else { Write-Bad ("缺少 " + $n); $missing++ }
    }
    if ($missing -gt 0) {
        Write-Host ""
        Write-Bad "请先在菜单 2 编译，或确认 build\Debug 目录存在"
        return
    }

    $busy = $false
    try {
        $busy = @(Get-NetTCPConnection -LocalPort 9000 -State Listen -ErrorAction SilentlyContinue).Count -gt 0
    } catch {
        $busy = ((netstat -ano | Select-String ":9000\s" -Quiet) -eq $true)
    }
    if ($busy) { Write-Bad "端口 9000 已被占用（可能是残留进程），菜单 11 可清理" }
    else       { Write-Ok "端口 9000 空闲" }

    $left = @(Get-Process -Name ClientGUI_App,MitmRelay,Server_App -ErrorAction SilentlyContinue)
    if ($left.Count -gt 0) { Write-Bad ("有 " + $left.Count + " 个残留进程，建议先执行菜单 11") }
    else                   { Write-Ok "无残留进程" }

    Write-Tip @(
        "这一步只是确认演示环境干净，几十秒即可",
        "重点说一句：所有演示都在本机，两个客户端用 --profile 隔离成两个「人」"
    )
}

function Step-Build {
    Write-Title "2 / 编译工程"
    Write-Info "cmake --build build --config Debug"
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

    Write-Tip @(
        "如果之前已经编译过，这一步会很快，属于「随时可跳过」的步骤",
        "想强调工程化时提一句：CMake + vcpkg 管理依赖，OpenSSL 静态链接，源码统一 /utf-8"
    )
}

function Step-Crypto {
    Write-Title "3 / 密码学与协议自测"
    Write-Info "CryptoTest.exe —— 覆盖 X25519、HKDF、AES-GCM、Ed25519、两种棘轮与完整握手"
    Write-Host ""

    $out = & (Join-Path $EXE "CryptoTest.exe") 2>&1
    foreach ($line in $out) { Write-Host ("  " + $line) }

    $all = ($out -join "`n")
    Write-Host ""
    if ($all -match "通过\s*(\d+)\s*项[，,]\s*失败\s*(\d+)\s*项") {
        if ($Matches[2] -eq "0") {
            Write-Ok ("全部断言通过：通过 " + $Matches[1] + " 项，失败 0 项")
        } else {
            Write-Bad ("有 " + $Matches[2] + " 项失败")
        }
    } else {
        Write-Bad "未解析到结果行，请人工确认"
    }

    Write-Tip @(
        "这 28 项里最值得点出来的是：篡改 AAD / 篡改密文 / 换密钥 都必须解密失败",
        "以及「完整握手 + 20 条消息 + 自动轮换」这条协议级用例，说明棘轮不是纸上设计",
        "被问到「怎么证明实现是对的」时，答案就是这一步"
    )
}

function Step-Server {
    Write-Title "4 / 启动中继服务器"

    if (Get-Proc "MitmRelay") {
        Write-Bad "MITM 中继正在占用 9000 端口，请先在菜单 10 结束后清理"
        return
    }
    if (Get-Proc "Server_App") {
        Write-Info "服务器已经在运行，无需重复启动"
        return
    }

    New-Item -ItemType Directory -Force -Path $TMPD | Out-Null
    $log = Join-Path $TMPD "server.log"
    Remove-Item $log -Force -ErrorAction SilentlyContinue

    $script:Srv = Start-Process -FilePath (Join-Path $EXE "Server_App.exe") `
                                -RedirectStandardOutput $log -PassThru
    Start-Sleep -Milliseconds 900
    Write-Ok ("服务器已启动，PID " + $script:Srv.Id + "，监听 9000")
    Write-Info ("日志：" + $log)

    Write-Tip @(
        "强调：服务器只是转发器，日志里只有字节数，看不到任何明文",
        "等一下演示完可以直接打开这个日志给大家看"
    )
}

function Step-Clients {
    Write-Title "5 / 启动两个客户端"

    if (-not (Get-Proc "Server_App")) {
        Write-Bad "请先执行菜单 4 启动服务器"
        return
    }

    if (Get-Proc "ClientGUI_App") {
        Write-Bad "已有客户端在运行，请先执行菜单 11 清理"
        return
    }

    Remove-Profile $PROF_A
    Remove-Profile $PROF_B

    $script:CA = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_A -PassThru
    Start-Sleep -Milliseconds 800
    $script:CB = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_B -PassThru
    Start-Sleep -Seconds 3

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB

    if ($idA -gt 0) { Write-Ok ("客户端 A 已连接，服务器 ID = " + $idA) } else { Write-Bad "客户端 A 未就绪" }
    if ($idB -gt 0) { Write-Ok ("客户端 B 已连接，服务器 ID = " + $idB) } else { Write-Bad "客户端 B 未就绪" }

    if ($idA -gt 0 -and $idB -gt 0) {
        Write-Host ""
        Write-Info ("接下来在 A 的窗口里填收件人 " + $idB + " 即可")
    }

    Write-Tip @(
        "两个客户端是两台机器上的两个真人，只是先用同一台机器演示",
        "ID 由服务器按接入顺序分配，所以每次演示都可能不同 —— 这正是后面要讲的问题"
    )
}

function Step-Send {
    Write-Title "6 / 发送一条消息"

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "请先执行菜单 5 启动两个客户端"
        return
    }

    $text = "这是一条端到端加密的消息"
    Write-Info ("A(ID " + $idA + ") -> B(ID " + $idB + ")：" + $text)
    [void](Send-Chat $info $idA $idB $text)
    Start-Sleep -Seconds 2

    Write-Host ""
    Write-Host "  ── A 的聊天区 ──" -ForegroundColor DarkGray
    (Read-Chat $info[$idA].Wnd) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host ("  " + $_) }
    Write-Host "  ── B 的聊天区 ──" -ForegroundColor DarkGray
    (Read-Chat $info[$idB].Wnd) -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host ("  " + $_) }

    Write-Tip @(
        "这条消息是 A 的客户端用会话密钥加密、B 的客户端解密后显示的",
        "注意 B 的聊天区没有任何「来自服务器」的痕迹 —— 服务器只可能改坏它，不可能读懂它"
    )
}

function Step-Sas {
    Write-Title "7 / 会话安全码与指纹核对"

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "请先执行菜单 5、6，让两个客户端建立会话"
        return
    }

    $sA = (Get-StatusLines $info[$idA].Wnd) -join " "
    $sB = (Get-StatusLines $info[$idB].Wnd) -join " "

    Write-Host "  A 的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sA)
    Write-Host "  B 的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sB)

    $sasA = ""; $sasB = ""
    if ($sA -match "安全码\s*(\d{6})") { $sasA = $Matches[1] }
    if ($sB -match "安全码\s*(\d{6})") { $sasB = $Matches[1] }

    Write-Host ""
    if ($sasA -and $sasB) {
        if ($sasA -eq $sasB) {
            Write-Ok ("两端安全码一致：" + $sasA + " —— 没有中间人")
        } else {
            Write-Bad ("两端安全码不一致：" + $sasA + " vs " + $sasB + " —— 存在中间人！")
        }
    } else {
        Write-Bad "还没建立会话，先发一条消息触发握手"
    }

    Write-Tip @(
        "安全码来自双方握手报文的哈希，中间人插不进同一段 transcript",
        "这句话直接对应菜单 10 的实验：被劫持时两端会看到不同的安全码"
    )
}

function Step-Cipher {
    Write-Title "8 / 本地密文取证"

    $chatDir = Join-Path (Join-Path $APPD $PROF_A) "chats"
    $logs = @(Get-ChildItem -Path $chatDir -Recurse -Filter *.log -ErrorAction SilentlyContinue)
    if ($logs.Count -eq 0) {
        Write-Bad "还没找到聊天记录，请先执行菜单 6 发一条消息"
        return
    }

    Write-Host "  磁盘上的记录文件（每行一条密文）：" -ForegroundColor DarkGray
    foreach ($f in $logs) { Write-Host ("    " + $f.FullName) }

    $raw = Get-Content $logs[0].FullName -Encoding UTF8 -Raw
    $first = ($raw -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1)
    Write-Host ""
    Write-Host "  文件里第一行长这样（十六进制，无明文）：" -ForegroundColor DarkGray
    Write-Host ("    " + $first.Substring(0, [Math]::Min(96, $first.Length)) + " ...")

    if ($raw -match "端到端加密") { Write-Bad "文件里出现了明文，存储加密失效！" }
    else                          { Write-Ok "文件里找不到任何明文，落盘内容是密文" }

    Write-Host ""
    Write-Host "  用受控导出接口解密（需要本机身份私钥，DPAPI 保护）：" -ForegroundColor DarkGray
    $dump = Dump-History $PROF_A "a"
    foreach ($l in $dump) { Write-Host ("    " + $l) }

    Write-Tip @(
        "同一条消息：磁盘上是 hex 密文，只有拿着本机身份派生的存储密钥才能解出明文",
        "存储密钥 = HKDF(Ed25519 私钥)，私钥又用 DPAPI 保护 —— 换账户、换机器都打不开",
        "如果时间不够，这一步可以只念结论，把文件路径展示一下就过"
    )
}

function Step-Reconnect {
    Write-Title "9 / 掉线重连：ID 变了，历史没断"

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) {
        Write-Bad "请先执行菜单 5、6"
        return
    }

    Write-Info ("B 当前 ID = " + $idB + "，现在强杀 B 的进程，模拟掉线")
    Stop-Process -Id $script:CB.Id -Force
    Start-Sleep -Milliseconds 900

    Write-Info "重新启动 B（同一个档案、同一份身份密钥）"
    $script:CB = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_B -PassThru
    Start-Sleep -Seconds 3

    $info = Get-Clients
    $idB2 = Get-IdByProc $info $script:CB
    if ($idB2 -le 0) { Write-Bad "B 未重新连接上"; return }

    Write-Host ""
    if ($idB2 -ne $idB) { Write-Ok ("B 拿到了新 ID：" + $idB + " -> " + $idB2) }
    else                { Write-Info ("B 仍拿到 ID " + $idB2) }

    $text = "重连之后我还在"
    Write-Info ("A 向新 ID " + $idB2 + " 再发一条：" + $text)
    [void](Send-Chat $info $idA $idB2 $text)
    Start-Sleep -Seconds 2

    Write-Host ""
    Write-Host "  A 的完整历史（导出）：" -ForegroundColor DarkGray
    foreach ($l in (Dump-History $PROF_A "a")) { Write-Host ("    " + $l) }

    $dumpA = Dump-History $PROF_A "a2"
    $peers = @($dumpA | Where-Object { $_ -match '\S' } | ForEach-Object { ($_ -split "`t")[0] } | Select-Object -Unique)
    Write-Host ""
    if ($peers.Count -eq 1) {
        Write-Ok ("两条消息都归在同一个联系人下（对端列 = " + ($peers -join ",") + "），历史没有被拆成两段")
    } else {
        Write-Bad ("历史被拆成了多个联系人：" + ($peers -join ","))
    }

    Write-Tip @(
        "服务器按接入顺序发号，同一个人重连就是新号码 —— 这是本设计的现实前提",
        "如果只按 ID 归档，这里就会变成两段历史；所以每条记录额外存了对端身份指纹，载入时按指纹合并",
        "顺带说明为什么不能直接改文件名：AAD 绑定了对端 ID，改名会让旧记录解不开"
    )
}

function Step-Mitm {
    Write-Title "10 / 中间人攻击演示"

    Write-Info "先停掉正常服务器与客户端，换成攻击者程序 MitmRelay 监听 9000"
    Stop-All
    Remove-Profile $PROF_M1
    Remove-Profile $PROF_M2

    New-Item -ItemType Directory -Force -Path $TMPD | Out-Null
    $log = Join-Path $TMPD "mitm.log"
    Remove-Item $log -Force -ErrorAction SilentlyContinue

    $script:Mitm = Start-Process -FilePath (Join-Path $EXE "MitmRelay.exe") `
                                 -RedirectStandardOutput $log -PassThru
    Start-Sleep -Milliseconds 900
    Write-Ok "攻击者已就位（两端都不知道）"

    $script:CA = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_M1 -PassThru
    Start-Sleep -Milliseconds 800
    $script:CB = Start-Process -FilePath (Join-Path $EXE "ClientGUI_App.exe") `
                               -ArgumentList "--profile", $PROF_M2 -PassThru
    Start-Sleep -Seconds 3

    $info = Get-Clients
    $idA = Get-IdByProc $info $script:CA
    $idB = Get-IdByProc $info $script:CB
    if ($idA -le 0 -or $idB -le 0) { Write-Bad "客户端未连上，请重试本步骤"; return }

    Write-Info ("两个客户端都以为连的是真服务器：" + $idA + " <-> " + $idB)
    $sensitive = "card-password-is-123456"
    Write-Info ("A 发送敏感内容：" + $sensitive)
    [void](Send-Chat $info $idA $idB $sensitive)
    Start-Sleep -Seconds 2
    [void](Send-Chat $info $idB $idA "received-ok-meet-at-8pm")
    Start-Sleep -Seconds 2

    $sA = (Get-StatusLines $info[$idA].Wnd) -join " "
    $sB = (Get-StatusLines $info[$idB].Wnd) -join " "

    Write-Host ""
    Write-Host "  A 看到的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sA)
    Write-Host "  B 看到的状态栏：" -ForegroundColor DarkGray
    Write-Host ("    " + $sB)

    $sasA = ""; $sasB = ""
    if ($sA -match "安全码\s*(\d{6})") { $sasA = $Matches[1] }
    if ($sB -match "安全码\s*(\d{6})") { $sasB = $Matches[1] }

    Write-Host ""
    if ($sasA -and $sasB) {
        if ($sasA -ne $sasB) {
            Write-Ok ("骗局暴露点：两端安全码不同 —— A 看到 " + $sasA + "，B 看到 " + $sasB)
        } else {
            Write-Bad "两端安全码竟然相同，演示环境可能有问题"
        }
    }

    Stop-Process -Id $script:Mitm.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Get-Process -Name ClientGUI_App -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 300

    Write-Host ""
    Write-Host "  攻击者视角（MitmRelay 的输出）：" -ForegroundColor DarkGray
    if (Test-Path $log) {
        Get-Content $log -Encoding UTF8 | ForEach-Object { Write-Host ("    " + $_) }
    } else {
        Write-Bad "没有拿到攻击日志"
    }

    # 演示用的指纹目录必须删掉，否则下次连真服务器会因指纹不一致被阻断
    Remove-Profile $PROF_M1
    Remove-Profile $PROF_M2
    $script:CA = $null
    $script:CB = $null
    $script:Mitm = $null

    Write-Tip @(
        "中间人分别和两端握手，所以它手里有两把会话密钥，能完整解密转发，双方界面毫无异常",
        "唯一的破绽是：两次握手产生两段不同的 transcript，安全码必然不同",
        "结论是 TOFU 模型的边界 —— 加密本身没问题（签名防篡改），但「对面是不是本人」必须靠带外核对"
    )
}

function Step-Clean {
    Write-Title "11 / 一键清理"
    Stop-All
    foreach ($p in @($PROF_A, $PROF_B, $PROF_M1, $PROF_M2)) { Remove-Profile $p }
    Write-Ok "进程已结束，演示档案已删除"
    Write-Info "你平时使用的档案（不带 demo- 前缀）没有被触碰"
}

# ============================================================ 主循环 ====

function Show-Menu {
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "   1  环境自检（可执行文件 / 端口 / 残留进程）" -ForegroundColor White
    Write-Host "   2  编译工程" -ForegroundColor White
    Write-Host "   3  密码学与协议自测（28 项断言）" -ForegroundColor White
    Write-Host "   4  启动中继服务器" -ForegroundColor White
    Write-Host "   5  启动两个客户端（档案 demo-a / demo-b）" -ForegroundColor White
    Write-Host "   6  发送一条消息" -ForegroundColor White
    Write-Host "   7  查看会话安全码与密钥指纹" -ForegroundColor White
    Write-Host "   8  本地密文取证（磁盘密文 vs 解密导出）" -ForegroundColor White
    Write-Host "   9  掉线重连（ID 变了，历史仍归并）" -ForegroundColor White
    Write-Host "  10  中间人攻击演示（两端安全码不一致）" -ForegroundColor White
    Write-Host "  11  一键清理" -ForegroundColor White
    Write-Host "   0  退出" -ForegroundColor White
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  ECDHE 前向保密聊天系统 —— 演示控制台" -ForegroundColor Cyan
Write-Host "  建议顺序：1 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11" -ForegroundColor DarkGray
Write-Host "  每步结束后按回车回到菜单，节奏由你控制" -ForegroundColor DarkGray

:menu while ($true) {
    Show-Header
    Show-Menu
    $choice = Read-Host "  请输入编号"
    $choice = "$choice".Trim()

    switch ($choice) {
        "1"  { Step-Env;        Wait-Menu }
        "2"  { Step-Build;      Wait-Menu }
        "3"  { Step-Crypto;     Wait-Menu }
        "4"  { Step-Server;     Wait-Menu }
        "5"  { Step-Clients;    Wait-Menu }
        "6"  { Step-Send;       Wait-Menu }
        "7"  { Step-Sas;        Wait-Menu }
        "8"  { Step-Cipher;     Wait-Menu }
        "9"  { Step-Reconnect;  Wait-Menu }
        "10" { Step-Mitm;       Wait-Menu }
        "11" { Step-Clean;      Wait-Menu }
        "0"  { break menu }
        default { Write-Host "  （无此编号，请输入 0-11）" -ForegroundColor DarkYellow }
    }
}

Write-Host ""
Write-Host "  已退出。如果还有进程在跑，重新运行后按 11 清理。" -ForegroundColor DarkGray
