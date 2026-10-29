# 基于 ECDHE 的前向保密聊天工具

> 《专业课程设计》— 网络信息安全方向  题目十九

一个用 C++17 实现的端到端加密（E2EE）聊天工具：**每次会话都用 X25519 临时密钥做 ECDHE 密钥交换**，派生独立的会话密钥，并用 AES-256-GCM 加密聊天内容。中继服务器不持有任何密钥，即使服务器被攻破也无法解密历史与实时消息。

---

## 1. 安全设计

### 1.1 威胁模型

| 攻击者能力 | 系统响应 |
|---|---|
| 被动窃听链路（抓包） | 只能看到密文、帧长度和收发关系 |
| 攻破中继服务器 | 服务器无密钥，无法解密；也无法篡改（会破坏 AEAD 认证） |
| 主动中间人（MITM） | 握手时用 Ed25519 签名验证对端临时公钥，签名不符立即中止并告警 |
| 重放/篡改/乱序 | 帧头（会话号 + 序号 + 收发方）作为 AAD 参与认证，序号严格单调 |
| **日后长期主密钥泄露** | 会话密钥只由**临时**私钥派生，历史会话无法被还原（前向保密） |

### 1.2 握手流程（自研 TLS 1.3 风格）

```mermaid
sequenceDiagram
    participant A as 客户端 A (发起方)
    participant R as 中继服务器
    participant B as 客户端 B (响应方)

    A->>R: INIT  ver|sid|pubA|nonceA|idpubA|idA|idB|Sig_A
    R->>B: 原样转发（无法解密/伪造）
    B->>R: RESP  ver|sid|pubB|nonceB|idpubB|Sig_B|MAC_B
    R->>A: 原样转发
    A->>R: CONFIRM ver|sid|MAC_A
    R->>B: 原样转发
    Note over A,B: 会话建立，双向 AES-256-GCM 加密通信
```

- `pubA / pubB`：**本次会话新生成**的 X25519 临时公钥（32 字节）
- `Sig_A / Sig_B`：Ed25519 **长期身份私钥**对握手报文的签名（只认证、不参与密钥派生）
- `MAC_A / MAC_B`：用 `finished_key` 对握手 transcript 做 HMAC-SHA256，证明双方派生出相同会话密钥

### 1.3 密钥调度

```
Z       = X25519(临时私钥, 对端临时公钥)                  // 每次会话都不同
secret  = HKDF-SHA256(Z, salt = nonceA‖nonceB, "CHAT-v1 ECDHE X25519")
chainI2R= HKDF(secret, "", "chain initiator->responder")   // 方向 1 的链密钥
chainR2I= HKDF(secret, "", "chain responder->initiator")   // 方向 2 的链密钥
finish  = HKDF(secret, "", "finished key")                // 握手确认用
```

**域分离**：收发两个方向使用不同链密钥，避免同一把密钥双向复用。

### 1.4 消息级密钥棘轮

每条消息发送前：

```
msg_key = HKDF(chain, "", "message key")
nonce   = HKDF(chain, "", "message iv")
chain'  = HKDF(chain, "", "chain next")     // 立即丢弃旧 chain
```

由此获得**消息级前向保密**：即使当前链密钥被攻破，也无法还原此前消息的密钥。

### 1.5 三次“前向保密”论证（答辩要点）

1. **握手临时化**：每次会话的 X25519 密钥对都用完即毁（`s.eph.reset()`），事后无从还原共享秘密；
2. **身份密钥隔离**：长期 Ed25519 私钥只负责签名，从不参与密钥派生 → 主密钥泄露不影响历史会话；
3. **链密钥推进**：消息密钥随棘轮前进并被覆盖，历史消息密钥不可恢复。

---

## 2. 帧格式

TCP 上每条消息：

```
[ uint32 长度 ][ uint32 目标/来源 ID ][ 载荷 ]
```

载荷首字节为版本，第二字节为类型：

| 类型 | 值 | 长度 | 说明 |
|---|---|---|---|
| `HS_INIT` | 0x01 | 162 | 握手请求 |
| `HS_RESP` | 0x02 | 186 | 握手响应（含签名 + MAC_B） |
| `HS_CONFIRM` | 0x03 | 42 | 握手确认（MAC_A） |
| `DATA` | 0x10 | 18 + 密文 + 16 | `sid|seq|AES-256-GCM(明文, AAD)` |
| `SYSTEM` | 0xFF | — | 服务器提示（如“用户不在线”），明文 |

**AAD** = `ver|type|sid|seq|sender|target`（26 字节）——中继服务器无法在不解密的情况下篡改会话号、序号或收发方。

---

## 3. 目录结构

```
├── CMakeLists.txt
├── Common/
│   ├── crypto_utils.h      # OpenSSL 封装：X25519 / HKDF / AES-GCM / Ed25519
│   └── protocol.h          # 协议常量、编解码、AAD 构造
├── Server/
│   └── server.cpp          # 不可信中继：按 ID 转发，不持密钥
├── ClientGUI/
│   └── ClientGUI.cpp       # Win32 GUI + 会话管理 + 握手/棘轮
├── Tests/
│   └── crypto_selftest.cpp # 密码学自测（19 项）
└── Tools/
    └── smoke_test.ps1      # 端到端自动化测试（服务器 + 两个客户端）
```

> 说明：`ClientGUI/ClientGUI.vcxproj`、`Server/Server.vcxproj` 与各自 `x64/` 目录是早期的 Visual Studio 手写工程，**已不再使用**，请统一用 CMake 构建，避免编译到旧代码。

---

## 4. 构建与运行

依赖：Visual Studio 2022、CMake ≥ 3.20、vcpkg（`openssl`、`boost-asio`）。

```bash
vcpkg install openssl:x64-windows boost-asio:x64-windows
```

用 VS Code 的 CMake Tools 直接构建，或：

```bash
cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Debug
```

运行：

1. 启动 `build/Debug/Server_App.exe`（监听 9000）；
2. 启动一个或多个 `build/Debug/ClientGUI_App.exe`；
3. 窗口标题会显示自己分配到的 ID；在左侧会话列表里点选联系人，或在“收件人 ID”里填对方 ID，输入消息回车发送。

界面说明：

| 区域 | 作用 |
|---|---|
| 左侧会话列表 | 按对端用户分组，未读消息显示红点 `●`；点击切换会话 |
| 中间聊天区 | 只显示聊天内容，格式为 `[时:分] 我: …` / `[时:分] 用户N: …` |
| 底部输入行 | 收件人 ID + 消息输入框 + 发送按钮（Enter 发送） |
| 底部状态栏 | 连接状态、握手进度、会话密钥指纹、错误提示（红色） |

握手、指纹、断线重连等过程信息全部只出现在状态栏，不会污染聊天记录。例如建立会话后状态栏显示：

```
与用户 2 的安全会话已建立 · 密钥指纹 8b1e07a4
```

发送给不在线用户时，聊天区会出现 `⚠ 用户 N 不在线，1 条消息未送达`，状态栏同时变红提示。

### 数据存放位置

| 文件 | 说明 |
|---|---|
| `%APPDATA%\ECDHE_Chat\identity.pem` | 长期身份私钥（Ed25519），重启后保持不变 |
| `%APPDATA%\ECDHE_Chat\chats\<本地ID>\<对端ID>.log` | 按会话分文件的聊天记录，重启自动重载并自动选中最近会话 |

路径均使用宽字符 API，支持中文用户名。聊天记录按“本地实例”分目录存放，同一台机器上同时运行两个客户端也不会互相串记录。

---

## 5. 验证

### 5.1 密码学自测（19 项）

```bash
build/Debug/CryptoTest.exe
```

覆盖：Ed25519 签名与验签、PEM 持久化、X25519 一致性、**每次握手共享秘密不同**、HKDF 域分离、GCM 篡改检测（AAD/密文/密钥）、棘轮同步与历史密钥不可恢复。

### 5.2 端到端自动化测试

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Tools\smoke_test.ps1
```

脚本会启动 1 个服务器 + 2 个客户端，驱动界面互发消息，并校验双方都能解密显示。典型服务器日志：

```
[中继] 1 -> 2 转发 162 字节（内容不可解密）   ← HS_INIT
[中继] 2 -> 1 转发 186 字节（内容不可解密）   ← HS_RESP
[中继] 1 -> 2 转发 42  字节（内容不可解密）   ← HS_CONFIRM
[中继] 1 -> 2 转发 53  字节（内容不可解密）   ← 加密消息
[中继] 2 -> 1 转发 51  字节（内容不可解密）   ← 加密消息
```

### 5.3 前向保密演示

1. 抓包可见两次连接的 32 字节公钥完全不同，密文完全不同；
2. 删除 `identity.pem`（模拟“主密钥泄露”）后重启，历史密文依旧无法解密；
3. 每次握手打印的“会话密钥指纹”互不相同。

---

## 6. 已知限制

- 客户端 ID 由服务器按接入顺序分配，无登录体系；对端身份的信任采用**本次运行内 TOFU**（首次见面即固定指纹），生产环境应做持久化 + 指纹核对；
- 聊天记录按“服务器分配的本地 ID”分目录，若服务器重启后客户端拿到的 ID 与上次不同，历史记录会归入新的目录；
- 一条 TCP 连接是单一有序流，若丢帧（如对端不在线）会导致棘轮失步，此时会话自动作废、下次发送时重新握手；
- 聊天记录以明文保存在本地（不属于传输层威胁模型），如需本地加密可后续扩展；
- 同一台机器上多个客户端共用同一 `identity.pem`（同一安装实例），部署到多机时天然独立。
