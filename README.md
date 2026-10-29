# ECDHE 前向保密即时通信系统

C++17 · Win32 · OpenSSL 3.x · Boost.Asio

端到端加密的桌面聊天系统。会话密钥由 X25519 临时密钥交换协商，中继服务器只转发密文帧、不持有任何密钥。在会话密钥之上叠加消息级密钥棘轮与周期性 DH 棘轮，同时具备前向保密与后向恢复能力。

## 主要特性

- **端到端加密**：X25519 ECDHE 协商密钥，HKDF-SHA256 按用途域分离派生，AES-256-GCM 加密记录；会话号、序号与收发方作为 AAD 参与认证。
- **前向保密**：会话密钥只由一次性临时私钥派生，长期身份密钥不参与密钥派生；消息级链棘轮使每条消息使用独立密钥。
- **后向恢复**：每 8 条消息轮换一次 DH 棘轮，引入新的 X25519 熵并销毁旧私钥。
- **可验证身份**：Ed25519 对握手报文签名；握手完成后双方由 transcript 派生 6 位安全码；对端身份公钥首次通信即固定（TOFU），指纹变化直接阻断。
- **不可信中继**：服务器只做按 ID 转发、心跳应答与超时回收，无法解密，也无法在不被发现的前提下篡改。
- **本地安全**：身份私钥经 Windows DPAPI 加密；聊天记录经 AES-256-GCM 加密后落盘。
- **工程健壮性**：心跳保活与自动重连、帧长上限、每连接写锁、多档案隔离。

## 系统结构

| 层 | 模块 | 职责 | 规模 |
|---|---|---|---|
| 密码学 | `Common/crypto_utils.h` | X25519、HKDF-SHA256、AES-256-GCM、Ed25519、密钥清零 | 371 行 |
| 协议 | `Common/protocol.h` | 帧格式、消息类型、AAD 构造、编解码 | 111 行 |
| 协议 | `Common/secure_session.h` | 三报文握手、密钥调度、消息级棘轮、DH 棘轮、安全码 | 515 行 |
| 中继 | `Server/server.cpp` | 连接管理、按 ID 路由、写完加锁、心跳应答、超时回收 | 238 行 |
| 客户端 | `ClientGUI/ClientGUI.cpp` | Win32 界面、会话管理、加密持久化、自动重连 | 1222 行 |
| 测试 | `Tests/crypto_selftest.cpp` | 28 项密码学与协议断言 | 235 行 |
| 工具 | `Tools/mitm_relay.cpp` | 中间人测试工具（复用同一套 `SecureSession`） | 357 行 |

依赖方向是单向的：应用层依赖协议层，协议层依赖密码学层，反向不成立。因此协议层既能被客户端使用，也能被测试工具直接复用——中间人测试的可信度正来自这一点。

## 协议

### 帧格式

TCP 是字节流，协议自带消息边界：

```
[ uint32 长度 ][ uint32 目标/来源 ID ][ 载荷 ]
```

载荷首字节为版本号，第二字节为类型：

| 类型 | 值 | 载荷长度 | 说明 |
|---|---|---|---|
| `HS_INIT` | 0x01 | 162 | 握手请求：pubA、nonceA、idpubA、双方 ID、Sig_A |
| `HS_RESP` | 0x02 | 186 | 握手响应：pubB、nonceB、idpubB、Sig_B、MAC_B |
| `HS_CONFIRM` | 0x03 | 42 | 握手确认：MAC_A |
| `REKEY` | 0x04 | 18 + 32 + 16 | DH 棘轮轮换，在加密通道内传输新公钥 |
| `DATA` | 0x10 | 18 + 密文 + 16 | 加密聊天数据 |
| `PING` / `PONG` | 0x20 / 0x21 | 2 | 心跳，目标 ID 为 0，不参与转发 |
| `SYSTEM` | 0xFF | 6 + 文本 | 服务器提示（如目标不在线），明文 |

长度字段同时是防御点：小于 4 或大于 1 MiB 立即断开连接，避免单个字段耗尽内存。

**AAD** = `ver‖type‖sid‖seq‖sender‖target`（26 字节）。中继无法在不解密的情况下改动会话号、序号或收发方。

### 握手

```
A                    中继服务器                    B
│  ① HS_INIT(162B)  ─────  原样转发  ─────▶  │
│                                              │ 验签 SigA，生成临时密钥
│  ◀────  原样转发  ─────  ② HS_RESP(186B)   │ 计算 Z，派生双向链密钥
│  验签 SigB、验 MAC_B                          │
│  ③ HS_CONFIRM(42B) ─────  原样转发  ─────▶  │ 验 MAC_A → 建立
```

- `pubA / pubB`：本次会话新生成的 X25519 临时公钥，握手结束后的首次轮换即销毁；
- `Sig_A / Sig_B`：Ed25519 长期身份私钥对报文的签名，只负责认证，不参与密钥派生；
- `MAC_A / MAC_B`：用 `finished_key` 对握手 transcript 做 HMAC-SHA256，用于密钥确认。

签名覆盖范围是防篡改的关键。`Sig_A` 覆盖帧头、`pubA`、`nonceA`、`idpubA` 与双方 ID；`Sig_B` 覆盖 INIT 摘要与 RESP 前 90 字节，把响应绑定到本次请求，报文无法被拼接或跨会话重放。

### 密钥派生

```
Z        = X25519(临时私钥, 对端临时公钥)
secret   = HKDF-SHA256(Z, salt = nonceA‖nonceB, info = "CHAT-v1 ECDHE X25519")
chainI2R = HKDF(secret, "", "chain initiator->responder")
chainR2I = HKDF(secret, "", "chain responder->initiator")
finished = HKDF(secret, "", "finished key")
root     = HKDF(secret, "", "root key")          // DH 棘轮起点
```

收发两个方向、消息密钥、Finished 密钥与根密钥各用一个 info 标签派生，互不相关。中间值在派生出下一层后立即用 `OPENSSL_cleanse` 覆盖。

握手完成后，双方对同一份 transcript 再做一次带标签的哈希，取前 4 字节对 10⁶ 取模，得到 6 位安全码。

### 记录层与棘轮

每条消息先由链密钥派生出消息密钥与 nonce，再用 HKDF 推进链密钥并覆盖旧值：

```
msg_key = HKDF(chain, "", "message key")
nonce   = HKDF(chain, "", "message iv")
chain'  = HKDF(chain, "", "chain next")
```

链只能单向推进，因此当前链密钥无法还原历史消息密钥，即消息级前向保密。

在消息级棘轮之上叠加 DH 棘轮：每发送 8 条消息，发送方生成新的 X25519 密钥对，用**旧链**加密一条 `REKEY` 帧携带新公钥；双方随后以 `root' = HKDF(ikm = DH(新私钥, 对端棘轮公钥), salt = root)` 更新根密钥、重建双向链，发送方旧私钥被覆盖销毁。攻击者即使窃取了某一时刻的棘轮私钥，下一次轮换后也无法继续推导新密钥。

## 安全属性与边界

| 威胁 | 结论 | 依据 |
|---|---|---|
| 链路被动窃听 | 可防 | 全流程 AEAD，抓包只能得到长度与密文 |
| 服务器解密 | 可防 | 服务器不持有任何密钥 |
| 篡改密文或帧头 | 可防 | 帧头作为 AAD 参与认证 |
| 重放旧报文 | 可防 | 序号严格单调，失步即作废 |
| 跨会话重放握手 | 可防 | 签名覆盖 sid 与双方 ID，RESP 绑定 Sig_A |
| 事后长期私钥泄露 | 可防 | 会话密钥只由临时私钥派生 |
| 当前棘轮密钥被窃取 | 可防（一次轮换后） | 每 8 条消息轮换并销毁旧私钥 |
| 首次接触的中间人 | 可发现，不能自动阻止 | 签名保证未被篡改，身份需安全码核对 |
| 通信关系（元数据） | 不可防 | 中继必须知道目标 ID 才能转发 |
| 终端被控制 | 超出范围 | 端到端加密不防护端点 |

前向保密的论证可以直接用攻击者的视角写：假设攻击者拿到全部长期与当前状态并回放历史密文，他要恢复某条历史消息，就必须得到当时的消息密钥；消息密钥只由当时的链密钥派生，而链只能正向推进，HKDF 的单向性使他无法反向计算。若绕过链密钥去重算当时的 X25519，对应的临时私钥在握手结束或上一轮轮换时就已被覆盖销毁。两条路径都走不通。

## 构建

依赖 Visual Studio 2022（MSVC 19.3x）、CMake ≥ 3.20、vcpkg 提供的 OpenSSL 3.x 与 Boost.Asio。

```bash
vcpkg install openssl:x64-windows boost-asio:x64-windows

cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Debug
```

产物为 `Server_App.exe`、`ClientGUI_App.exe`、`CryptoTest.exe` 与 `MitmRelay.exe`。

部分构建约束：Boost 需以 `find_package(Boost CONFIG REQUIRED COMPONENTS system)` 引入（CMake 4 已移除 `FindBoost` 模块）；源码以 `/utf-8` 编译并统一使用宽字符 API；OpenSSL 静态链接时不可使用 `PEM_*(FILE*)`，身份密钥的读写走内存 BIO。

## 使用

1. 启动 `build/Debug/Server_App.exe`，监听 9000 端口；
2. 启动一个或多个 `build/Debug/ClientGUI_App.exe`，窗口标题会显示分配到的 ID；
3. 在“收件人 ID”里填写对方 ID 后输入消息发送。

同一台机器上可以运行多个客户端，用 `--profile` 区分档案，各自的身份、历史与指纹目录完全独立：

```bash
ClientGUI_App.exe --profile alice
ClientGUI_App.exe --profile bob
```

聊天记录可用 `--dump` 在本地解密导出：

```bash
ClientGUI_App.exe --profile alice --dump D:\backup\alice.txt
```

界面分为四块：左侧会话列表（含未读标记）、中间聊天区、底部输入行、底部状态栏。握手进度、安全码、指纹、断线等信息只写入状态栏，聊天区只保留消息内容。

## 测试

**密码学与协议自测（28 项）**

```bash
build/Debug/CryptoTest.exe
```

覆盖 Ed25519 签名与验签、PEM 持久化、X25519 一致性、每次握手共享秘密互不相同、HKDF 域分离、GCM 对 AAD/密文/密钥的篡改检测、两种棘轮的同步，以及“完整握手 + 20 条消息 + 两次自动轮换”的协议级用例。

**端到端自动化**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Tools\smoke_test.ps1
```

脚本启动一个服务器与两个客户端，驱动界面互发消息，再用受控导出比对双方历史。服务器侧日志只包含字节数：

```
[中继] 1 -> 2 转发 162 字节（内容不可解密）
[中继] 2 -> 1 转发 186 字节（内容不可解密）
[中继] 1 -> 2 转发 42  字节（内容不可解密）
[中继] 1 -> 2 转发 53  字节（内容不可解密）
```

**中间人测试**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Tools\mitm_demo.ps1
```

`MitmRelay` 冒充中继服务器，与通信双方各自完成一次握手，因此同时握有两把会话密钥。输出如下（安全码每次运行都不同）：

```
[MITM] 已冒充用户 2 接受用户 1 的握手
[MITM] 已冒充用户 1 向用户 2 发起握手
[MITM] 欺骗成功：两端都显示“加密会话已建立”
[MITM] 但两端的安全码不同：用户 1 看到 079293，用户 2 看到 144243
[截获] 1 -> 2 明文: card-password-is-123456
[抓包]   密文 39 字节，前 16 字节 8f1e95664a5770afdf1a0dbfebec1aa5
```

不加核对时，中间人可以完整解密并转发，双方毫无察觉；核对一次安全码即可发现——两段独立握手必然产生两份不同的 transcript。这是 TOFU 模型的固有边界，与 Signal 的安全码机制一致。

> 测试结束后需关闭 `MitmRelay` 并重新启动 `Server_App`；若曾被中间人污染过 `pins` 目录，删除该目录即可重置信任。

## 数据存储

| 路径 | 内容 |
|---|---|
| `%APPDATA%\ECDHE_Chat\profiles\<name>\identity.pem` | Ed25519 长期身份私钥，DPAPI 加密 |
| `...\chats\<本地身份指纹>\<对端 ID>.log` | 聊天记录，每行一条 AES-256-GCM 密文（`hex(nonce‖ct‖tag)`） |
| `...\pins\<本地身份指纹>.log` | 已固定的对端身份公钥（TOFU） |

归档目录用身份指纹而不是服务器分配的 ID：ID 是临时的，重启即变，身份密钥才是持久的。聊天记录的 AAD 绑定对端 ID，防止记录被张冠李戴地拼接。

## 已知限制

- 未提供登录体系，客户端 ID 由服务器按接入顺序分配；
- 不支持乱序与丢帧恢复：序号失步会重置会话，下次发送时重新握手；
- DH 棘轮采用周期性轮换（每 8 条消息），而非每条消息携带 DH 头，因此没有 skipped-key 缓存；
- 身份私钥经 DPAPI 加密，只在本机本用户下可解密，换机器或换账户会导致身份重新生成、历史无法解密；
- 尚未实现离线消息、群聊、文件传输与消息分片，超过 64 KB 的单条消息会被拒绝；
- 元数据（谁在何时与谁通信）对中继可见。

## 目录结构

```
├── CMakeLists.txt
├── Common/
│   ├── crypto_utils.h
│   ├── protocol.h
│   └── secure_session.h
├── Server/
│   └── server.cpp
├── ClientGUI/
│   └── ClientGUI.cpp
├── Tests/
│   └── crypto_selftest.cpp
├── Tools/
│   ├── mitm_relay.cpp
│   ├── mitm_demo.ps1
│   └── smoke_test.ps1
└── docs/
    ├── report.md
    ├── figures/
    ├── 专业程序设计报告-成员A-密码协议方向.docx
    └── 专业程序设计报告-成员B-网络与工程化方向.docx
```

`ClientGUI/ClientGUI.vcxproj` 与 `Server/Server.vcxproj` 为早期手写工程，已不再使用，构建请统一走 CMake。
