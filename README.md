# ECDHE-Secured Chat System (PFS-IM)

> **《专业课程设计》- 网络信息安全方向**
> 题目：基于 ECDHE 的前向保密的聊天工具的实现

## 📖 项目简介
本项目是一个基于 C++ 开发的端到端安全即时通讯系统。针对传统通信中长期密钥泄露导致历史数据被窃听的风险，本项目引入 **ECDHE (椭圆曲线迪菲-赫尔曼临时密钥交换)** 与 **AES-256-GCM** 算法，实现了具备**完美前向保密 (Perfect Forward Secrecy, PFS)** 特性的安全通信通道。

## ✨ 核心特性
- **🔒 完美前向保密 (PFS)**：每次连接均使用 X25519 曲线动态生成临时会话密钥，即使长期主密钥泄露，历史聊天记录依然安全。
- **🛡️ 端到端加密传输**：应用层数据全部采用 AES-256-GCM 算法进行加密，防止中间人窃听。
- **✅ 数据完整性校验**：利用 GCM 模式的认证标签 (Tag) 机制，有效防止密文在传输过程中被篡改。
- **⚡ 高性能异步 I/O**：基于 Boost.Asio 网络库构建，保障高并发下的数据传输效率。
- **🧩 模块化设计**：网络层与密码学层解耦，具备良好的可扩展性。

## 🛠️ 技术栈
- **开发语言**：C++17
- **网络通信**：Boost.Asio (Socket 编程)
- **密码学库**：OpenSSL 3.x (EVP API)
- **开发环境**：Visual Studio 2022 / vcpkg 包管理器

## 🏗️ 核心架构与通信流程
系统采用经典的 C/S (Client-Server) 架构，一次完整的加密通信握手流程如下：
1. **Client** 启动，生成基于 X25519 的临时公私钥对，并将公钥发送给 Server。
2. **Server** 接收公钥，同样生成临时公私钥对，将公钥回传给 Client。
3. 双方利用各自的私钥和对端公钥，通过 ECDHE 算法计算出相同的共享密钥 (Shared Secret)。
4. 双方使用 KDF 派生出 256 位的 AES 会话密钥。
5. 后续聊天数据经 `IV + AES-GCM(明文) + Tag` 封装后，通过 TCP 进行安全传输。

## 🚀 编译与运行指南

### 1. 环境依赖
请确保你的电脑上已安装 `vcpkg`，并安装了以下依赖：
```bash
vcpkg install openssl:x64-windows
vcpkg install boost-asio:x64-windows

2. 项目配置 (Visual Studio)

    使用 VS 2022 克隆本仓库。

    打开 Client 和 Server 的项目属性。

    在 C/C++ -> 常规 -> 附加包含目录 中添加：
    你的vcpkg路径\installed\x64-windows\include

    在 链接器 -> 常规 -> 附加库目录 中添加：
    你的vcpkg路径\installed\x64-windows\lib

    在 C/C++ -> 预处理器 中添加 _WIN32_WINNT=0x0A00。

3. 运行测试

    右键 Server 项目，选择“设为启动项目”，按 F5 运行，等待监听 9000 端口。

    右键 Client 项目，选择“设为启动项目”，按 F5 运行。

    观察控制台输出 ✅ ECDHE 握手完成，即可开始加密通信。

📂 项目结构
text

├── Client/               # 客户端项目 (包含主函数与网络逻辑)
├── Server/               # 服务端项目 (包含主函数与网络逻辑)
├── Common/               # 公共模块
│   └── crypto_utils.h    # OpenSSL 封装：密钥生成/交换/AES加解密
├── .gitignore            # Git 忽略配置
└── README.md             # 项目说明文档

🔮 未来计划 (TODO)

    □

    接入 Windows GUI / Qt 框架，实现图形化聊天界面。
    □

    增加双向身份认证机制，防范中间人攻击 (MITM)。
    □

    引入密钥轮换机制 (Key Ratcheting)，实现消息级别的前向安全。
