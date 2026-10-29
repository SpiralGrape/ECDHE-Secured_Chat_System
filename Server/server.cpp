// ============================================================================
//  ECDHE 安全聊天系统 —— 中继服务器
//
//  定位：不可信中继（Untrusted Relay）
//   * 服务器只按目标 ID 转发密文帧，不持有任何会话密钥，无法解密聊天内容；
//   * 握手消息（INIT/RESP/CONFIRM）同样原样转发，服务器无法伪造或篡改
//     （双方用 Ed25519 签名 + Finished MAC 校验，篡改必然被发现）；
//   * 服务器若被攻破，攻击者只能看到长度与收发关系，拿不到明文。
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#include <boost/asio.hpp>

#include <atomic>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "protocol.h"

using boost::asio::ip::tcp;

// ------------------------------------------------------------------ 会话 ----
struct ClientSession {
    tcp::socket sock;
    int id;
    std::mutex write_mu;              // 保证同一 socket 上不会出现帧交错
    std::atomic<bool> alive{ true };

    ClientSession(tcp::socket&& s, int i) : sock(std::move(s)), id(i) {}
};
using SessionPtr = std::shared_ptr<ClientSession>;

static std::map<int, SessionPtr> g_clients;
static std::mutex g_clients_mu;
static std::mutex g_log_mu;

// 多线程日志：整行加锁输出，避免不同连接线程的日志互相穿插
static void Log(const std::string& line) {
    std::lock_guard<std::mutex> lk(g_log_mu);
    std::cout << line << '\n';
}

// -------------------------------------------------------------- 发送帧 ------
// 必须在 write_mu 保护下完成“长度 + 载荷”两次写，否则多线程写同一 socket
// 会导致 TCP 字节流被交叉，接收端无法还原帧边界。
static bool SendFrame(ClientSession& c, const unsigned char* payload, uint32_t len) {
    std::lock_guard<std::mutex> lk(c.write_mu);
    if (!c.alive.load()) return false;

    boost::system::error_code ec;
    uint32_t n = len;
    boost::asio::write(c.sock, boost::asio::buffer(&n, 4), ec);
    if (!ec && len > 0)
        boost::asio::write(c.sock, boost::asio::buffer(payload, len), ec);
    if (ec) {
        c.alive.store(false);
        boost::system::error_code ig;
        c.sock.close(ig);
        return false;
    }
    return true;
}

// 向发送方回报一条系统通知（明文，只用于“用户不在线”等提示）
static void SendSystem(ClientSession& c, int related_id, const std::string& text) {
    proto::Bytes payload;
    payload.push_back(proto::VERSION);
    payload.push_back(proto::SYSTEM);
    proto::append_u32(payload, (uint32_t)related_id);
    proto::append(payload, text.data(), text.size());
    SendFrame(c, payload.data(), (uint32_t)payload.size());
}

// ------------------------------------------------------------ 处理客户端 ----
static void HandleClient(SessionPtr client) {
    const int my_id = client->id;
    boost::system::error_code ec;

    // 1. 先把分配到的 ID 告诉客户端
    {
        std::lock_guard<std::mutex> lk(client->write_mu);
        uint32_t id = (uint32_t)my_id;
        boost::asio::write(client->sock, boost::asio::buffer(&id, 4), ec);
    }
    if (ec) { client->alive.store(false); }

    std::vector<unsigned char> buf;
    while (client->alive.load()) {
        // 2. 读帧长度（严格限制上限，防止 OOM / DoS）
        uint32_t len = 0;
        boost::asio::read(client->sock, boost::asio::buffer(&len, 4), ec);
        if (ec) break;

        if (len < 4 || len > proto::MAX_PAYLOAD) {
            Log("[警告] 客户端 " + std::to_string(my_id) + " 发送了非法帧长度 " +
                std::to_string(len) + "，断开连接");
            break;
        }

        buf.resize(len);
        boost::asio::read(client->sock, boost::asio::buffer(buf), ec);
        if (ec) break;

        const int target = (int)proto::get_u32(buf.data());
        if (target == my_id) continue;

        // 3. 查找目标（锁内只做查找，锁外做阻塞写，避免全局串行化）
        SessionPtr dst;
        {
            std::lock_guard<std::mutex> lk(g_clients_mu);
            auto it = g_clients.find(target);
            if (it != g_clients.end()) dst = it->second;
        }

        if (dst && dst->alive.load()) {
            // 重新组帧：[发送者 ID][原始 payload]
            std::vector<unsigned char> out(4 + (len - 4));
            proto::put_u32(out.data(), (uint32_t)my_id);
            std::memcpy(out.data() + 4, buf.data() + 4, len - 4);
            if (SendFrame(*dst, out.data(), (uint32_t)out.size())) {
                Log("[中继] " + std::to_string(my_id) + " -> " + std::to_string(target) +
                    " 转发 " + std::to_string(len - 4) + " 字节（内容不可解密）");
            } else {
                Log("[中继] " + std::to_string(my_id) + " -> " + std::to_string(target) +
                    " 转发失败：目标连接已断开");
            }
        } else {
            Log("[中继] " + std::to_string(my_id) + " -> " + std::to_string(target) +
                " 失败：目标不在线");
            SendSystem(*client, target, "用户 " + std::to_string(target) + " 不在线");
        }
    }

    // 4. 清理
    client->alive.store(false);
    {
        std::lock_guard<std::mutex> lk(g_clients_mu);
        g_clients.erase(my_id);
    }
    boost::system::error_code ig;
    client->sock.close(ig);
    Log("[系统] 客户端 " + std::to_string(my_id) + " 下线");
}

int main() {
    SetConsoleOutputCP(CP_UTF8);   // 控制台按 UTF-8 输出中文
    std::cout << std::unitbuf;     // 关闭缓冲，日志实时可见（含重定向到文件时）

    boost::asio::io_context io;
    boost::system::error_code ec;
    tcp::acceptor acceptor(io);
    acceptor.open(tcp::v4(), ec);
    if (!ec) acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
    if (!ec) acceptor.bind(tcp::endpoint(tcp::v4(), 9000), ec);
    if (!ec) acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        std::cerr << "[错误] 无法监听 9000 端口: " << ec.message() << "\n";
        return 1;
    }

    std::cout << "ECDHE 安全聊天中继已启动，监听 9000 端口（服务器无法解密聊天内容）\n";

    int next_id = 1;
    for (;;) {
        tcp::socket s(io);
        acceptor.accept(s, ec);
        if (ec) { std::cerr << "[错误] accept: " << ec.message() << "\n"; continue; }

        auto client = std::make_shared<ClientSession>(std::move(s), next_id++);
        {
            std::lock_guard<std::mutex> lk(g_clients_mu);
            g_clients[client->id] = client;
        }
        std::cout << "[系统] 客户端接入，分配 ID " << client->id << "\n";
        std::thread(HandleClient, client).detach();    }
    return 0;
}
