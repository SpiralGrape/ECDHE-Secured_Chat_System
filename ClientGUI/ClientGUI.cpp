// ============================================================================
//  ECDHE 安全聊天系统 —— 客户端 (Win32 GUI)
//
//  功能：
//   * 与任意在线用户进行 ECDHE(X25519) 临时密钥交换，每次会话独立会话密钥
//   * AES-256-GCM 端到端加密，服务器无法解密
//   * Ed25519 身份签名 + Finished 校验，抵御中间人攻击
//   * 消息级密钥棘轮（每条消息由链式 HKDF 派生新密钥，删除旧链密钥）
//
//  前向保密的实现要点：
//   1. 每次握手都生成全新的临时 X25519 密钥对，用完立即销毁；
//   2. 长期身份私钥只用于签名，不参与会话密钥派生；
//   3. 每条消息的密钥由棘轮推进后立即覆盖，历史消息密钥不可再恢复。
//   因此即使长期主密钥或当前会话密钥泄露，历史通信依然安全。
// ============================================================================

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <uxtheme.h>
#include <dwmapi.h>

#include <boost/asio.hpp>

#include "crypto_utils.h"
#include "protocol.h"

#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ws2_32.lib")

using boost::asio::ip::tcp;
using crypto::Bytes;

// ============================================================== 全局状态 ====
HWND  hChatBox = NULL, hInputBox = NULL, hTargetBox = NULL, hSendButton = NULL, hMainWnd = NULL;
HBRUSH g_hDarkBrush = NULL;
float  g_scale = 1.0f;

#define WM_APPEND_CHAT (WM_APP + 1)

// 网络
std::shared_ptr<boost::asio::io_context> g_io;
std::shared_ptr<tcp::socket>              g_sock;
std::mutex                                g_net_mu;        // 保护 g_sock 与发送
std::atomic<bool>                         g_connected(false);
int                                       my_client_id = 0;

// 身份（长期主密钥）
crypto::PkeyPtr g_identity;
std::wstring    g_my_fingerprint;

// 会话表
struct Session {
    enum class State { None, Initiator, Responder, Established };

    State          state = State::None;
    uint64_t       sid = 0;
    crypto::PkeyPtr eph;                    // 临时私钥（派生后立即销毁）
    Bytes          my_pub, my_nonce, my_idpub;
    Bytes          peer_pub, peer_nonce, peer_idpub;
    Bytes          init_msg, resp_msg;      // 握手报文（用于计算 transcript）
    Bytes          send_chain, recv_chain;  // 密钥棘轮链密钥
    Bytes          finished_key;
    uint64_t       send_seq = 0, recv_seq = 0;
    std::wstring   fingerprint;             // 会话密钥指纹（演示用）
    std::deque<std::string> outbox;         // 握手完成前排队的消息
};

std::map<int, Session> g_sessions;
std::map<int, Bytes>   g_pins;              // TOFU：对端身份公钥
std::mutex             g_sess_mu;

// ============================================================== 工具函数 ====
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring HexW(const Bytes& b, size_t n = 8) {
    static const wchar_t* digits = L"0123456789abcdef";
    std::wstring out;
    for (size_t i = 0; i < n && i < b.size(); ++i) {
        out.push_back(digits[b[i] >> 4]);
        out.push_back(digits[b[i] & 0x0F]);
    }
    return out;
}

static std::wstring AppDir() {
    wchar_t buf[MAX_PATH] = { 0 };
    DWORD n = GetEnvironmentVariableW(L"APPDATA", buf, MAX_PATH);
    std::wstring dir = (n > 0) ? std::wstring(buf, n) : std::wstring(L".");
    dir += L"\\ECDHE_Chat";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

static void SaveToLocalFile(const std::wstring& text) {
    std::filesystem::path p = std::filesystem::path(AppDir()) / L"history.txt";
    FILE* f = nullptr;
    if (_wfopen_s(&f, p.c_str(), L"ab") == 0 && f) {   // 宽字符路径，支持中文用户名
        std::string u8 = WideToUtf8(text);
        fwrite(u8.data(), 1, u8.size(), f);
        fclose(f);
    }
}

// 向界面投递文本（线程安全）
static void UiPost(const std::wstring& s) {
    if (!hMainWnd) return;
    PostMessageW(hMainWnd, WM_APPEND_CHAT, 0, (LPARAM)new std::wstring(s));
}

// ============================================================ 链路收发 ====
static Bytes MakeFrame(int target, const Bytes& payload) {
    Bytes f(8);
    proto::put_u32(f.data(), (uint32_t)(payload.size() + 4));
    proto::put_u32(f.data() + 4, (uint32_t)target);
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

static bool SendRaw(const Bytes& frame) {
    std::lock_guard<std::mutex> lk(g_net_mu);
    if (!g_sock || !g_connected.load()) return false;
    boost::system::error_code ec;
    boost::asio::write(*g_sock, boost::asio::buffer(frame), ec);
    if (ec) g_connected.store(false);
    return !ec;
}

// ============================================================ 密钥派生 ====
// 由 ECDHE 共享秘密派生会话密钥。派生完成后立刻销毁临时私钥。
static void DeriveSession(Session& s, bool initiator) {
    crypto::PkeyPtr peer = crypto::x25519_from_public_raw(s.peer_pub.data(), s.peer_pub.size());
    Bytes z = crypto::x25519_shared(s.eph.get(), peer.get());

    // salt 固定为 nonceA || nonceB（A = 发起方），把双方随机数绑进密钥
    Bytes salt = initiator ? crypto::cat(s.my_nonce, s.peer_nonce)
                           : crypto::cat(s.peer_nonce, s.my_nonce);

    Bytes secret = crypto::hkdf(z, salt, "CHAT-v1 ECDHE X25519", 32);
    Bytes c_i2r  = crypto::hkdf(secret, Bytes{}, "chain initiator->responder", 32);
    Bytes c_r2i  = crypto::hkdf(secret, Bytes{}, "chain responder->initiator", 32);
    s.finished_key = crypto::hkdf(secret, Bytes{}, "finished key", 32);

    crypto::wipe(s.send_chain);
    crypto::wipe(s.recv_chain);
    s.send_chain = initiator ? c_i2r : c_r2i;
    s.recv_chain = initiator ? c_r2i : c_i2r;
    s.fingerprint = HexW(crypto::sha256(secret), 8);

    crypto::wipe(z);
    crypto::wipe(secret);
    crypto::wipe(c_i2r);
    crypto::wipe(c_r2i);

    // ★ 前向保密关键：临时私钥用完即毁，事后无法再复现共享秘密
    s.eph.reset();
}

static Bytes TranscriptHash(const Bytes& a, const Bytes& b) {
    return crypto::sha256(crypto::cat(a, b));
}

// ======================================================= 会话（需持锁） ====
static void LockedSendChat(int peer, Session& s, const std::string& text) {
    // 密钥棘轮：每条消息用链密钥派生新密钥，然后立刻推进链密钥
    Bytes msg_key = crypto::hkdf(s.send_chain, Bytes{}, "message key", 32);
    Bytes nonce   = crypto::hkdf(s.send_chain, Bytes{}, "message iv", 12);
    Bytes next    = crypto::hkdf(s.send_chain, Bytes{}, "chain next", 32);

    Bytes aad = proto::make_aad(proto::DATA, s.sid, s.send_seq, my_client_id, peer);
    Bytes ct;
    try {
        ct = crypto::aead_encrypt(msg_key, nonce, text, aad);
    } catch (...) {
        crypto::wipe(msg_key); crypto::wipe(nonce); crypto::wipe(next);
        return;
    }

    Bytes payload;
    payload.push_back(proto::VERSION);
    payload.push_back(proto::DATA);
    proto::append_u64(payload, s.sid);
    proto::append_u64(payload, s.send_seq);
    proto::append(payload, ct);
    s.send_seq++;

    crypto::wipe(s.send_chain);
    s.send_chain = next;
    crypto::wipe(msg_key);
    crypto::wipe(nonce);
    crypto::wipe(next);

    SendRaw(MakeFrame(peer, payload));
}

static void LockedFlushOutbox(int peer, Session& s) {
    while (!s.outbox.empty()) {
        std::string m = s.outbox.front();
        s.outbox.pop_front();
        LockedSendChat(peer, s, m);
    }
}

// 发起握手（需持 g_sess_mu）
static void LockedStartHandshake(int peer) {
    Session& s = g_sessions[peer];
    std::deque<std::string> saved;
    saved.swap(s.outbox);

    s = Session();
    s.outbox.swap(saved);
    s.state = Session::State::Initiator;

    try {
        s.sid      = crypto::random_u64();
        s.eph      = crypto::x25519_generate();
        s.my_pub   = crypto::x25519_public_raw(s.eph.get());
        s.my_nonce = crypto::random_bytes(proto::NONCE_LEN);
        s.my_idpub = crypto::ed25519_public_raw(g_identity.get());
    } catch (...) {
        UiPost(L"[X] 生成本次会话临时密钥失败\r\n");
        s.state = Session::State::None;
        return;
    }

    Bytes msg;
    msg.push_back(proto::VERSION);
    msg.push_back(proto::HS_INIT);
    proto::append_u64(msg, s.sid);
    proto::append(msg, s.my_pub);
    proto::append(msg, s.my_nonce);
    proto::append(msg, s.my_idpub);
    proto::append_u32(msg, (uint32_t)my_client_id);
    proto::append_u32(msg, (uint32_t)peer);

    Bytes sig = crypto::ed25519_sign(g_identity.get(), msg);   // 长期主密钥签名临时公钥

    Bytes payload = msg;
    proto::append(payload, sig);
    s.init_msg = payload;

    SendRaw(MakeFrame(peer, payload));
    UiPost(L"--- [握手] 已向用户" + std::to_wstring(peer) + L" 发送 ECDHE 临时公钥 ---\r\n");
}

static bool CheckPin(int peer, const Bytes& idpub) {
    auto it = g_pins.find(peer);
    if (it == g_pins.end()) {
        g_pins[peer] = idpub;
        UiPost(L"--- [身份] 已固定用户" + std::to_wstring(peer) + L" 的身份公钥 " + HexW(crypto::sha256(idpub), 8) + L" ---\r\n");
        return true;
    }
    if (it->second != idpub) {
        UiPost(L"[!] 警告：用户" + std::to_wstring(peer) + L" 的身份公钥发生变化，可能遭遇中间人攻击！\r\n");
        return false;
    }
    return true;
}

// ====================================================== 处理收到的报文 ====
static void HandleInit(int sender, const Bytes& body);
static void HandleResp(int sender, const Bytes& body);
static void HandleConfirm(int sender, const Bytes& body);
static void HandleData(int sender, const Bytes& body);
static void HandleSystem(const Bytes& body);

// ------------------------------------------------------------ 收到 INIT ---
static void HandleInit(int sender, const Bytes& body) {
    if (body.size() != proto::HS_INIT_LEN) return;

    const uint64_t sid     = proto::get_u64(body.data() + 2);
    Bytes pubA             = proto::slice(body, 10, proto::X25519_LEN);
    Bytes nonceA           = proto::slice(body, 42, proto::NONCE_LEN);
    Bytes idpubA           = proto::slice(body, 58, proto::ED25519_LEN);
    const uint32_t idA     = proto::get_u32(body.data() + 90);
    const uint32_t idB     = proto::get_u32(body.data() + 94);
    Bytes sigA             = proto::slice(body, 98, proto::SIG_LEN);

    if ((int)idA != sender || (int)idB != my_client_id) return;   // 报文被改投

    if (!crypto::ed25519_verify(idpubA, proto::slice(body, 0, proto::HS_INIT_BASE), sigA)) {
        UiPost(L"[!] 用户" + std::to_wstring(sender) + L" 的握手签名无效，已丢弃（可能是中间人）\r\n");
        return;
    }

    std::lock_guard<std::mutex> lk(g_sess_mu);

    // 同时发起握手时的确定性仲裁：ID 小的一方胜出
    auto it = g_sessions.find(sender);
    if (it != g_sessions.end() &&
        it->second.state == Session::State::Initiator &&
        my_client_id < sender) {
        return;
    }
    if (!CheckPin(sender, idpubA)) return;

    // 允许重新协商：用新的握手覆盖旧会话（例如上一次会话因丢包失步）
    Session& s = g_sessions[sender];
    std::deque<std::string> saved;
    saved.swap(s.outbox);

    s = Session();
    s.outbox.swap(saved);
    s.state      = Session::State::Responder;
    s.sid        = sid;
    s.peer_pub   = pubA;
    s.peer_nonce = nonceA;
    s.peer_idpub = idpubA;
    s.init_msg   = body;

    try {
        s.eph      = crypto::x25519_generate();
        s.my_pub   = crypto::x25519_public_raw(s.eph.get());
        s.my_nonce = crypto::random_bytes(proto::NONCE_LEN);
        s.my_idpub = crypto::ed25519_public_raw(g_identity.get());

        Bytes resp;
        resp.push_back(proto::VERSION);
        resp.push_back(proto::HS_RESP);
        proto::append_u64(resp, s.sid);
        proto::append(resp, s.my_pub);
        proto::append(resp, s.my_nonce);
        proto::append(resp, s.my_idpub);            // 前 90 字节

        Bytes to_sign = resp;
        proto::append(to_sign, sigA);               // 绑定到对方的 INIT
        Bytes sigB = crypto::ed25519_sign(g_identity.get(), to_sign);
        proto::append(resp, sigB);                  // 前 154 字节

        DeriveSession(s, /*initiator=*/false);

        Bytes th = TranscriptHash(s.init_msg, resp);
        Bytes mac_input = th;
        mac_input.push_back('B');
        Bytes macB = crypto::hmac_sha256(s.finished_key, mac_input);

        s.resp_msg = resp;                          // 保存不含 mac 的副本
        Bytes payload = resp;
        proto::append(payload, macB);

        SendRaw(MakeFrame(sender, payload));
        UiPost(L"--- [握手] 已响应用户" + std::to_wstring(sender) + L"，会话密钥指纹 " + s.fingerprint + L" ---\r\n");
    } catch (...) {
        s.state = Session::State::None;
        UiPost(L"[X] 处理握手请求时出错\r\n");
    }
}

// ------------------------------------------------------------ 收到 RESP ---
static void HandleResp(int sender, const Bytes& body) {
    if (body.size() != proto::HS_RESP_LEN) return;

    const uint64_t sid = proto::get_u64(body.data() + 2);
    Bytes pubB         = proto::slice(body, 10, proto::X25519_LEN);
    Bytes nonceB       = proto::slice(body, 42, proto::NONCE_LEN);
    Bytes idpubB       = proto::slice(body, 58, proto::ED25519_LEN);
    Bytes sigB         = proto::slice(body, 90, proto::SIG_LEN);
    Bytes macB         = proto::slice(body, proto::HS_RESP_SIGN, proto::KEY_LEN);
    Bytes resp_core    = proto::slice(body, 0, proto::HS_RESP_SIGN);

    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(sender);
    if (it == g_sessions.end() || it->second.state != Session::State::Initiator) return;
    Session& s = it->second;
    if (s.sid != sid || s.init_msg.size() != proto::HS_INIT_LEN) return;   // 陈旧响应

    Bytes sigA = proto::slice(s.init_msg, proto::HS_INIT_BASE, proto::SIG_LEN);
    // 签名覆盖：RESP 前 90 字节 + 对方 INIT 的签名（不含 sigB 自身）
    Bytes to_sign = proto::slice(body, 0, proto::HS_RESP_BASE);
    proto::append(to_sign, sigA);
    if (!crypto::ed25519_verify(idpubB, to_sign, sigB)) {
        UiPost(L"[!] 用户" + std::to_wstring(sender) + L" 的握手响应签名无效，已中止\r\n");
        g_sessions.erase(it);
        return;
    }
    if (!CheckPin(sender, idpubB)) { g_sessions.erase(it); return; }

    s.peer_pub   = pubB;
    s.peer_nonce = nonceB;
    s.peer_idpub = idpubB;

    try {
        DeriveSession(s, /*initiator=*/true);
    } catch (...) {
        g_sessions.erase(it);
        UiPost(L"[X] 会话密钥派生失败\r\n");
        return;
    }

    Bytes th = TranscriptHash(s.init_msg, resp_core);
    Bytes mac_input = th;
    mac_input.push_back('B');
    Bytes expect = crypto::hmac_sha256(s.finished_key, mac_input);
    if (expect != macB) {
        UiPost(L"[!] 会话密钥确认失败，握手中止（可能被中间人篡改）\r\n");
        g_sessions.erase(it);
        return;
    }

    // 发送 CONFIRM
    Bytes mac_input_a = th;
    mac_input_a.push_back('A');
    Bytes macA = crypto::hmac_sha256(s.finished_key, mac_input_a);

    Bytes payload;
    payload.push_back(proto::VERSION);
    payload.push_back(proto::HS_CONFIRM);
    proto::append_u64(payload, s.sid);
    proto::append(payload, macA);
    SendRaw(MakeFrame(sender, payload));

    s.state = Session::State::Established;
    s.resp_msg = resp_core;
    UiPost(L"[+] 与用户" + std::to_wstring(sender) + L" 的安全会话已建立，会话密钥指纹 " + s.fingerprint + L"\r\n");
    LockedFlushOutbox(sender, s);
}

// --------------------------------------------------------- 收到 CONFIRM ---
static void HandleConfirm(int sender, const Bytes& body) {
    if (body.size() != proto::HS_CONFIRM_LEN) return;
    const uint64_t sid = proto::get_u64(body.data() + 2);
    Bytes macA = proto::slice(body, 10, proto::KEY_LEN);

    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(sender);
    if (it == g_sessions.end() || it->second.state != Session::State::Responder) return;
    Session& s = it->second;
    if (s.sid != sid) return;

    Bytes th = TranscriptHash(s.init_msg, s.resp_msg);
    Bytes mac_input = th;
    mac_input.push_back('A');
    Bytes expect = crypto::hmac_sha256(s.finished_key, mac_input);
    if (expect != macA) {
        UiPost(L"[!] 用户" + std::to_wstring(sender) + L" 的握手确认无效，会话未建立\r\n");
        g_sessions.erase(it);
        return;
    }

    s.state = Session::State::Established;
    UiPost(L"[+] 与用户" + std::to_wstring(sender) + L" 的安全会话已建立，会话密钥指纹 " + s.fingerprint + L"\r\n");
    LockedFlushOutbox(sender, s);
}

// ------------------------------------------------------------ 收到 DATA ---
static void HandleData(int sender, const Bytes& body) {
    if (body.size() < proto::DATA_MIN) return;
    const uint64_t sid = proto::get_u64(body.data() + 2);
    const uint64_t seq = proto::get_u64(body.data() + 10);
    Bytes ct = proto::slice(body, proto::DATA_HEADER, body.size() - proto::DATA_HEADER);

    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(sender);
    if (it == g_sessions.end() || it->second.state != Session::State::Established) {
        UiPost(L"[!] 收到用户" + std::to_wstring(sender) + L" 的消息，但本地没有可用会话，已丢弃\r\n");
        return;
    }
    Session& s = it->second;
    if (s.sid != sid || seq != s.recv_seq) {
        UiPost(L"[!] 用户" + std::to_wstring(sender) + L" 的会话失步或重放，会话已重置\r\n");
        g_sessions.erase(it);
        return;
    }

    Bytes msg_key = crypto::hkdf(s.recv_chain, Bytes{}, "message key", 32);
    Bytes nonce   = crypto::hkdf(s.recv_chain, Bytes{}, "message iv", 12);
    Bytes next    = crypto::hkdf(s.recv_chain, Bytes{}, "chain next", 32);

    Bytes aad = proto::make_aad(proto::DATA, sid, seq, sender, my_client_id);
    std::string plain;
    bool ok = crypto::aead_decrypt(msg_key, nonce, ct, aad, plain);

    crypto::wipe(msg_key);
    crypto::wipe(nonce);

    if (!ok) {
        crypto::wipe(next);
        UiPost(L"[!] 用户" + std::to_wstring(sender) + L" 的消息认证失败（被篡改或密钥不匹配），会话已重置\r\n");
        g_sessions.erase(it);
        return;
    }

    crypto::wipe(s.recv_chain);
    s.recv_chain = next;
    crypto::wipe(next);
    s.recv_seq++;

    std::wstring text = L"用户" + std::to_wstring(sender) + L": " + Utf8ToWide(plain) + L"\r\n";
    SaveToLocalFile(text);
    UiPost(text);
}

// ---------------------------------------------------------- 收到系统消息 ---
static void HandleSystem(const Bytes& body) {
    // [ver][SYSTEM][related_id(4)][文本]
    if (body.size() < 6) return;
    int related = (int)proto::get_u32(body.data() + 2);
    std::string text(body.begin() + 6, body.end());

    UiPost(L"[系统] " + Utf8ToWide(text) + L"\r\n");

    // 目标不在线：丢弃挂起的会话，避免棘轮状态与对端不一致
    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(related);
    if (it != g_sessions.end() && it->second.state != Session::State::Established) {
        g_sessions.erase(it);
    }
}

// ============================================================ 网络线程 ====
static void NetworkThread() {
    try {
        g_io = std::make_shared<boost::asio::io_context>();
        auto sock = std::make_shared<tcp::socket>(*g_io);
        sock->connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 9000));

        boost::system::error_code ec;
        uint32_t id = 0;
        boost::asio::read(*sock, boost::asio::buffer(&id, 4), ec);
        if (ec) throw std::runtime_error("读取客户端 ID 失败");
        my_client_id = (int)id;
        // 标题带上自己的 ID，便于多开时区分窗口
        {
            std::wstring title = L"ECDHE 前向保密聊天工具 - 用户 " + std::to_wstring(my_client_id);
            SetWindowTextW(hMainWnd, title.c_str());
        }

        {
            std::lock_guard<std::mutex> lk(g_net_mu);
            g_sock = sock;
            g_connected.store(true);
        }

        UiPost(L"--- [系统] 已连接服务器，你的 ID 是 " + std::to_wstring(my_client_id) + L" ---\r\n");
        UiPost(L"--- [身份] 长期身份公钥指纹 " + g_my_fingerprint +
               L"（仅用于签名临时密钥，泄露也不影响历史会话）---\r\n");

        while (g_connected.load()) {
            uint32_t len = 0;
            boost::asio::read(*sock, boost::asio::buffer(&len, 4), ec);
            if (ec) break;
            if (len < 4 || len > proto::MAX_PAYLOAD) break;

            std::vector<unsigned char> packet(len);
            boost::asio::read(*sock, boost::asio::buffer(packet), ec);
            if (ec) break;

            const int sender = (int)proto::get_u32(packet.data());
            Bytes body(packet.begin() + 4, packet.end());
            if (body.size() < 2) continue;

            const uint8_t type = body[1];
            switch (type) {
            case proto::SYSTEM:     HandleSystem(body);            break;
            case proto::HS_INIT:    HandleInit(sender, body);       break;
            case proto::HS_RESP:    HandleResp(sender, body);       break;
            case proto::HS_CONFIRM: HandleConfirm(sender, body);    break;
            case proto::DATA:       HandleData(sender, body);       break;
            default: break;
            }
        }
    } catch (std::exception& e) {
        UiPost(L"--- 网络错误: " + Utf8ToWide(e.what()) + L" ---\r\n");
    }

    g_connected.store(false);
    UiPost(L"--- [系统] 与服务器断开连接 ---\r\n");
}

// ============================================================ 发送消息 ====
static void SendUserMessage(int target, const std::wstring& wtext) {
    if (target == my_client_id) {
        UiPost(L"[X] 不能给自己发消息\r\n");
        return;
    }
    std::string text = WideToUtf8(wtext);

    std::lock_guard<std::mutex> lk(g_sess_mu);
    Session& s = g_sessions[target];
    if (s.state == Session::State::Established) {
        LockedSendChat(target, s, text);
    } else {
        s.outbox.push_back(text);
        if (s.state != Session::State::Initiator) LockedStartHandshake(target);
        UiPost(L"--- [握手] 正在与用户" + std::to_wstring(target) + L" 协商 ECDHE 会话，消息已排队 ---\r\n");
    }
}

// ============================================================ 窗口过程 ====
static int S(int value) { return (int)(value * g_scale); }

static void OnSendClicked() {
    wchar_t target_buf[16] = { 0 };
    GetWindowTextW(hTargetBox, target_buf, 16);
    int target = _wtoi(target_buf);

    int n = GetWindowTextLengthW(hInputBox);
    if (n <= 0 || target <= 0) return;
    std::wstring text(n, L'\0');
    GetWindowTextW(hInputBox, &text[0], n + 1);
    text.resize(n);

    if (text.empty()) return;
    if (!g_connected.load()) {
        UiPost(L"[X] 尚未连接服务器\r\n");
        return;
    }

    SendUserMessage(target, text);

    std::wstring shown = L"我 -> 用户" + std::to_wstring(target) + L": " + text + L"\r\n";
    SaveToLocalFile(shown);
    UiPost(shown);
    SetWindowTextW(hInputBox, L"");
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
    {
        g_hDarkBrush = CreateSolidBrush(RGB(30, 30, 30));

        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));

        hChatBox = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            S(10), S(10), S(560), S(370), hwnd, NULL, NULL, NULL);

        CreateWindowW(L"STATIC", L"收件人 ID:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            S(10), S(390), S(80), S(32), hwnd, NULL, NULL, NULL);

        hTargetBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"2",
            WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER,
            S(95), S(390), S(50), S(32), hwnd, NULL, NULL, NULL);

        hInputBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            S(155), S(390), S(280), S(32), hwnd, NULL, NULL, NULL);

        hSendButton = CreateWindowExW(0, L"BUTTON", L"发送 (Enter)",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
            S(445), S(390), S(125), S(32), hwnd, (HMENU)1, NULL, NULL);

        HFONT hFont = CreateFontW(-S(20), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei");
        SendMessageW(hChatBox, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hInputBox, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hSendButton, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hTargetBox, WM_SETFONT, (WPARAM)hFont, TRUE);

        SetWindowTheme(hSendButton, L" ", L" ");
        SetWindowTheme(hInputBox, L" ", L" ");
        SetWindowTheme(hTargetBox, L" ", L" ");
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(220, 220, 220));
        SetBkColor(hdc, RGB(30, 30, 30));
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)g_hDarkBrush;
    }
    case WM_CTLCOLORBTN:
        return (LRESULT)GetStockObject(NULL_BRUSH);

    case WM_ERASEBKGND:
    {
        HDC hdc = (HDC)wParam;
        RECT rect;
        GetClientRect(hwnd, &rect);
        FillRect(hdc, &rect, g_hDarkBrush);
        return 1;
    }

    case WM_KEYDOWN:
        if (wParam == VK_RETURN && GetFocus() == hInputBox)
            SendMessageW(hwnd, WM_COMMAND, MAKEWPARAM(1, BN_CLICKED), (LPARAM)hSendButton);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) OnSendClicked();
        return 0;

    case WM_APPEND_CHAT:
    {
        std::wstring* text = (std::wstring*)lParam;
        int len = GetWindowTextLengthW(hChatBox);
        SendMessageW(hChatBox, EM_SETSEL, len, len);
        SendMessageW(hChatBox, EM_REPLACESEL, FALSE, (LPARAM)text->c_str());
        SendMessageW(hChatBox, WM_VSCROLL, SB_BOTTOM, 0);
        delete text;
        return 0;
    }

    case WM_DESTROY:
        if (g_hDarkBrush) DeleteObject(g_hDarkBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// ================================================================ 入口 ====
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    HDC screen = GetDC(NULL);
    int dpiX = GetDeviceCaps(screen, LOGPIXELSX);
    ReleaseDC(NULL, screen);
    g_scale = dpiX / 96.0f;

    // 加载/生成长期身份密钥（Ed25519）
    try {
        std::filesystem::path p = std::filesystem::path(AppDir()) / L"identity.pem";
        g_identity = crypto::ed25519_load_or_create(p.wstring());
        g_my_fingerprint = HexW(crypto::sha256(crypto::ed25519_public_raw(g_identity.get())), 8);
    } catch (...) {
        MessageBoxW(NULL, L"身份密钥初始化失败", L"错误", MB_ICONERROR);
        return 1;
    }

    const wchar_t* CLASS_NAME = L"ChatWindowClass";
    WNDCLASSW wc = { };
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    RegisterClassW(&wc);

    hMainWnd = CreateWindowExW(0, CLASS_NAME, L"ECDHE 前向保密聊天工具",
        WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, S(600), S(500), NULL, NULL, hInstance, NULL);
    if (!hMainWnd) return 0;

    ShowWindow(hMainWnd, nCmdShow);

    std::thread(NetworkThread).detach();

    MSG msg = { };
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
