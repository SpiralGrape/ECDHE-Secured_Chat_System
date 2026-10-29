// ============================================================================
//  ECDHE 安全聊天系统 —— 客户端 (Win32 GUI)
//
//  功能：
//   * 与任意在线用户进行 ECDHE(X25519) 临时密钥交换，每次会话独立会话密钥
//   * AES-256-GCM 端到端加密，服务器无法解密
//   * Ed25519 身份签名 + Finished 校验，抵御中间人攻击
//   * 消息级密钥棘轮（每条消息由链式 HKDF 派生新密钥，删除旧链密钥）
//
//  体验相关：
//   * 左侧会话列表，聊天记录按对端用户分文件持久化，重启自动重载
//   * 握手/连接/错误等提示统一显示在底部状态栏，不污染聊天记录
//   * 断线自动重连
// ============================================================================

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
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
#include "secure_session.h"

#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ws2_32.lib")

using boost::asio::ip::tcp;
using crypto::Bytes;

// ============================================================== 常量/消息 ====
#define WM_CHAT_EVENT   (WM_APP + 1)   // lParam = new ChatEvent
#define WM_SET_STATUS   (WM_APP + 2)   // wParam = 是否错误, lParam = new std::wstring
#define WM_LOAD_CHATS   (WM_APP + 3)   // wParam = 本地客户端 ID（加载该实例的聊天记录）

#define IDC_SEND          1
#define IDC_SESSION_LIST  101
#define IDC_STATUS        102

constexpr UINT_PTR IDT_RECONNECT = 1;

// ============================================================== 全局状态 ====
HWND  hChatBox = NULL, hInputBox = NULL, hTargetBox = NULL, hSendButton = NULL;
HWND  hMainWnd = NULL, hSessionList = NULL, hStatus = NULL, hTargetLabel = NULL;
HBRUSH g_hDarkBrush = NULL;
HFONT  g_hFont = NULL, g_hStatusFont = NULL;
float  g_scale = 1.0f;
bool   g_statusError = false;

// 网络
std::shared_ptr<boost::asio::io_context> g_io;
std::shared_ptr<tcp::socket>              g_sock;
std::mutex                                g_net_mu;
std::atomic<bool>                         g_connected(false);
std::atomic<bool>                         g_connecting(false);
int                                       my_client_id = 0;

// 身份（长期主密钥）
crypto::PkeyPtr g_identity;
std::wstring    g_my_fingerprint;

// 会话（跨线程访问，用 g_sess_mu 保护）
struct PeerSession {
    securechat::SecureSession crypto;
    std::deque<std::string>   outbox;       // 握手完成前排队等待发送的消息
};

std::map<int, PeerSession> g_sessions;
std::map<int, crypto::Bytes> g_pins;        // 对端身份公钥固定（持久化 TOFU）
std::mutex                   g_sess_mu;

// 聊天记录（只在 UI 线程访问）
struct ChatMsg {
    uint64_t     ts = 0;    // unix 秒
    int          dir = 0;   // 0=收到 1=发出
    std::wstring text;
};
std::map<int, std::vector<ChatMsg>> g_chats;
std::set<int>  g_unread;
int            g_activePeer = 0;            // 0 表示无选中会话
int            g_profileId  = 0;            // 聊天记录所属的本地实例（= 服务器分配的 ID）

// 网络线程 → UI 线程的消息
struct ChatEvent {
    int          peer;
    int          dir;    // 0=收到 1=发出 2=系统提示
    std::wstring text;
};

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

static std::wstring ChatsDir(int profileId) {
    std::wstring dir = AppDir() + L"\\chats";
    if (profileId > 0) dir += L"\\" + std::to_wstring(profileId);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

static std::wstring FormatTime(uint64_t ts) {
    time_t t = (time_t)ts;
    tm local {};
    localtime_s(&local, &t);
    wchar_t b[16];
    swprintf_s(b, L"%02d:%02d", local.tm_hour, local.tm_min);
    return b;
}

// 文本转义：让每条消息在文件中严格占一行
static std::wstring Esc(const std::wstring& s) {
    std::wstring o;
    o.reserve(s.size());
    for (wchar_t c : s) {
        if (c == L'\\')      o += L"\\\\";
        else if (c == L'\n') o += L"\\n";
        else if (c == L'\r') continue;
        else if (c == L'\t') o += L"\\t";
        else                 o += c;
    }
    return o;
}

static std::wstring Unesc(const std::wstring& s) {
    std::wstring o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == L'\\' && i + 1 < s.size()) {
            wchar_t n = s[++i];
            if (n == L'n')      o += L'\n';
            else if (n == L't') o += L'\t';
            else                o += n;
        } else {
            o += s[i];
        }
    }
    return o;
}

// ============================================================ 聊天记录 IO ====
static std::wstring ChatFile(int peer) {
    return ChatsDir(g_profileId) + L"\\" + std::to_wstring(peer) + L".log";
}

static void SaveChatMsg(int peer, const ChatMsg& m) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, ChatFile(peer).c_str(), L"ab") != 0 || !f) return;

    wchar_t head[64];
    swprintf_s(head, L"%llu\t%d\t", (unsigned long long)m.ts, m.dir);
    std::string line = WideToUtf8(std::wstring(head) + Esc(m.text) + L"\n");
    fwrite(line.data(), 1, line.size(), f);
    fclose(f);
}

static void LoadAllChats(int profileId) {
    g_chats.clear();
    g_unread.clear();
    g_activePeer = 0;
    g_profileId  = profileId;

    std::error_code ec;
    std::filesystem::path dir(ChatsDir(profileId));
    if (!std::filesystem::exists(dir, ec)) return;

    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        std::wstring name = entry.path().stem().wstring();
        if (entry.path().extension() != L".log") continue;

        int peer = _wtoi(name.c_str());
        if (peer <= 0) continue;

        FILE* f = nullptr;
        if (_wfopen_s(&f, entry.path().c_str(), L"rb") != 0 || !f) continue;
        std::string raw;
        char buf[4096];
        size_t n = 0;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) raw.append(buf, n);
        fclose(f);

        std::wstring all = Utf8ToWide(raw);
        size_t pos = 0;
        while (pos < all.size()) {
            size_t eol = all.find(L'\n', pos);
            if (eol == std::wstring::npos) eol = all.size();
            std::wstring line = all.substr(pos, eol - pos);
            pos = eol + 1;
            if (line.empty()) continue;

            size_t t1 = line.find(L'\t');
            if (t1 == std::wstring::npos) continue;
            size_t t2 = line.find(L'\t', t1 + 1);
            if (t2 == std::wstring::npos) continue;

            ChatMsg m;
            m.ts  = _wcstoui64(line.substr(0, t1).c_str(), nullptr, 10);
            m.dir = _wtoi(line.substr(t1 + 1, t2 - t1 - 1).c_str());
            m.text = Unesc(line.substr(t2 + 1));
            g_chats[peer].push_back(m);
        }
    }
}

// ========================================================== 指纹固定 IO ====
static std::wstring PinsFile() {
    std::wstring dir = AppDir() + L"\\pins";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir + L"\\" + std::to_wstring(g_profileId) + L".log";
}

static void SavePin(int peer, const crypto::Bytes& pub) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, PinsFile().c_str(), L"ab") != 0 || !f) return;
    static const char* hexd = "0123456789abcdef";
    std::string hex;
    for (unsigned char c : pub) { hex.push_back(hexd[c >> 4]); hex.push_back(hexd[c & 0x0F]); }
    std::string line = std::to_string(peer) + "\t" + hex + "\n";
    fwrite(line.data(), 1, line.size(), f);
    fclose(f);
}

// 载入已固定的对端身份公钥（调用方需持 g_sess_mu）
static void LoadPins() {
    g_pins.clear();
    std::wstring path = PinsFile();

    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return;
    std::string raw;
    char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) raw.append(buf, n);
    fclose(f);

    auto hexv = [](wchar_t c) -> int {
        if (c >= L'0' && c <= L'9') return (int)(c - L'0');
        if (c >= L'a' && c <= L'f') return (int)(c - L'a') + 10;
        if (c >= L'A' && c <= L'F') return (int)(c - L'A') + 10;
        return -1;
    };

    std::wstring all = Utf8ToWide(raw);
    size_t pos = 0;
    while (pos < all.size()) {
        size_t eol = all.find(L'\n', pos);
        if (eol == std::wstring::npos) eol = all.size();
        std::wstring line = all.substr(pos, eol - pos);
        pos = eol + 1;

        size_t t = line.find(L'\t');
        if (t == std::wstring::npos) continue;
        int peer = _wtoi(line.substr(0, t).c_str());
        std::wstring hex = line.substr(t + 1);
        if (peer <= 0 || hex.size() < 2) continue;

        crypto::Bytes pub;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            int hi = hexv(hex[i]), lo = hexv(hex[i + 1]);
            if (hi < 0 || lo < 0) { pub.clear(); break; }
            pub.push_back((unsigned char)((hi << 4) | lo));
        }
        if (!pub.empty()) g_pins[peer] = pub;
    }
}

// ============================================================== UI 辅助 ====
static void RefreshSessionList() {
    if (!hSessionList) return;
    SendMessageW(hSessionList, LB_RESETCONTENT, 0, 0);

    for (const auto& kv : g_chats) {
        const int peer = kv.first;
        std::wstring label = L"用户 " + std::to_wstring(peer);
        if (g_unread.count(peer)) label += L"  ●";
        int idx = (int)SendMessageW(hSessionList, LB_ADDSTRING, 0, (LPARAM)label.c_str());
        if (idx >= 0) SendMessageW(hSessionList, LB_SETITEMDATA, idx, (LPARAM)peer);
    }

    // 保持当前选中项
    if (g_activePeer > 0) {
        int count = (int)SendMessageW(hSessionList, LB_GETCOUNT, 0, 0);
        for (int i = 0; i < count; ++i) {
            if (SendMessageW(hSessionList, LB_GETITEMDATA, i, 0) == (LPARAM)g_activePeer) {
                SendMessageW(hSessionList, LB_SETCURSEL, i, 0);
                break;
            }
        }
    }
}

static std::wstring RenderLine(int peer, const ChatMsg& m) {
    std::wstring line = L"[" + FormatTime(m.ts) + L"] ";
    if (m.dir == 0)      line += L"用户 " + std::to_wstring(peer) + L": ";
    else if (m.dir == 1) line += L"我: ";
    else                 line += L"⚠ ";
    line += m.text + L"\r\n";
    return line;
}

static void RefreshChatView() {
    if (!hChatBox) return;

    std::wstring all;
    auto it = g_chats.find(g_activePeer);
    if (it != g_chats.end()) {
        for (const auto& m : it->second) all += RenderLine(g_activePeer, m);
    }
    SetWindowTextW(hChatBox, all.c_str());
    SendMessageW(hChatBox, EM_SETSEL, (WPARAM)all.size(), (LPARAM)all.size());
    SendMessageW(hChatBox, WM_VSCROLL, SB_BOTTOM, 0);
}

// 在聊天视图尾部追加一行（仅当属于当前会话）
static void AppendChatView(const std::wstring& line) {
    int len = GetWindowTextLengthW(hChatBox);
    SendMessageW(hChatBox, EM_SETSEL, len, len);
    SendMessageW(hChatBox, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    SendMessageW(hChatBox, WM_VSCROLL, SB_BOTTOM, 0);
}

static void ApplyChatEvent(int peer, int dir, const std::wstring& text) {
    if (peer <= 0) return;

    ChatMsg m;
    m.ts   = (uint64_t)time(nullptr);
    m.dir  = dir;
    m.text = text;

    g_chats[peer].push_back(m);
    SaveChatMsg(peer, m);

    if (peer == g_activePeer) {
        AppendChatView(RenderLine(peer, m));
    } else if (dir == 0) {
        g_unread.insert(peer);
    }

    int listCount = (int)SendMessageW(hSessionList, LB_GETCOUNT, 0, 0);
    if (dir == 1 || (int)g_chats.size() != listCount) RefreshSessionList();
}

// 线程安全地投递界面事件
static void PostChat(int peer, int dir, const std::wstring& text) {
    if (!hMainWnd) return;
    PostMessageW(hMainWnd, WM_CHAT_EVENT, 0, (LPARAM)new ChatEvent{ peer, dir, text });
}

static void PostStatus(const std::wstring& text, bool error = false) {
    if (!hMainWnd) return;
    PostMessageW(hMainWnd, WM_SET_STATUS, (WPARAM)(error ? 1 : 0), (LPARAM)new std::wstring(text));
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

// ======================================================= 会话（需持锁） ====
static void LockedSendChat(int peer, PeerSession& ps, const std::string& text) {
    Bytes payload;
    std::string err;
    if (!ps.crypto.Seal(my_client_id, peer, text, payload, err)) {
        PostStatus(Utf8ToWide(err), true);
        return;
    }
    SendRaw(MakeFrame(peer, payload));
}

static void LockedFlushOutbox(int peer, PeerSession& ps) {
    while (!ps.outbox.empty()) {
        std::string m = ps.outbox.front();
        ps.outbox.pop_front();
        LockedSendChat(peer, ps, m);
    }
}

// 会话建立后的状态栏提示：安全码 + 密钥指纹
static void PostEstablished(int peer, const securechat::SecureSession& c) {
    PostStatus(L"与用户 " + std::to_wstring(peer) + L" 的加密会话已建立 · 安全码 " +
               Utf8ToWide(c.sas()) + L"（请与对方口头核对）· 密钥指纹 " +
               Utf8ToWide(c.fingerprint()));
}

static void LockedStartHandshake(int peer) {
    PeerSession& ps = g_sessions[peer];
    Bytes payload;
    std::string err;
    if (!ps.crypto.BuildInit(crypto::random_u64(), my_client_id, peer,
                             g_identity.get(), payload, err)) {
        PostStatus(L"建立会话失败：" + Utf8ToWide(err), true);
        return;
    }
    SendRaw(MakeFrame(peer, payload));
    PostStatus(L"正在与用户 " + std::to_wstring(peer) + L" 协商 ECDHE 会话…");
}

// 身份公钥固定（TOFU）：首次见面即记录，之后变化即视为中间人
static bool CheckPin(int peer, const crypto::Bytes& idpub) {
    auto it = g_pins.find(peer);
    if (it == g_pins.end()) {
        g_pins[peer] = idpub;
        SavePin(peer, idpub);
        return true;
    }
    if (it->second != idpub) {
        PostChat(peer, 2, L"对端身份公钥与已记录的指纹不一致，可能存在中间人攻击，已中止"
                          L"（若确认对方是换了新客户端，可删除 %APPDATA%\\ECDHE_Chat\\pins 后重试）");
        PostStatus(L"用户 " + std::to_wstring(peer) + L" 身份指纹变化，已阻断", true);
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

static void HandleInit(int sender, const Bytes& body) {
    if (body.size() != proto::HS_INIT_LEN) return;

    std::lock_guard<std::mutex> lk(g_sess_mu);

    // 同时发起握手时的确定性仲裁：ID 小的一方胜出
    auto it = g_sessions.find(sender);
    if (it != g_sessions.end() &&
        it->second.crypto.state() == securechat::SecureSession::State::Initiating &&
        my_client_id < sender) {
        return;
    }

    PeerSession& ps = g_sessions[sender];
    Bytes resp;
    std::string err;
    if (!ps.crypto.HandleInit(body, my_client_id, sender, g_identity.get(), resp, err)) {
        PostChat(sender, 2, L"握手失败：" + Utf8ToWide(err));
        g_sessions.erase(sender);
        return;
    }
    if (!CheckPin(sender, ps.crypto.peerIdentity())) {
        g_sessions.erase(sender);
        return;
    }

    SendRaw(MakeFrame(sender, resp));
    PostStatus(L"正在与用户 " + std::to_wstring(sender) + L" 协商 ECDHE 会话…");
}

static void HandleResp(int sender, const Bytes& body) {
    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(sender);
    if (it == g_sessions.end()) return;
    PeerSession& ps = it->second;
    if (ps.crypto.state() != securechat::SecureSession::State::Initiating) return;

    Bytes confirm;
    std::string err;
    if (!ps.crypto.HandleResp(body, my_client_id, sender, confirm, err)) {
        PostChat(sender, 2, L"握手失败：" + Utf8ToWide(err) + L"，会话已中止");
        g_sessions.erase(it);
        return;
    }
    if (!CheckPin(sender, ps.crypto.peerIdentity())) {
        g_sessions.erase(it);
        return;
    }

    SendRaw(MakeFrame(sender, confirm));
    PostEstablished(sender, ps.crypto);
    LockedFlushOutbox(sender, ps);
}

static void HandleConfirm(int sender, const Bytes& body) {
    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(sender);
    if (it == g_sessions.end()) return;
    PeerSession& ps = it->second;
    if (ps.crypto.state() != securechat::SecureSession::State::Responding) return;

    std::string err;
    if (!ps.crypto.HandleConfirm(body, err)) {
        PostChat(sender, 2, L"握手确认失败：" + Utf8ToWide(err));
        g_sessions.erase(it);
        return;
    }

    PostEstablished(sender, ps.crypto);
    LockedFlushOutbox(sender, ps);
}

static void HandleData(int sender, const Bytes& body) {
    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(sender);
    if (it == g_sessions.end()) return;
    PeerSession& ps = it->second;
    if (!ps.crypto.established()) return;

    std::string plain, err;
    if (!ps.crypto.Open(my_client_id, sender, body, plain, err)) {
        PostChat(sender, 2, L"消息校验失败：" + Utf8ToWide(err) + L"，已重置会话");
        g_sessions.erase(it);
        return;
    }

    PostChat(sender, 0, Utf8ToWide(plain));
}

static void HandleSystem(const Bytes& body) {
    // [ver][SYSTEM][related_id(4)][文本]
    if (body.size() < 6) return;
    int related = (int)proto::get_u32(body.data() + 2);
    std::wstring text = Utf8ToWide(std::string(body.begin() + 6, body.end()));

    std::lock_guard<std::mutex> lk(g_sess_mu);
    auto it = g_sessions.find(related);
    if (it != g_sessions.end()) {
        size_t pending = it->second.outbox.size();
        bool established = it->second.crypto.established();
        g_sessions.erase(it);

        if (pending > 0) {
            PostChat(related, 2, text + L"，" + std::to_wstring(pending) + L" 条消息未送达");
        } else if (established) {
            PostChat(related, 2, text + L"，会话已断开，下次发送将重新协商");
        } else {
            PostChat(related, 2, text);
        }
    } else {
        PostChat(related, 2, text);
    }
    PostStatus(text, true);
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

        {
            std::lock_guard<std::mutex> lk(g_net_mu);
            g_sock = sock;
            g_connected.store(true);
        }

        std::wstring title = L"ECDHE 前向保密聊天工具 - 用户 " + std::to_wstring(my_client_id);
        SetWindowTextW(hMainWnd, title.c_str());
        PostMessageW(hMainWnd, WM_LOAD_CHATS, (WPARAM)my_client_id, 0);
        PostStatus(L"已连接服务器 · 我的 ID 是 " + std::to_wstring(my_client_id));

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

            switch (body[1]) {
            case proto::SYSTEM:     HandleSystem(body);           break;
            case proto::HS_INIT:    HandleInit(sender, body);     break;
            case proto::HS_RESP:    HandleResp(sender, body);     break;
            case proto::HS_CONFIRM: HandleConfirm(sender, body);  break;
            case proto::DATA:       HandleData(sender, body);     break;
            default: break;
            }
        }
    } catch (...) {
        // 连接失败/中断，统一在下面处理
    }

    {
        std::lock_guard<std::mutex> lk(g_net_mu);
        if (g_sock) {
            boost::system::error_code ig;
            g_sock->close(ig);
            g_sock.reset();
        }
    }
    g_connected.store(false);

    // 清空会话（重连后必须重新握手）
    {
        std::lock_guard<std::mutex> lk(g_sess_mu);
        g_sessions.clear();
    }

    SetWindowTextW(hMainWnd, L"ECDHE 前向保密聊天工具");
    if (my_client_id == 0)
        PostStatus(L"无法连接服务器（127.0.0.1:9000），正在重试…", true);
    else
        PostStatus(L"与服务器断开，正在重试连接…", true);

    g_connecting.store(false);
}

// ============================================================ 发送消息 ====
static void SendUserMessage(int target, const std::wstring& wtext, bool& queued) {
    queued = false;
    std::string text = WideToUtf8(wtext);

    std::lock_guard<std::mutex> lk(g_sess_mu);
    PeerSession& s = g_sessions[target];
    if (s.crypto.established()) {
        LockedSendChat(target, s, text);
    } else {
        s.outbox.push_back(text);
        queued = true;
        if (s.crypto.state() != securechat::SecureSession::State::Initiating) LockedStartHandshake(target);
    }
}

// ============================================================ 窗口过程 ====
static int S(int value) { return (int)(value * g_scale); }

static void LayoutControls(int w, int h) {
    const int M = S(10);
    const int sessionW = S(150);
    const int statusH = S(22);
    const int inputH = S(30);

    int statusY = h - M - statusH;
    int inputY  = statusY - S(8) - inputH;
    int bodyH   = inputY - S(8) - M;

    MoveWindow(hSessionList, M, M, sessionW, bodyH, TRUE);
    MoveWindow(hChatBox, M + sessionW + S(8), M, w - (sessionW + S(8)) - 2 * M, bodyH, TRUE);

    MoveWindow(hTargetLabel, M, inputY + S(5), S(72), S(20), TRUE);
    MoveWindow(hTargetBox, M + S(76), inputY, S(52), inputH, TRUE);
    MoveWindow(hSendButton, w - M - S(76), inputY, S(76), inputH, TRUE);
    MoveWindow(hInputBox, M + S(136), inputY,
               (w - M - S(76)) - S(8) - (M + S(136)), inputH, TRUE);

    MoveWindow(hStatus, M, statusY, w - 2 * M, statusH, TRUE);
}

static void OnSessionChanged() {
    int sel = (int)SendMessageW(hSessionList, LB_GETCURSEL, 0, 0);
    if (sel < 0) return;
    int peer = (int)SendMessageW(hSessionList, LB_GETITEMDATA, sel, 0);
    if (peer <= 0) return;

    g_activePeer = peer;
    g_unread.erase(peer);
    SetWindowTextW(hTargetBox, std::to_wstring(peer).c_str());
    RefreshChatView();
    RefreshSessionList();
    SetFocus(hInputBox);

    // 若已有会话，回显安全码，方便随时核对
    {
        std::lock_guard<std::mutex> lk(g_sess_mu);
        auto it = g_sessions.find(peer);
        if (it != g_sessions.end() && it->second.crypto.established())
            PostEstablished(peer, it->second.crypto);
    }
}

static void OnSendClicked() {
    wchar_t targetBuf[16] = { 0 };
    GetWindowTextW(hTargetBox, targetBuf, 16);
    int target = _wtoi(targetBuf);

    int n = GetWindowTextLengthW(hInputBox);
    if (n <= 0) return;
    std::wstring text(n, L'\0');
    GetWindowTextW(hInputBox, &text[0], n + 1);
    text.resize(n);

    if (text.empty()) return;
    if (target <= 0) {
        SetFocus(hTargetBox);
        PostStatus(L"请先填写收件人 ID", true);
        return;
    }
    if (target == my_client_id) {
        PostStatus(L"不能给自己发消息", true);
        return;
    }
    if (!g_connected.load()) {
        PostStatus(L"尚未连接服务器，请稍候…", true);
        return;
    }

    bool queued = false;
    SendUserMessage(target, text, queued);

    // 本地回显 + 落盘
    g_activePeer = target;
    SetWindowTextW(hInputBox, L"");
    ApplyChatEvent(target, 1, text);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
    {
        g_hDarkBrush = CreateSolidBrush(RGB(30, 30, 30));

        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));

        g_hFont = CreateFontW(-S(18), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei");
        g_hStatusFont = CreateFontW(-S(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei");

        hSessionList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            0, 0, 0, 0, hwnd, (HMENU)IDC_SESSION_LIST, NULL, NULL);

        hChatBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);

        hTargetLabel = CreateWindowW(L"STATIC", L"收件人 ID:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);

        hTargetBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);

        hInputBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);

        hSendButton = CreateWindowExW(0, L"BUTTON", L"发送",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
            0, 0, 0, 0, hwnd, (HMENU)IDC_SEND, NULL, NULL);

        hStatus = CreateWindowW(L"STATIC", L"正在连接服务器…",
            WS_CHILD | WS_VISIBLE | SS_ENDELLIPSIS | SS_CENTERIMAGE,
            0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS, NULL, NULL);

        for (HWND h : { hSessionList, hChatBox, hInputBox, hSendButton, hTargetBox, hTargetLabel })
            SendMessageW(h, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageW(hStatus, WM_SETFONT, (WPARAM)g_hStatusFont, TRUE);

        SetWindowTheme(hSendButton, L" ", L" ");
        SetWindowTheme(hInputBox, L" ", L" ");
        SetWindowTheme(hTargetBox, L" ", L" ");
        SetWindowTheme(hSessionList, L"DarkMode_Explorer", NULL);

        RECT rc;
        GetClientRect(hwnd, &rc);
        LayoutControls(rc.right, rc.bottom);

        SetFocus(hInputBox);
        return 0;
    }

    case WM_SIZE:
        LayoutControls(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = S(560);
        mmi->ptMinTrackSize.y = S(380);
        return 0;
    }

    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        HWND ctl = (HWND)lParam;

        if (uMsg == WM_CTLCOLORSTATIC && ctl == hStatus) {
            SetTextColor(hdc, g_statusError ? RGB(240, 120, 120) : RGB(150, 150, 150));
            SetBkColor(hdc, RGB(24, 24, 24));
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)g_hDarkBrush;
        }
        SetTextColor(hdc, RGB(220, 220, 220));
        SetBkColor(hdc, RGB(30, 30, 30));
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)g_hDarkBrush;
    }

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
            SendMessageW(hwnd, WM_COMMAND, MAKEWPARAM(IDC_SEND, BN_CLICKED), (LPARAM)hSendButton);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_SEND && HIWORD(wParam) == BN_CLICKED) {
            OnSendClicked();
        } else if (LOWORD(wParam) == IDC_SESSION_LIST && HIWORD(wParam) == LBN_SELCHANGE) {
            OnSessionChanged();
        }
        return 0;

    case WM_CHAT_EVENT:
    {
        ChatEvent* ev = (ChatEvent*)lParam;
        if (ev) {
            ApplyChatEvent(ev->peer, ev->dir, ev->text);
            delete ev;
        }
        return 0;
    }

    case WM_SET_STATUS:
    {
        std::wstring* text = (std::wstring*)lParam;
        if (text) {
            g_statusError = (wParam != 0);
            SetWindowTextW(hStatus, text->c_str());
            InvalidateRect(hStatus, NULL, TRUE);
            delete text;
        }
        return 0;
    }

    case WM_LOAD_CHATS:
    {
        LoadAllChats((int)wParam);
        {
            std::lock_guard<std::mutex> lk(g_sess_mu);
            LoadPins();
        }

        // 自动选中最近一次会话，打开即可看到上次的聊天记录
        int best = 0;
        uint64_t bestTs = 0;
        for (const auto& kv : g_chats) {
            if (!kv.second.empty() && kv.second.back().ts >= bestTs) {
                bestTs = kv.second.back().ts;
                best = kv.first;
            }
        }
        if (best > 0) {
            g_activePeer = best;
            SetWindowTextW(hTargetBox, std::to_wstring(best).c_str());
        }

        RefreshSessionList();
        RefreshChatView();
        return 0;
    }

    case WM_TIMER:
        if (wParam == IDT_RECONNECT) {
            if (!g_connected.load() && !g_connecting.load()) {
                g_connecting.store(true);
                std::thread(NetworkThread).detach();
            }
        }
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_RECONNECT);
        if (g_hDarkBrush) DeleteObject(g_hDarkBrush);
        if (g_hFont) DeleteObject(g_hFont);
        if (g_hStatusFont) DeleteObject(g_hStatusFont);
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

    // 长期身份密钥（Ed25519）
    try {
        std::filesystem::path p = std::filesystem::path(AppDir()) / L"identity.pem";
        g_identity = crypto::ed25519_load_or_create(p.wstring());
        g_my_fingerprint = HexW(crypto::sha256(crypto::ed25519_public_raw(g_identity.get())), 8);
    } catch (...) {
        MessageBoxW(NULL, L"身份密钥初始化失败", L"错误", MB_ICONERROR);
        return 1;
    }

    // 载入历史聊天记录
    LoadAllChats(0);

    const wchar_t* CLASS_NAME = L"ChatWindowClass";
    WNDCLASSW wc = { };
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    hMainWnd = CreateWindowExW(0, CLASS_NAME, L"ECDHE 前向保密聊天工具",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, S(760), S(560), NULL, NULL, hInstance, NULL);
    if (!hMainWnd) return 0;

    ShowWindow(hMainWnd, nCmdShow);
    RefreshSessionList();

    // 首次连接 + 断线重连定时器
    g_connecting.store(true);
    std::thread(NetworkThread).detach();
    SetTimer(hMainWnd, IDT_RECONNECT, 2000, NULL);

    MSG msg = { };
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
