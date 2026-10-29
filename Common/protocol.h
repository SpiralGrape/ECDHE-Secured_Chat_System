#pragma once
// ============================================================================
//  协议定义（客户端 <-> 中继服务器 <-> 客户端）
//
//  外层帧（TCP 上每条消息）：
//      [ uint32 长度 ][ uint32 源/目标ID ][ payload ]
//      长度 = 4 + payload.size()
//
//  payload 由 1 字节版本号 + 1 字节类型 + 具体字段组成。
//
//  握手（端到端，服务器只转发、不可解密）：
//      INIT    : A -> B   携带临时公钥 pubA、随机数 nonceA、身份公钥 idpubA、签名
//      RESP    : B -> A   携带 pubB、nonceB、idpubB、签名 + Finished(B)
//      CONFIRM : A -> B   Finished(A)，双方确认派生出一致的会话密钥
//
//  记录层：
//      DATA    : ver|type|sid|seq|AES-256-GCM(消息密钥, nonce, 明文, AAD)
//
//  密钥派生：
//      Z       = X25519(临时私钥, 对端临时公钥)
//      secret  = HKDF(Z, salt = nonceA||nonceB, "CHAT-v1 ECDHE X25519")
//      chain   = HKDF(secret, "", "chain initiator->responder" / "... responder->initiator")
//      finish  = HKDF(secret, "", "finished key")
//  ============================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace proto {

using Bytes = std::vector<unsigned char>;

constexpr uint8_t  VERSION     = 1;
constexpr uint32_t MAX_PAYLOAD = 1u << 20;   // 单帧上限 1 MiB，防内存耗尽
constexpr uint32_t MAX_FRAME   = MAX_PAYLOAD; // 长度字段本身的最大合法值

// 消息类型
enum MsgType : uint8_t {
    HS_INIT    = 0x01,   // A -> B  握手请求
    HS_RESP    = 0x02,   // B -> A  握手响应
    HS_CONFIRM = 0x03,   // A -> B  握手确认
    DATA       = 0x10,   // 加密聊天数据
    SYSTEM     = 0xFF,   // 服务器通知（明文，仅用于提示）
};

// 各字段长度
constexpr size_t SID_LEN      = 8;
constexpr size_t NONCE_LEN    = 16;
constexpr size_t X25519_LEN   = 32;
constexpr size_t ED25519_LEN  = 32;
constexpr size_t SIG_LEN      = 64;
constexpr size_t KEY_LEN      = 32;
constexpr size_t TAG_LEN      = 16;
constexpr size_t IV_LEN       = 12;

// INIT 载荷： [ver][type][sid][pubA][nonceA][idpubA][idA][idB][sig]
constexpr size_t HS_INIT_BASE = 2 + SID_LEN + X25519_LEN + NONCE_LEN + ED25519_LEN + 8;  // 98
constexpr size_t HS_INIT_LEN  = HS_INIT_BASE + SIG_LEN;                                 // 162

// RESP 载荷： [ver][type][sid][pubB][nonceB][idpubB][sigB][mac]  (签名覆盖 INIT + 自身前 90 字节)
constexpr size_t HS_RESP_BASE = 2 + SID_LEN + X25519_LEN + NONCE_LEN + ED25519_LEN;     // 90
constexpr size_t HS_RESP_SIGN = HS_RESP_BASE + SIG_LEN;                                 // 154
constexpr size_t HS_RESP_LEN  = HS_RESP_SIGN + KEY_LEN;                                 // 186

// CONFIRM 载荷：[ver][type][sid][mac]
constexpr size_t HS_CONFIRM_LEN = 2 + SID_LEN + KEY_LEN;   // 42

// DATA 载荷： [ver][type][sid][seq][密文||Tag]
constexpr size_t DATA_HEADER = 2 + SID_LEN + 8;            // 18
constexpr size_t DATA_MIN    = DATA_HEADER + TAG_LEN;      // 34

// ---------------------------------------------------------------- 编解码 ----
inline void put_u32(unsigned char* p, uint32_t v) { std::memcpy(p, &v, 4); }
inline void put_u64(unsigned char* p, uint64_t v) { std::memcpy(p, &v, 8); }
inline uint32_t get_u32(const unsigned char* p) { uint32_t v = 0; std::memcpy(&v, p, 4); return v; }
inline uint64_t get_u64(const unsigned char* p) { uint64_t v = 0; std::memcpy(&v, p, 8); return v; }

inline void append(Bytes& dst, const void* data, size_t len) {
    const unsigned char* p = static_cast<const unsigned char*>(data);
    dst.insert(dst.end(), p, p + len);
}
inline void append(Bytes& dst, const Bytes& src) { append(dst, src.data(), src.size()); }
inline void append_u32(Bytes& dst, uint32_t v) { unsigned char b[4]; put_u32(b, v); append(dst, b, 4); }
inline void append_u64(Bytes& dst, uint64_t v) { unsigned char b[8]; put_u64(b, v); append(dst, b, 8); }

inline Bytes slice(const Bytes& src, size_t off, size_t len) {
    return Bytes(src.begin() + off, src.begin() + off + len);
}

// AAD：把帧头绑定进 AEAD 认证标签，任何篡改都会导致解密失败
inline Bytes make_aad(uint8_t type, uint64_t sid, uint64_t seq, int sender, int target) {
    Bytes aad;
    aad.reserve(2 + SID_LEN + 8 + 8);
    aad.push_back(VERSION);
    aad.push_back(type);
    append_u64(aad, sid);
    append_u64(aad, seq);
    append_u32(aad, (uint32_t)sender);
    append_u32(aad, (uint32_t)target);
    return aad;
}

} // namespace proto
