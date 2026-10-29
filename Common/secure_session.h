#pragma once
// ============================================================================
//  SecureSession —— 可复用的 ECDHE 安全会话（握手 + 记录层）
//
//  被客户端（正常通信）与 MITM 演示工具（攻击方）共同使用：
//  只要两边都按同一份代码实现协议，演示结果才有说服力。
//
//  协议要点（详见 protocol.h）：
//    INIT/RESP/CONFIRM 三次握手，X25519 临时密钥 + Ed25519 身份签名
//    HKDF-SHA256 派生双向链密钥，消息级棘轮
//    AES-256-GCM 加密，AAD 绑定会话号/序号/收发方
//
//  安全码（SAS）：
//    握手完成后，双方对 transcript 计算 6 位数字。若中间人插入了两段独立
//    握手，两侧算出的安全码必然不同 —— 用户口头核对即可发现 MITM。
// ============================================================================

#include <cstdio>
#include <deque>
#include <string>

#include "crypto_utils.h"
#include "protocol.h"

namespace securechat {

class SecureSession {
public:
    using Bytes = crypto::Bytes;

    enum class State { None, Initiating, Responding, Established };

    SecureSession() = default;
    SecureSession(const SecureSession&) = delete;
    SecureSession& operator=(const SecureSession&) = delete;
    SecureSession(SecureSession&&) = default;
    SecureSession& operator=(SecureSession&&) = default;

    State state() const { return state_; }
    bool  established() const { return state_ == State::Established; }
    uint64_t sid() const { return sid_; }
    const std::string& fingerprint() const { return fingerprint_; }   // 会话密钥指纹
    const std::string& sas() const { return sas_; }                   // 6 位安全码
    const Bytes& peerIdentity() const { return peer_idpub_; }         // 对端身份公钥

    void Reset() { *this = SecureSession(); }

    // ---------------------------------------------------------- 握手 ------
    // 发起方：生成临时密钥并产出 INIT 载荷
    bool BuildInit(uint64_t sid, int myId, int peerId, EVP_PKEY* identity,
                   Bytes& out, std::string& err);

    // 响应方：校验 INIT 并产出 RESP 载荷
    bool HandleInit(const Bytes& in, int myId, int peerId, EVP_PKEY* identity,
                    Bytes& out, std::string& err);

    // 发起方：校验 RESP 并产出 CONFIRM 载荷
    bool HandleResp(const Bytes& in, int myId, int peerId,
                    Bytes& out, std::string& err);

    // 响应方：校验 CONFIRM
    bool HandleConfirm(const Bytes& in, std::string& err);

    // -------------------------------------------------------- 记录层 ------
    bool Seal(int myId, int peerId, const std::string& plain, Bytes& out, std::string& err);
    bool Open(int myId, int peerId, const Bytes& in, std::string& plain, std::string& err);

private:
    static Bytes TranscriptHash(const Bytes& a, const Bytes& b) {
        return crypto::sha256(crypto::cat(a, b));
    }

    bool Derive(bool initiator, std::string& err);
    void ComputeSas();

    State    state_ = State::None;
    uint64_t sid_ = 0;

    crypto::PkeyPtr eph_;                      // 临时私钥（派生后立即销毁）
    Bytes my_pub_, my_nonce_, my_idpub_;
    Bytes peer_pub_, peer_nonce_, peer_idpub_;

    Bytes init_msg_, resp_msg_;                // transcript 组成
    Bytes send_chain_, recv_chain_, finished_key_;
    uint64_t send_seq_ = 0, recv_seq_ = 0;

    std::string fingerprint_, sas_;
};

// ============================================================ 握手 ========
inline bool SecureSession::BuildInit(uint64_t sid, int myId, int peerId,
                                     EVP_PKEY* identity, Bytes& out, std::string& err) {
    Reset();
    state_ = State::Initiating;
    sid_   = sid;

    try {
        eph_      = crypto::x25519_generate();
        my_pub_   = crypto::x25519_public_raw(eph_.get());
        my_nonce_ = crypto::random_bytes(proto::NONCE_LEN);
        my_idpub_ = crypto::ed25519_public_raw(identity);
    } catch (std::exception& e) {
        err = e.what();
        state_ = State::None;
        return false;
    }

    Bytes msg;
    msg.push_back(proto::VERSION);
    msg.push_back(proto::HS_INIT);
    proto::append_u64(msg, sid_);
    proto::append(msg, my_pub_);
    proto::append(msg, my_nonce_);
    proto::append(msg, my_idpub_);
    proto::append_u32(msg, (uint32_t)myId);
    proto::append_u32(msg, (uint32_t)peerId);

    try {
        Bytes sig = crypto::ed25519_sign(identity, msg);
        proto::append(msg, sig);
    } catch (std::exception& e) {
        err = e.what();
        state_ = State::None;
        return false;
    }

    init_msg_ = msg;
    out = msg;
    return true;
}

inline bool SecureSession::HandleInit(const Bytes& in, int myId, int peerId,
                                      EVP_PKEY* identity, Bytes& out, std::string& err) {
    if (in.size() != proto::HS_INIT_LEN) { err = "INIT 长度非法"; return false; }

    const uint64_t sid = proto::get_u64(in.data() + 2);
    Bytes pubA         = proto::slice(in, 10, proto::X25519_LEN);
    Bytes nonceA       = proto::slice(in, 42, proto::NONCE_LEN);
    Bytes idpubA       = proto::slice(in, 58, proto::ED25519_LEN);
    const uint32_t idA = proto::get_u32(in.data() + 90);
    const uint32_t idB = proto::get_u32(in.data() + 94);
    Bytes sigA         = proto::slice(in, 98, proto::SIG_LEN);

    if ((int)idA != peerId || (int)idB != myId) { err = "INIT 收发方不匹配"; return false; }
    if (!crypto::ed25519_verify(idpubA, proto::slice(in, 0, proto::HS_INIT_BASE), sigA)) {
        err = "对端身份签名无效";
        return false;
    }

    Reset();
    state_      = State::Responding;
    sid_        = sid;
    peer_pub_   = pubA;
    peer_nonce_ = nonceA;
    peer_idpub_ = idpubA;
    init_msg_   = in;

    try {
        eph_      = crypto::x25519_generate();
        my_pub_   = crypto::x25519_public_raw(eph_.get());
        my_nonce_ = crypto::random_bytes(proto::NONCE_LEN);
        my_idpub_ = crypto::ed25519_public_raw(identity);

        Bytes resp;
        resp.push_back(proto::VERSION);
        resp.push_back(proto::HS_RESP);
        proto::append_u64(resp, sid_);
        proto::append(resp, my_pub_);
        proto::append(resp, my_nonce_);
        proto::append(resp, my_idpub_);

        Bytes to_sign = resp;
        proto::append(to_sign, sigA);
        Bytes sigB = crypto::ed25519_sign(identity, to_sign);
        proto::append(resp, sigB);          // 前 154 字节

        if (!Derive(/*initiator=*/false, err)) { state_ = State::None; return false; }

        Bytes th = TranscriptHash(init_msg_, resp);
        Bytes mi = th;
        mi.push_back('B');
        Bytes macB = crypto::hmac_sha256(finished_key_, mi);

        resp_msg_ = resp;
        out = resp;
        proto::append(out, macB);
        return true;
    } catch (std::exception& e) {
        err = e.what();
        state_ = State::None;
        return false;
    }
}

inline bool SecureSession::HandleResp(const Bytes& in, int myId, int peerId,
                                      Bytes& out, std::string& err) {
    if (state_ != State::Initiating) { err = "状态不匹配（期望 Initiating）"; return false; }
    if (in.size() != proto::HS_RESP_LEN) { err = "RESP 长度非法"; return false; }
    if (proto::get_u64(in.data() + 2) != sid_) { err = "会话号不匹配"; return false; }

    Bytes pubB      = proto::slice(in, 10, proto::X25519_LEN);
    Bytes nonceB    = proto::slice(in, 42, proto::NONCE_LEN);
    Bytes idpubB    = proto::slice(in, 58, proto::ED25519_LEN);
    Bytes sigB      = proto::slice(in, 90, proto::SIG_LEN);
    Bytes macB      = proto::slice(in, proto::HS_RESP_SIGN, proto::KEY_LEN);
    Bytes resp_core = proto::slice(in, 0, proto::HS_RESP_SIGN);

    // 签名覆盖：RESP 前 90 字节 + 我方 INIT 的签名
    Bytes sigA = proto::slice(init_msg_, proto::HS_INIT_BASE, proto::SIG_LEN);
    Bytes to_sign = proto::slice(in, 0, proto::HS_RESP_BASE);
    proto::append(to_sign, sigA);
    if (!crypto::ed25519_verify(idpubB, to_sign, sigB)) { err = "对端响应签名无效"; return false; }

    peer_pub_   = pubB;
    peer_nonce_ = nonceB;
    peer_idpub_ = idpubB;

    if (!Derive(/*initiator=*/true, err)) { state_ = State::None; return false; }

    Bytes th = TranscriptHash(init_msg_, resp_core);
    Bytes mi = th;
    mi.push_back('B');
    if (crypto::hmac_sha256(finished_key_, mi) != macB) {
        err = "会话密钥确认失败";
        state_ = State::None;
        return false;
    }

    resp_msg_ = resp_core;

    Bytes ma = th;
    ma.push_back('A');
    Bytes macA = crypto::hmac_sha256(finished_key_, ma);

    out.clear();
    out.push_back(proto::VERSION);
    out.push_back(proto::HS_CONFIRM);
    proto::append_u64(out, sid_);
    proto::append(out, macA);

    state_ = State::Established;
    ComputeSas();
    return true;
}

inline bool SecureSession::HandleConfirm(const Bytes& in, std::string& err) {
    if (state_ != State::Responding) { err = "状态不匹配（期望 Responding）"; return false; }
    if (in.size() != proto::HS_CONFIRM_LEN) { err = "CONFIRM 长度非法"; return false; }
    if (proto::get_u64(in.data() + 2) != sid_) { err = "会话号不匹配"; return false; }

    Bytes macA = proto::slice(in, 10, proto::KEY_LEN);
    Bytes th = TranscriptHash(init_msg_, resp_msg_);
    Bytes ma = th;
    ma.push_back('A');
    if (crypto::hmac_sha256(finished_key_, ma) != macA) {
        err = "对端握手确认无效";
        state_ = State::None;
        return false;
    }

    state_ = State::Established;
    ComputeSas();
    return true;
}

// ========================================================== 密钥派生 ======
inline bool SecureSession::Derive(bool initiator, std::string& err) {
    try {
        crypto::PkeyPtr peer = crypto::x25519_from_public_raw(peer_pub_.data(), peer_pub_.size());
        Bytes z = crypto::x25519_shared(eph_.get(), peer.get());

        // salt 固定为 nonceA || nonceB（A = 发起方）
        Bytes salt = initiator ? crypto::cat(my_nonce_, peer_nonce_)
                               : crypto::cat(peer_nonce_, my_nonce_);

        Bytes secret = crypto::hkdf(z, salt, "CHAT-v1 ECDHE X25519", 32);
        Bytes c_i2r  = crypto::hkdf(secret, Bytes{}, "chain initiator->responder", 32);
        Bytes c_r2i  = crypto::hkdf(secret, Bytes{}, "chain responder->initiator", 32);
        finished_key_ = crypto::hkdf(secret, Bytes{}, "finished key", 32);

        crypto::wipe(send_chain_);
        crypto::wipe(recv_chain_);
        send_chain_ = initiator ? c_i2r : c_r2i;
        recv_chain_ = initiator ? c_r2i : c_i2r;

        fingerprint_.clear();
        {
            static const char* hex = "0123456789abcdef";
            Bytes fp = crypto::sha256(secret);
            for (size_t i = 0; i < 8 && i < fp.size(); ++i) {
                fingerprint_.push_back(hex[fp[i] >> 4]);
                fingerprint_.push_back(hex[fp[i] & 0x0F]);
            }
        }

        crypto::wipe(z);
        crypto::wipe(secret);
        crypto::wipe(c_i2r);
        crypto::wipe(c_r2i);

        // 前向保密关键：临时私钥用完即毁
        eph_.reset();
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

inline void SecureSession::ComputeSas() {
    try {
        Bytes th = TranscriptHash(init_msg_, resp_msg_);
        Bytes s = crypto::sha256(crypto::cat(th, Bytes{ 'S', 'A', 'S' }));
        uint32_t v = (((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16) |
                      ((uint32_t)s[2] << 8) | (uint32_t)s[3]) % 1000000u;
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%06u", v);
        sas_ = buf;
    } catch (...) {
        sas_.clear();
    }
}

// ============================================================ 记录层 ======
inline bool SecureSession::Seal(int myId, int peerId, const std::string& plain,
                                Bytes& out, std::string& err) {
    if (state_ != State::Established) { err = "会话未建立"; return false; }

    try {
        Bytes msg_key = crypto::hkdf(send_chain_, Bytes{}, "message key", 32);
        Bytes nonce   = crypto::hkdf(send_chain_, Bytes{}, "message iv", 12);
        Bytes next    = crypto::hkdf(send_chain_, Bytes{}, "chain next", 32);

        Bytes aad = proto::make_aad(proto::DATA, sid_, send_seq_, myId, peerId);
        Bytes ct  = crypto::aead_encrypt(msg_key, nonce, plain, aad);

        out.clear();
        out.push_back(proto::VERSION);
        out.push_back(proto::DATA);
        proto::append_u64(out, sid_);
        proto::append_u64(out, send_seq_);
        proto::append(out, ct);
        send_seq_++;

        crypto::wipe(send_chain_);
        send_chain_ = next;
        crypto::wipe(msg_key);
        crypto::wipe(nonce);
        crypto::wipe(next);
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

inline bool SecureSession::Open(int myId, int peerId, const Bytes& in,
                                std::string& plain, std::string& err) {
    if (state_ != State::Established) { err = "会话未建立"; return false; }
    if (in.size() < proto::DATA_MIN) { err = "DATA 长度非法"; return false; }

    const uint64_t sid = proto::get_u64(in.data() + 2);
    const uint64_t seq = proto::get_u64(in.data() + 10);
    if (sid != sid_) { err = "会话号不匹配"; return false; }
    if (seq != recv_seq_) { err = "序号失步或重放"; return false; }

    Bytes ct = proto::slice(in, proto::DATA_HEADER, in.size() - proto::DATA_HEADER);

    try {
        Bytes msg_key = crypto::hkdf(recv_chain_, Bytes{}, "message key", 32);
        Bytes nonce   = crypto::hkdf(recv_chain_, Bytes{}, "message iv", 12);
        Bytes next    = crypto::hkdf(recv_chain_, Bytes{}, "chain next", 32);

        Bytes aad = proto::make_aad(proto::DATA, sid, seq, peerId, myId);
        bool ok = crypto::aead_decrypt(msg_key, nonce, ct, aad, plain);

        crypto::wipe(msg_key);
        crypto::wipe(nonce);

        if (!ok) {
            crypto::wipe(next);
            err = "消息认证失败";
            return false;
        }

        crypto::wipe(recv_chain_);
        recv_chain_ = next;
        crypto::wipe(next);
        recv_seq_++;
        return true;
    } catch (std::exception& e) {
        err = e.what();
        return false;
    }
}

} // namespace securechat
