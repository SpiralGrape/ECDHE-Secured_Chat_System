// ============================================================================
//  密码学自测：验证 ECDHE 握手密钥调度、AEAD、签名与消息级棘轮
//  运行方式：build\Debug\CryptoTest.exe
// ============================================================================

#include <cstdio>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#include "crypto_utils.h"
#include "protocol.h"

using crypto::Bytes;

static int g_pass = 0, g_fail = 0;

static void Check(bool cond, const char* what) {
    if (cond) { ++g_pass; std::printf("  [OK]   %s\n", what); }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", what); }
}

// 与客户端完全一致的密钥调度
static void Derive(const Bytes& z, const Bytes& nonceA, const Bytes& nonceB, bool initiator,
                   Bytes& send_chain, Bytes& recv_chain, Bytes& finished_key) {
    // salt 固定为 nonceA || nonceB（A 为发起方），与角色无关
    Bytes salt = crypto::cat(nonceA, nonceB);
    Bytes secret = crypto::hkdf(z, salt, "CHAT-v1 ECDHE X25519", 32);
    Bytes c_i2r = crypto::hkdf(secret, Bytes{}, "chain initiator->responder", 32);
    Bytes c_r2i = crypto::hkdf(secret, Bytes{}, "chain responder->initiator", 32);
    finished_key = crypto::hkdf(secret, Bytes{}, "finished key", 32);
    send_chain = initiator ? c_i2r : c_r2i;
    recv_chain = initiator ? c_r2i : c_i2r;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::printf("=== ECDHE 安全聊天系统 密码学自测 ===\n\n");

    // ---------------------------------------------------------- 1. 签名 ----
    std::printf("[1] Ed25519 身份签名\n");
    {
        auto idA = crypto::ed25519_generate();
        Bytes pub = crypto::ed25519_public_raw(idA.get());
        Bytes msg = { 'h', 'e', 'l', 'l', 'o' };
        Bytes sig = crypto::ed25519_sign(idA.get(), msg);

        Check(crypto::ed25519_verify(pub, msg, sig), "正确签名可通过验证");

        Bytes bad = msg;
        bad[0] ^= 0x01;
        Check(!crypto::ed25519_verify(pub, bad, sig), "消息被篡改后验证失败");

        auto idB = crypto::ed25519_generate();
        Bytes pubB = crypto::ed25519_public_raw(idB.get());
        Check(!crypto::ed25519_verify(pubB, msg, sig), "冒用他人公钥验证失败");

        // PEM 持久化（宽字符路径）
        std::wstring path = L"D:\\ECDHE_selftest_identity.pem";
        bool saved = crypto::ed25519_save_pem(idA.get(), path);
        Check(saved, "身份私钥可写入 PEM 文件");
        auto loaded = crypto::ed25519_load_pem(path);
        Check(loaded != nullptr, "身份私钥可从 PEM 文件加载");
        if (loaded) {
            Check(crypto::ed25519_public_raw(loaded.get()) == pub, "加载后的身份公钥与原公钥一致");
        }
        _wremove(path.c_str());
    }

    // --------------------------------------------------------- 2. ECDHE ----
    std::printf("\n[2] X25519 临时密钥交换 (ECDHE)\n");
    Bytes z1, z2;
    {
        auto a = crypto::x25519_generate();
        auto b = crypto::x25519_generate();
        Bytes pubA = crypto::x25519_public_raw(a.get());
        Bytes pubB = crypto::x25519_public_raw(b.get());

        auto B = crypto::x25519_from_public_raw(pubB.data(), pubB.size());
        auto A = crypto::x25519_from_public_raw(pubA.data(), pubA.size());
        z1 = crypto::x25519_shared(a.get(), B.get());
        z2 = crypto::x25519_shared(b.get(), A.get());
        Check(z1 == z2, "双方计算出相同的共享秘密");
        Check(z1.size() == 32, "共享秘密长度为 32 字节");

        // 第二次握手（模拟下一次会话）：共享秘密必须不同 → 前向保密
        auto a2 = crypto::x25519_generate();
        auto b2 = crypto::x25519_generate();
        Bytes p2 = crypto::x25519_public_raw(b2.get());
        auto B2 = crypto::x25519_from_public_raw(p2.data(), p2.size());
        Bytes z3 = crypto::x25519_shared(a2.get(), B2.get());
        Check(z1 != z3, "每次握手的共享秘密都不同（会话密钥独立）");
    }

    // ----------------------------------------------------- 3. 密钥调度 ----
    std::printf("\n[3] HKDF 密钥调度（双方会话密钥一致性 + 域分离）\n");
    Bytes nA = crypto::random_bytes(16);
    Bytes nB = crypto::random_bytes(16);
    Bytes sA, rA, fA, sB, rB, fB;
    {
        Derive(z1, nA, nB, true, sA, rA, fA);
        Derive(z1, nA, nB, false, sB, rB, fB);

        Check(sA == rB && rA == sB, "发起方发送链 == 响应方接收链（反之亦然）");
        Check(fA == fB, "双方 Finished 密钥一致");
        Check(sA != rA, "收发方向密钥相互独立（域分离）");

        Bytes other = crypto::hkdf(z1, crypto::cat(nA, nB), "different label", 32);
        Check(other != sA, "不同 info 标签派生出不同密钥");
    }

    // -------------------------------------------------------- 4. AEAD -----
    std::printf("\n[4] AES-256-GCM 认证加密\n");
    {
        Bytes key = sA;
        Bytes nonce = crypto::hkdf(sA, Bytes{}, "message iv", 12);
        Bytes aad = proto::make_aad(proto::DATA, 0x1122334455667788ULL, 0, 1, 2);
        std::string plain = "你好，这是一条端到端加密消息。";

        Bytes ct = crypto::aead_encrypt(key, nonce, plain, aad);
        std::string out;
        Check(crypto::aead_decrypt(key, nonce, ct, aad, out) && out == plain, "密文可正确解密");

        Bytes badAad = aad;
        badAad[2] ^= 0x01;   // 篡改会话号
        Check(!crypto::aead_decrypt(key, nonce, ct, badAad, out), "篡改 AAD 后解密失败");

        Bytes badCt = ct;
        badCt[0] ^= 0x01;
        Check(!crypto::aead_decrypt(key, nonce, badCt, aad, out), "篡改密文后解密失败");

        Bytes wrongKey = rA;
        Check(!crypto::aead_decrypt(wrongKey, nonce, ct, aad, out), "错误密钥解密失败");
    }

    // ------------------------------------------------------- 5. 棘轮 ------
    std::printf("\n[5] 消息级密钥棘轮（消息级前向保密）\n");
    {
        Bytes sSend = sA, rRecv = rB;   // 发起方发送链 vs 响应方接收链
        Bytes oldKey = crypto::hkdf(sSend, Bytes{}, "message key", 32);

        bool all_ok = true;
        for (int i = 0; i < 8; ++i) {
            Bytes mk = crypto::hkdf(sSend, Bytes{}, "message key", 32);
            Bytes iv = crypto::hkdf(sSend, Bytes{}, "message iv", 12);
            Bytes next = crypto::hkdf(sSend, Bytes{}, "chain next", 32);

            Bytes rmk = crypto::hkdf(rRecv, Bytes{}, "message key", 32);
            Bytes riv = crypto::hkdf(rRecv, Bytes{}, "message iv", 12);
            Bytes rnext = crypto::hkdf(rRecv, Bytes{}, "chain next", 32);
            if (mk != rmk || iv != riv) all_ok = false;

            Bytes aad = proto::make_aad(proto::DATA, 1, (uint64_t)i, 1, 2);
            std::string msg = "msg#" + std::to_string(i);
            Bytes ct = crypto::aead_encrypt(mk, iv, msg, aad);
            std::string out;
            if (!crypto::aead_decrypt(rmk, riv, ct, aad, out) || out != msg) all_ok = false;

            sSend = next; rRecv = rnext;
        }
        Check(all_ok, "连续 8 条消息双方棘轮状态同步");

        // 当前链密钥无法还原第 1 条消息的密钥 → 消息级前向保密
        Bytes nowKey = crypto::hkdf(sSend, Bytes{}, "message key", 32);
        Check(nowKey != oldKey, "当前链密钥无法恢复历史消息密钥");
    }

    // --------------------------------------------------------- 结果 ------
    std::printf("\n=== 结果: 通过 %d 项，失败 %d 项 ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
