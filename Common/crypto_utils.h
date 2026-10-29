#pragma once
// ============================================================================
//  ECDHE 安全聊天系统 - 密码学原语封装 (OpenSSL 3.x / EVP)
//
//  设计说明：
//   1. 密钥交换：X25519（椭圆曲线迪菲-赫尔曼临时密钥交换 ECDHE）
//   2. 密钥派生：HKDF-SHA256（RFC 5869），用于会话密钥条件化与域分离
//   3. 记录加密：AES-256-GCM（AEAD，带附加认证数据 AAD）
//   4. 身份认证：Ed25519 数字签名（长期主密钥，只签名临时公钥）
//
//  前向保密（PFS）的关键约束：
//   * 会话密钥只由“临时”X25519 私钥派生；
//   * 长期身份私钥仅用于签名，不参与会话密钥生成；
//   * 临时私钥与中间秘密用后立即 OPENSSL_cleanse 清零并释放。
// ============================================================================

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

namespace crypto {

using Bytes = std::vector<unsigned char>;

// ---------------------------------------------------------------- RAII ------
struct PkeyDeleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const { if (p) EVP_CIPHER_CTX_free(p); }
};
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

// ------------------------------------------------------------ 工具函数 ------
// 安全擦除：防止密钥残留在内存或交换文件中
inline void wipe(Bytes& b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
}
inline void wipe(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
}

inline Bytes cat(const Bytes& a, const Bytes& b) {
    Bytes out = a;
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

inline Bytes random_bytes(size_t n) {
    Bytes out(n);
    if (RAND_bytes(out.data(), (int)n) != 1)
        throw std::runtime_error("RAND_bytes 失败");
    return out;
}

inline uint64_t random_u64() {
    Bytes b = random_bytes(8);
    uint64_t v = 0;
    std::memcpy(&v, b.data(), 8);
    return v;
}

// ============================================================ X25519 ========
// 生成临时（ephemeral）X25519 密钥对。每次握手都必须重新调用。
inline PkeyPtr x25519_generate() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) throw std::runtime_error("x25519: 无法创建上下文");

    EVP_PKEY* pkey = nullptr;
    bool ok = EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0;
    EVP_PKEY_CTX_free(ctx);
    if (!ok || !pkey) throw std::runtime_error("x25519: 密钥生成失败");
    return PkeyPtr(pkey);
}

// 导出 32 字节原始公钥（可在网络上传输）
inline Bytes x25519_public_raw(EVP_PKEY* pkey) {
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) <= 0)
        throw std::runtime_error("x25519: 读取公钥长度失败");
    Bytes out(len);
    if (EVP_PKEY_get_raw_public_key(pkey, out.data(), &len) <= 0)
        throw std::runtime_error("x25519: 读取公钥失败");
    out.resize(len);
    return out;
}

// 由 32 字节原始公钥还原 EVP_PKEY
inline PkeyPtr x25519_from_public_raw(const unsigned char* data, size_t len) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, data, len);
    if (!pkey) throw std::runtime_error("x25519: 公钥格式非法");
    return PkeyPtr(pkey);
}

// 计算共享秘密 Z = X25519(my_priv, peer_pub)
inline Bytes x25519_shared(EVP_PKEY* my_priv, EVP_PKEY* peer_pub) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_priv, nullptr);
    if (!ctx) throw std::runtime_error("x25519: 无法创建派生上下文");

    Bytes secret;
    size_t len = 0;
    bool ok = EVP_PKEY_derive_init(ctx) > 0 &&
              EVP_PKEY_derive_set_peer(ctx, peer_pub) > 0 &&
              EVP_PKEY_derive(ctx, nullptr, &len) > 0;
    if (ok) {
        secret.resize(len);
        ok = EVP_PKEY_derive(ctx, secret.data(), &len) > 0;
        secret.resize(len);
    }
    EVP_PKEY_CTX_free(ctx);
    if (!ok) throw std::runtime_error("x25519: 共享秘密计算失败");
    return secret;
}

// ============================================================== HKDF ========
// HKDF-SHA256 (extract-and-expand)。从同一共享秘密派生多把用途不同的密钥，
// 实现密码学中的“域分离”(domain separation)。
inline Bytes hkdf(const Bytes& ikm, const Bytes& salt, const std::string& info, size_t out_len) {
    static const unsigned char kZero = 0;
    const unsigned char* salt_ptr = salt.empty() ? &kZero : salt.data();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) throw std::runtime_error("hkdf: 无法创建上下文");

    Bytes out(out_len);
    size_t len = out_len;
    bool ok = EVP_PKEY_derive_init(ctx) > 0;
    if (ok) ok = EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0;
    if (ok) ok = EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt_ptr, (int)salt.size()) > 0;
    if (ok) ok = EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), (int)ikm.size()) > 0;
    if (ok) ok = EVP_PKEY_CTX_add1_hkdf_info(ctx,
                        reinterpret_cast<const unsigned char*>(info.data()), (int)info.size()) > 0;
    if (ok) ok = EVP_PKEY_derive(ctx, out.data(), &len) > 0;
    EVP_PKEY_CTX_free(ctx);
    if (!ok) throw std::runtime_error("hkdf: 派生失败");
    out.resize(len);
    return out;
}

// ============================================================== 摘要 ========
inline Bytes sha256(const Bytes& data) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("sha256 失败");
    out.resize(len);
    return out;
}

// HMAC-SHA256（用于 Finished 校验，证明双方派生出相同的会话密钥）
inline Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes out(32);
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), (int)key.size(),
              data.data(), data.size(), out.data(), &len))
        throw std::runtime_error("hmac 失败");
    out.resize(len);
    return out;
}

// ====================================================== AES-256-GCM ========
// 加密：返回 密文 || Tag(16)。nonce 由密钥棘轮派生，绝不复用。
inline Bytes aead_encrypt(const Bytes& key, const Bytes& nonce,
                          const std::string& plaintext, const Bytes& aad) {
    if (key.size() != 32) throw std::runtime_error("AES-256 需要 32 字节密钥");

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("aead: ctx");

    Bytes out(plaintext.size() + 16);
    int len = 0, total = 0;
    bool ok = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) == 1;
    if (ok) ok = EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) == 1;
    // AAD：把帧头（会话号/序号/收发方）绑定进 Tag，中继服务器无法篡改
    if (ok && !aad.empty())
        ok = EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) == 1;
    if (ok && !plaintext.empty())
        ok = EVP_EncryptUpdate(ctx.get(), out.data(), &len,
                               reinterpret_cast<const unsigned char*>(plaintext.data()),
                               (int)plaintext.size()) == 1;
    if (ok) { total = len; ok = EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &len) == 1; }
    if (!ok) throw std::runtime_error("aead: 加密失败");
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) != 1)
        throw std::runtime_error("aead: 取 Tag 失败");
    out.resize(total + 16);
    return out;
}

// 解密：in = 密文 || Tag(16)。返回 false 表示认证失败（被篡改或密钥错误）。
inline bool aead_decrypt(const Bytes& key, const Bytes& nonce,
                         const Bytes& in, const Bytes& aad, std::string& out) {
    if (key.size() != 32 || in.size() < 16) return false;
    const size_t ct_len = in.size() - 16;

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return false;

    std::vector<unsigned char> tag(in.end() - 16, in.end());
    std::vector<char> buf(ct_len + 16);
    int len = 0, total = 0;

    bool ok = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) == 1;
    if (ok) ok = EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) == 1;
    if (ok && !aad.empty())
        ok = EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) == 1;
    if (ok && ct_len > 0)
        ok = EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(buf.data()), &len,
                               in.data(), (int)ct_len) == 1;
    if (!ok) return false;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) return false;
    if (EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(buf.data()) + total, &len) <= 0)
        return false;   // 认证失败
    total += len;
    out.assign(buf.data(), (size_t)total);
    return true;
}

// ============================================================ Ed25519 ======
// 长期身份密钥（“主密钥”）：只签名临时公钥，永不参与会话密钥派生。
// 因此即使主密钥泄露，历史会话密钥依然安全 —— 这就是前向保密。
inline PkeyPtr ed25519_generate() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) throw std::runtime_error("ed25519: ctx");
    EVP_PKEY* pkey = nullptr;
    bool ok = EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0;
    EVP_PKEY_CTX_free(ctx);
    if (!ok || !pkey) throw std::runtime_error("ed25519: 密钥生成失败");
    return PkeyPtr(pkey);
}

inline Bytes ed25519_public_raw(EVP_PKEY* pkey) {
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) <= 0)
        throw std::runtime_error("ed25519: 读取公钥失败");
    Bytes out(len);
    if (EVP_PKEY_get_raw_public_key(pkey, out.data(), &len) <= 0)
        throw std::runtime_error("ed25519: 读取公钥失败");
    out.resize(len);
    return out;
}

// 导出 32 字节原始私钥（仅用于派生本地存储密钥，不得外传）
inline Bytes ed25519_private_raw(EVP_PKEY* pkey) {
    size_t len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &len) <= 0)
        throw std::runtime_error("ed25519: 读取私钥失败");
    Bytes out(len);
    if (EVP_PKEY_get_raw_private_key(pkey, out.data(), &len) <= 0)
        throw std::runtime_error("ed25519: 读取私钥失败");
    out.resize(len);
    return out;
}

// 内存版 PEM 编解码（配合 DPAPI 等外部保护机制使用）
inline std::string ed25519_to_pem(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return std::string();
    std::string out;
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
        char* p = nullptr;
        long len = BIO_get_mem_data(bio, &p);
        if (len > 0) out.assign(p, (size_t)len);
    }
    BIO_free(bio);
    return out;
}

inline PkeyPtr ed25519_from_pem(const std::string& pem) {
    if (pem.empty()) return PkeyPtr(nullptr);
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return PkeyPtr(nullptr);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return PkeyPtr(pkey);
}

inline Bytes ed25519_sign(EVP_PKEY* priv, const Bytes& msg) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("ed25519: md ctx");
    Bytes sig(64);
    size_t sig_len = sig.size();
    bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, priv) == 1 &&
              EVP_DigestSign(ctx, sig.data(), &sig_len, msg.data(), msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) throw std::runtime_error("ed25519: 签名失败");
    sig.resize(sig_len);
    return sig;
}

inline bool ed25519_verify(const Bytes& pub, const Bytes& msg, const Bytes& sig) {
    EVP_PKEY* raw = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!raw) return false;
    PkeyPtr key(raw);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key.get()) == 1 &&
              EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

// 身份密钥持久化（PEM 格式），保证“长期主密钥”在重启后保持不变。
// 说明：
//   * 使用宽字符路径，支持中文用户名（如 C:\Users\张三）；
//   * 使用内存 BIO + 自行读写文件，避免 OpenSSL 静态库在 Windows 上
//     对 FILE* 接口要求 OPENSSL_Applink 的问题。
inline PkeyPtr ed25519_load_pem(const std::wstring& path) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return PkeyPtr(nullptr);

    std::string data;
    char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
    fclose(f);
    if (data.empty()) return PkeyPtr(nullptr);

    BIO* bio = BIO_new_mem_buf(data.data(), (int)data.size());
    if (!bio) return PkeyPtr(nullptr);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return PkeyPtr(pkey);
}

inline bool ed25519_save_pem(EVP_PKEY* pkey, const std::wstring& path) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;

    bool ok = PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    if (ok) {
        char* p = nullptr;
        long len = BIO_get_mem_data(bio, &p);
        FILE* f = nullptr;
        if (len > 0 && _wfopen_s(&f, path.c_str(), L"wb") == 0 && f) {
            ok = fwrite(p, 1, (size_t)len, f) == (size_t)len;
            fclose(f);
        } else {
            ok = false;
        }
    }
    BIO_free(bio);
    return ok;
}

// 加载或创建身份密钥
inline PkeyPtr ed25519_load_or_create(const std::wstring& path) {
    PkeyPtr k = ed25519_load_pem(path);
    if (k) return k;
    k = ed25519_generate();
    ed25519_save_pem(k.get(), path);   // 保存失败不致命
    return k;
}

} // namespace crypto
