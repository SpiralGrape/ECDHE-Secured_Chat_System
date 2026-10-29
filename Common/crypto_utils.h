#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

// 简化的加密工具类
class CryptoUtils {
public:
    // 1. 生成 X25519 密钥对
    static EVP_PKEY* generate_keypair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
        return pkey;
    }

    // 2. 导出公钥为字节流 (用于网络发送)
    static std::vector<unsigned char> get_public_key_bytes(EVP_PKEY* pkey) {
        size_t len;
        EVP_PKEY_get_raw_public_key(pkey, NULL, &len);
        std::vector<unsigned char> pub_key(len);
        EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &len);
        return pub_key;
    }

    // 3. 从字节流恢复公钥 (接收方使用)
    static EVP_PKEY* load_public_key(const std::vector<unsigned char>& pub_bytes) {
        return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub_bytes.data(), pub_bytes.size());
    }

    // 4. 计算共享密钥
    static std::vector<unsigned char> derive_shared_secret(EVP_PKEY* my_priv, EVP_PKEY* peer_pub) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_priv, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peer_pub);
        size_t secret_len;
        EVP_PKEY_derive(ctx, NULL, &secret_len);
        std::vector<unsigned char> secret(secret_len);
        EVP_PKEY_derive(ctx, secret.data(), &secret_len);
        EVP_PKEY_CTX_free(ctx);
        return secret;
    }

    // 5. AES-256-GCM 加密 (返回打包好的 IV + 密文 + Tag)
    static std::vector<unsigned char> encrypt(const std::string& plaintext, const std::vector<unsigned char>& key) {
        std::vector<unsigned char> safe_key = key;
        if (safe_key.size() < 32) {
            safe_key.assign(32, 1); // 如果密钥长度不对，强制覆盖为 32 个 1
        }
        std::vector<unsigned char> iv(12);
        RAND_bytes(iv.data(), iv.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());

        std::vector<unsigned char> ciphertext(plaintext.length() + 16);
        int len;
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.length());
        int ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        std::vector<unsigned char> tag(16);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);

        ciphertext.resize(ciphertext_len);

        // 组装数据包：IV(12) + 密文 + Tag(16)
        std::vector<unsigned char> packet = iv;
        packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
        packet.insert(packet.end(), tag.begin(), tag.end());
        return packet;
    }

    // 6. AES-256-GCM 解密
    static std::string decrypt(const std::vector<unsigned char>& packet, const std::vector<unsigned char>& key) {
        std::vector<unsigned char> safe_key = key;
        if (safe_key.size() < 32) {
            safe_key.assign(32, 1); // 如果密钥长度不对，强制覆盖为 32 个 1
        }
        if (packet.size() < 28) return "";
        std::vector<unsigned char> iv(packet.begin(), packet.begin() + 12);
        std::vector<unsigned char> tag(packet.end() - 16, packet.end());
        std::vector<unsigned char> ciphertext(packet.begin() + 12, packet.end() - 16);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data());

        // 准备一个足够大的数组来接收明文
        std::vector<unsigned char> plaintext(ciphertext.size() + 16);
        int len; // 记录 Update 解密的长度
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
        int dec_len; // 记录 Final 校验后追加的长度（GCM通常是0）
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &dec_len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret > 0) {
            // 总长度 = Update 的长度 + Final 的长度
            return std::string((char*)plaintext.data(), len + dec_len);
        }
        return "[解密失败或数据被篡改]";
    } 
};