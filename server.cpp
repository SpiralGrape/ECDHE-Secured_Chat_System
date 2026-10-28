#include <iostream>
#include <boost/asio.hpp>
#include "crypto_utils.h"

using boost::asio::ip::tcp;

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 9000));
        std::cout << "安全服务器已启动，监听 9000 端口...\n";

        for (;;) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);
            std::cout << "有客户端连上了，开始 ECDHE 握手...\n";

            // 1. 接收客户端公钥 (X25519 公钥固定 32 字节)
            std::vector<unsigned char> client_pub_bytes(32);
            boost::asio::read(socket, boost::asio::buffer(client_pub_bytes));

            // 2. 生成服务端临时密钥对，并发送公钥
            EVP_PKEY* server_key = CryptoUtils::generate_keypair();
            std::vector<unsigned char> server_pub_bytes = CryptoUtils::get_public_key_bytes(server_key);
            boost::asio::write(socket, boost::asio::buffer(server_pub_bytes));

            // 3. 计算共享密钥
            EVP_PKEY* client_pub_key = CryptoUtils::load_public_key(client_pub_bytes);
            std::vector<unsigned char> shared_secret = CryptoUtils::derive_shared_secret(server_key, client_pub_key);
            // 截取前32字节作为 AES Key
            std::vector<unsigned char> aes_key(shared_secret.begin(), shared_secret.begin() + 32);

            std::cout << " ECDHE 握手完成！准备接收加密消息...\n";

            // 4. 循环接收加密数据并解密
            for (;;) {
                // 先读 4 个字节，代表数据包长度
                uint32_t packet_len;
                boost::system::error_code error;
                boost::asio::read(socket, boost::asio::buffer(&packet_len, 4), error);
                if (error == boost::asio::error::eof) break; // 断开

                // 读具体的数据包
                std::vector<unsigned char> packet(packet_len);
                boost::asio::read(socket, boost::asio::buffer(packet));

                // 解密
                std::string decrypted_msg = CryptoUtils::decrypt(packet, aes_key);
                std::cout << "[收到并解密] " << decrypted_msg << std::endl;

                // 原路加密发回去（Echo）
                std::vector<unsigned char> reply_packet = CryptoUtils::encrypt("服务器已收到你的加密消息!", aes_key);
                uint32_t reply_len = reply_packet.size();
                boost::asio::write(socket, boost::asio::buffer(&reply_len, 4));
                boost::asio::write(socket, boost::asio::buffer(reply_packet));
            }

            // 清理资源
            EVP_PKEY_free(server_key);
            EVP_PKEY_free(client_pub_key);
            std::cout << "客户端断开连接。\n";
        }
    }
    catch (std::exception& e) {
        std::cerr << "服务器异常: " << e.what() << "\n";
    }
    return 0;
}