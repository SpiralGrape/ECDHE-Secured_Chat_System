#include <iostream>
#include <boost/asio.hpp>
#include "crypto_utils.h"

using boost::asio::ip::tcp;

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        socket.connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 9000));
        std::cout << "已连接服务器，开始 ECDHE 握手...\n";

        // 1. 生成客户端临时密钥，并发送公钥
        EVP_PKEY* client_key = CryptoUtils::generate_keypair();
        std::vector<unsigned char> client_pub_bytes = CryptoUtils::get_public_key_bytes(client_key);
        boost::asio::write(socket, boost::asio::buffer(client_pub_bytes));

        // 2. 接收服务端公钥
        std::vector<unsigned char> server_pub_bytes(32);
        boost::asio::read(socket, boost::asio::buffer(server_pub_bytes));

        // 3. 计算共享密钥
        EVP_PKEY* server_pub_key = CryptoUtils::load_public_key(server_pub_bytes);
        std::vector<unsigned char> shared_secret = CryptoUtils::derive_shared_secret(client_key, server_pub_key);
        std::vector<unsigned char> aes_key(shared_secret.begin(), shared_secret.begin() + 32);

        std::cout << "✅ ECDHE 握手完成！通道已加密。\n";

        // 4. 发送加密消息
        std::string msg = "这是一条测试消息，服务器你好！";
        std::cout << "准备发送明文: " << msg << std::endl;

        std::vector<unsigned char> packet = CryptoUtils::encrypt(msg, aes_key);
        uint32_t packet_len = packet.size();

        // 先发长度，再发数据包
        boost::asio::write(socket, boost::asio::buffer(&packet_len, 4));
        boost::asio::write(socket, boost::asio::buffer(packet));

        // 5. 接收服务器回复
        uint32_t reply_len;
        boost::asio::read(socket, boost::asio::buffer(&reply_len, 4));
        std::vector<unsigned char> reply_packet(reply_len);
        boost::asio::read(socket, boost::asio::buffer(reply_packet));

        std::string reply_msg = CryptoUtils::decrypt(reply_packet, aes_key);
        std::cout << "[收到服务器回复] " << reply_msg << std::endl;

        // 清理
        EVP_PKEY_free(client_key);
        EVP_PKEY_free(server_pub_key);

    }
    catch (std::exception& e) {
        std::cerr << "客户端异常: " << e.what() << "\n";
    }
    return 0;
}