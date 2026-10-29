#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

struct ClientSession {
    tcp::socket sock;
    int client_id;
    ClientSession(tcp::socket&& s, int id) : sock(std::move(s)), client_id(id) {}
};

std::map<int, std::shared_ptr<ClientSession>> clients;
std::mutex clients_mutex;

void handle_client(std::shared_ptr<ClientSession> client) {
    try {
        // 1. 连上后，第一件事：把分配的 ID 发给客户端
        int my_id = client->client_id;
        boost::asio::write(client->sock, boost::asio::buffer(&my_id, 4));

        while (true) {
            // 2. 读取包裹总长度
            uint32_t packet_len = 0;
            boost::system::error_code error;
            boost::asio::read(client->sock, boost::asio::buffer(&packet_len, 4), error);
            if (error || packet_len < 4) break;

            // 3. 读取包裹：[目标ID(4字节) + 密文]
            std::vector<unsigned char> packet(packet_len);
            boost::asio::read(client->sock, boost::asio::buffer(packet));

            int target_id;
            memcpy(&target_id, packet.data(), 4);
            std::vector<unsigned char> ciphertext(packet.begin() + 4, packet.end());

            std::cout << "[路由器] 收到客户端 " << client->client_id << " 发往 " << target_id << " 的包裹，密文大小: " << ciphertext.size() << " 字节\n";

            // 4. 精准投递
            std::lock_guard<std::mutex> lock(clients_mutex);
            if (clients.find(target_id) != clients.end()) {
                auto& target_client = clients[target_id];
                // 重新打包：[发送者ID(4字节) + 密文]
                int sender_id = client->client_id;
                std::vector<unsigned char> forward_packet(4 + ciphertext.size());
                memcpy(forward_packet.data(), &sender_id, 4);
                memcpy(forward_packet.data() + 4, ciphertext.data(), ciphertext.size());

                uint32_t len = forward_packet.size();
                boost::asio::write(target_client->sock, boost::asio::buffer(&len, 4));
                boost::asio::write(target_client->sock, boost::asio::buffer(forward_packet));
                std::cout << "  -> 成功投递给客户端 " << target_id << "\n";
            }
            else {
                std::cout << "  -> 投递失败：客户端 " << target_id << " 不在线\n";
            }
        }
    }
    catch (...) {}

    // 断开清理
    std::lock_guard<std::mutex> lock(clients_mutex);
    clients.erase(client->client_id);
    std::cout << "[系统] 客户端 " << client->client_id << " 下线。\n";
}

int main() {
    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 9000));
    std::cout << "真正的 E2EE 路由器已启动，监听 9000 端口...\n";

    int next_id = 1;
    for (;;) {
        tcp::socket s(io_context);
        acceptor.accept(s);
        auto client = std::make_shared<ClientSession>(std::move(s), next_id++);
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients[client->client_id] = client;
        }
        std::cout << "[系统] 客户端连入，分配 ID: " << client->client_id << "\n";
        std::thread(handle_client, client).detach();
    }
    return 0;
}