#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include <openssl/evp.h>
#include "crypto_utils.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "libcrypto.lib")
using boost::asio::ip::tcp;

HWND hChatBox = NULL, hInputBox = NULL, hTargetBox = NULL, hSendButton = NULL, hMainWnd = NULL;
std::shared_ptr<tcp::socket> global_socket = nullptr;
int my_client_id = 0; // 服务器分配的ID

#define WM_APPEND_CHAT (WM_APP + 1)

// 动态生成基于 ID 的密钥 (用户 1 就是 32 个 '1')
std::vector<unsigned char> get_user_key(int id) {
    return std::vector<unsigned char>(32, (unsigned char)id);
}

void NetworkThread() {
    try {
        boost::asio::io_context io_context;
        global_socket = std::make_shared<tcp::socket>(io_context);
        global_socket->connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 9000));

        // 接收服务器分配给我的 ID
        boost::asio::read(*global_socket, boost::asio::buffer(&my_client_id, 4));
        std::string hello_msg = "系统: 连接成功！你的专属ID是 " + std::to_string(my_client_id) + "\r\n";
        PostMessage(hMainWnd, WM_APPEND_CHAT, 0, (LPARAM)new std::string(hello_msg));

        while (true) {
            uint32_t reply_len = 0;
            boost::asio::read(*global_socket, boost::asio::buffer(&reply_len, 4));
            std::vector<unsigned char> packet(reply_len);
            boost::asio::read(*global_socket, boost::asio::buffer(packet));

            int sender_id;
            memcpy(&sender_id, packet.data(), 4);
            std::vector<unsigned char> ciphertext(packet.begin() + 4, packet.end());

            // 用自己的专属密钥解密
            std::vector<unsigned char> my_key = get_user_key(my_client_id);
            std::string msg = CryptoUtils::decrypt(ciphertext, my_key);

            std::string display_msg = "用户" + std::to_string(sender_id) + " 对你说: " + msg + "\r\n";
            PostMessage(hMainWnd, WM_APPEND_CHAT, 0, (LPARAM)new std::string(display_msg));
        }
    }
    catch (std::exception& e) {
        std::string err = "网络断开: " + std::string(e.what()) + "\r\n";
        PostMessage(hMainWnd, WM_APPEND_CHAT, 0, (LPARAM)new std::string(err));
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateWindowA("STATIC", "收件人ID:", WS_CHILD | WS_VISIBLE, 10, 320, 70, 30, hwnd, NULL, NULL, NULL);
        hTargetBox = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "2", WS_CHILD | WS_VISIBLE | ES_NUMBER, 80, 320, 40, 30, hwnd, NULL, NULL, NULL);
        hChatBox = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 10, 10, 460, 300, hwnd, NULL, NULL, NULL);
        hInputBox = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 130, 320, 240, 30, hwnd, NULL, NULL, NULL);
        hSendButton = CreateWindowExA(0, "BUTTON", "发送", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 380, 320, 90, 30, hwnd, (HMENU)1, NULL, NULL);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            char target_buf[16] = { 0 }, msg_buf[1024] = { 0 };
            GetWindowTextA(hTargetBox, target_buf, 16);
            GetWindowTextA(hInputBox, msg_buf, 1024);

            int target_id = atoi(target_buf);
            std::string msg(msg_buf);

            if (msg.empty() || target_id <= 0) return 0;

            try {
                if (!global_socket || !global_socket->is_open()) return 0;

                // 用目标用户的专属密钥加密！
                std::vector<unsigned char> target_key = get_user_key(target_id);
                std::vector<unsigned char> ciphertext = CryptoUtils::encrypt(msg, target_key);

                std::vector<unsigned char> packet(4 + ciphertext.size());
                memcpy(packet.data(), &target_id, 4);
                memcpy(packet.data() + 4, ciphertext.data(), ciphertext.size());

                uint32_t packet_len = packet.size();
                boost::asio::write(*global_socket, boost::asio::buffer(&packet_len, 4));
                boost::asio::write(*global_socket, boost::asio::buffer(packet));

                std::string display_msg = "我发给用户" + std::to_string(target_id) + ": " + msg + "\r\n";
                int len = GetWindowTextLength(hChatBox);
                SendMessage(hChatBox, EM_SETSEL, len, len);
                SendMessage(hChatBox, EM_REPLACESEL, FALSE, (LPARAM)display_msg.c_str());
                SetWindowTextA(hInputBox, "");
            }
            catch (...) {}
        }
        return 0;

    case WM_APPEND_CHAT: {
        std::string* text = (std::string*)lParam;
        int len = GetWindowTextLength(hChatBox);
        SendMessage(hChatBox, EM_SETSEL, len, len);
        SendMessage(hChatBox, EM_REPLACESEL, FALSE, (LPARAM)text->c_str());
        delete text;
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "ChatWindowClass";
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    hMainWnd = CreateWindowEx(0, CLASS_NAME, "端到端加密聊天室 (支持多用户)", WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 500, 400, NULL, NULL, hInstance, NULL);
    if (hMainWnd == NULL) return 0;
    ShowWindow(hMainWnd, nCmdShow);
    std::thread(NetworkThread).detach();

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}