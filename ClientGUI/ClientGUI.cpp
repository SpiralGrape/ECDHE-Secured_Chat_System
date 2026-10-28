#include <iostream>
#include <vector>
#include <string>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#include <boost/asio.hpp>
#include <openssl/evp.h>
#pragma comment(lib, "libcrypto.lib")
#include "crypto_utils.h"

using boost::asio::ip::tcp;

HWND hChatBox = NULL;
HWND hMainWnd = NULL; // 新增：用来保存主窗口句柄
HWND hInputBox = NULL;
HWND hSendButton = NULL;
tcp::socket* global_socket = NULL;
std::vector<unsigned char> global_aes_key;

#define WM_APPEND_CHAT (WM_APP + 1)

void NetworkThread() {
    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        global_socket = &socket;

        socket.connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 9000));

        EVP_PKEY* client_key = CryptoUtils::generate_keypair();
        std::vector<unsigned char> client_pub_bytes = CryptoUtils::get_public_key_bytes(client_key);
        boost::asio::write(socket, boost::asio::buffer(client_pub_bytes));

        std::vector<unsigned char> server_pub_bytes(32);
        boost::asio::read(socket, boost::asio::buffer(server_pub_bytes));

        EVP_PKEY* server_pub_key = CryptoUtils::load_public_key(server_pub_bytes);
        std::vector<unsigned char> shared_secret = CryptoUtils::derive_shared_secret(client_key, server_pub_key);
        global_aes_key.assign(shared_secret.begin(), shared_secret.begin() + 32);

        PostMessage(hMainWnd, WM_APPEND_CHAT, 0, (LPARAM)new std::string("系统提示：ECDHE 握手完成，通道已加密！\r\n"));

        while (true) {
            uint32_t reply_len;
            boost::asio::read(socket, boost::asio::buffer(&reply_len, 4));
            std::vector<unsigned char> reply_packet(reply_len);
            boost::asio::read(socket, boost::asio::buffer(reply_packet));

            std::string reply_msg = CryptoUtils::decrypt(reply_packet, global_aes_key);
            std::string display_msg = "服务器: " + reply_msg + "\r\n";
            PostMessage(hMainWnd, WM_APPEND_CHAT, 0, (LPARAM)new std::string(display_msg));
        }
    }
    catch (std::exception& e) {
        PostMessage(hChatBox, WM_APPEND_CHAT, 0, (LPARAM)new std::string("网络错误: " + std::string(e.what()) + "\r\n"));
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        // 注意这里去掉了 L 宏，因为现在是多字节模式
        hChatBox = CreateWindowEx(0, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            10, 10, 460, 300, hwnd, NULL, NULL, NULL);

        hInputBox = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            10, 320, 360, 30, hwnd, NULL, NULL, NULL);

        hSendButton = CreateWindowEx(0, "BUTTON", "发送",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            380, 320, 90, 30, hwnd, (HMENU)1, NULL, NULL);

        SendMessage(hChatBox, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        SendMessage(hInputBox, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        SendMessage(hSendButton, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            char buffer[1024];
            GetWindowTextA(hInputBox, buffer, 1024); // 使用 A 版本读取
            std::string msg(buffer);

            if (!msg.empty() && global_socket) {
                std::string display_msg = "我: " + msg + "\r\n";
                int len = GetWindowTextLength(hChatBox);
                SendMessage(hChatBox, EM_SETSEL, len, len);
                SendMessage(hChatBox, EM_REPLACESEL, FALSE, (LPARAM)display_msg.c_str());

                std::vector<unsigned char> packet = CryptoUtils::encrypt(msg, global_aes_key);
                uint32_t packet_len = packet.size();
                boost::asio::write(*global_socket, boost::asio::buffer(&packet_len, 4));
                boost::asio::write(*global_socket, boost::asio::buffer(packet));

                SetWindowTextA(hInputBox, "");
            }
        }
        return 0;

    case WM_APPEND_CHAT: {
        std::string* text = (std::string*)lParam;
        int len = GetWindowTextLength(hChatBox);
        SendMessage(hChatBox, EM_SETSEL, len, len);
        // 直接传字符串指针，无需转换
        SendMessage(hChatBox, EM_REPLACESEL, FALSE, (LPARAM)text->c_str());
        delete text;
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
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

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, "端到端加密聊天室 (ECDHE + AES-GCM)",
        WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 400,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;
    hMainWnd = hwnd;
    ShowWindow(hwnd, nCmdShow);

    std::thread netThread(NetworkThread);

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    netThread.detach();
    return 0;
}