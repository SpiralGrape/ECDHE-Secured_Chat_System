cmake_minimum_required(VERSION 3.20)
project(ECDHE_Secured_Chat_System LANGUAGES CXX)

# ------------------------------------------------------------------ 全局配置 --
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(_WIN32_WINNT=0x0A00)

if (MSVC)
    # 源码统一使用 UTF-8 编码（源码集的字符串字面量为 UTF-8）
    add_compile_options(/utf-8 /W3)
endif()

# ------------------------------------------------------------------ 依赖 ------
find_package(OpenSSL REQUIRED)
# CMake 4.x 已移除 FindBoost 模块，必须使用 Boost 自带的 CONFIG 模式
find_package(Boost CONFIG REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)

# ------------------------------------------------------------------ 公共头文件 --
set(COMMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Common)

# ------------------------------------------------------------------ 服务端 ----
add_executable(Server_App
    Server/server.cpp
)
target_include_directories(Server_App PRIVATE ${COMMON_DIR})
target_link_libraries(Server_App PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
    Threads::Threads
    ws2_32
)

# ------------------------------------------------------------------ 客户端 ----
add_executable(ClientGUI_App WIN32
    ClientGUI/ClientGUI.cpp
)
target_include_directories(ClientGUI_App PRIVATE ${COMMON_DIR})
target_link_libraries(ClientGUI_App PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
    Threads::Threads
    ws2_32
    uxtheme
    dwmapi
)

# ------------------------------------------------------------------ 自测 ----
add_executable(CryptoTest
    Tests/crypto_selftest.cpp
)
target_include_directories(CryptoTest PRIVATE ${COMMON_DIR})
target_link_libraries(CryptoTest PRIVATE OpenSSL::Crypto ws2_32)
