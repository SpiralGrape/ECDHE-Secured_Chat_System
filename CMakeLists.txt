cmake_minimum_required(VERSION 3.10)
project(ECDHE_Secured_Chat_System)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)

# 寻找 OpenSSL 和 Boost
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
# 生成服务端程序
add_executable(server server.cpp)
target_link_libraries(server PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto)

# 生成客户端程序
add_executable(client client.cpp)
target_link_libraries(client PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto)
# 包含头文件
include_directories(${OPENSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIRS})
include_directories(${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# 添加你的源代码文件
add_executable(ECDHE_Secured_Chat_System main.cpp)

# 链接库
target_link_libraries(ECDHE_Secured_Chat_System PRIVATE 
    Boost::system 
    OpenSSL::SSL 
    OpenSSL::Crypto
)