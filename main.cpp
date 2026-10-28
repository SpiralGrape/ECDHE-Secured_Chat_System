#include <iostream>
#include <boost/asio.hpp>
#include <openssl/opensslv.h>

int main() {
    std::cout << "===== 环境验证开始 =====" << std::endl;

    // 1. 验证 OpenSSL 版本
    std::cout << "[OpenSSL] 版本: " << OPENSSL_VERSION_TEXT << std::endl;

    // 2. 验证 Boost.Asio 核心对象
    boost::asio::io_context io;
    std::cout << "[Boost.Asio] io_context 创建成功，网络引擎就绪！" << std::endl;

    std::cout << "===== 恭喜！所有依赖已成功链接！ =====" << std::endl;
    return 0;
}