//
// tun_echo.cpp
// ~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// tun_echo：DESIGN.md §10 的回显示例 —— TCP 桥接本地服务 + UDP 回显
//
// 用法示例：
//   sudo ./tun_echo --tun tun0 --ip 10.0.0.1 --netmask 255.255.255.0
//
// TCP：将虚拟连接转发到本机 127.0.0.1:echo 端口；
// UDP：直接在引擎层面回显数据报。
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "tunio/tun_acceptor.hpp"
#include "tunio/tun_config.hpp"
#include "tunio/tunio.hpp"
#include "tunio/tun_stream.hpp"
#include "tunio/tun_udp_acceptor.hpp"
#include "tunio/tun_udp_socket.hpp"

namespace asio = boost::asio;

namespace {

struct options {
    std::string dev_name = "tun0";
    std::string ipv4_addr = "10.0.0.1";
    std::string netmask = "255.255.255.0";
    size_t mtu = 1500;
    uint16_t echo_port = 7;
    int inject_fd = -1;
};

options parse_args(int argc, char** argv) {
    options opt;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("missing value for " + arg);
            }
            return argv[++i];
        };
        if (arg == "--tun") {
            opt.dev_name = next();
        } else if (arg == "--ip") {
            opt.ipv4_addr = next();
        } else if (arg == "--netmask") {
            opt.netmask = next();
        } else if (arg == "--mtu") {
            opt.mtu = static_cast<size_t>(std::stoul(next()));
        } else if (arg == "--echo-port") {
            opt.echo_port = static_cast<uint16_t>(std::stoul(next()));
        } else if (arg == "--inject-fd") {
            opt.inject_fd = std::stoi(next());
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    return opt;
}

// ---- TCP 全双工数据泵（DESIGN.md §10.1）----
asio::awaitable<void> bidirectional_bridge(tunio::tun_stream client, asio::ip::tcp::endpoint target) {
    auto ex = co_await asio::this_coro::executor;
    auto proxy = std::make_shared<asio::ip::tcp::socket>(ex);
    boost::system::error_code ec;
    co_await proxy->async_connect(target, asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        client.reset();
        co_return;
    }
    auto c = std::make_shared<tunio::tun_stream>(std::move(client));

    asio::co_spawn(ex, [c, proxy]() -> asio::awaitable<void> {
        std::array<char, 8192> buf;
        try {
            for (;;) {
                size_t n = co_await c->async_read_some(asio::buffer(buf), asio::use_awaitable);
                co_await asio::async_write(*proxy, asio::buffer(buf, n), asio::use_awaitable);
            }
        } catch (...) {
        }
        boost::system::error_code sec;
        proxy->shutdown(asio::ip::tcp::socket::shutdown_send, sec);
    }, asio::detached);

    asio::co_spawn(ex, [c, proxy]() -> asio::awaitable<void> {
        std::array<char, 8192> buf;
        try {
            for (;;) {
                size_t n = co_await proxy->async_read_some(asio::buffer(buf), asio::use_awaitable);
                co_await asio::async_write(*c, asio::buffer(buf, n), asio::use_awaitable);
            }
        } catch (...) {
            c->close();
        }
    }, asio::detached);
}

asio::awaitable<void> tcp_listener(tunio::tunio& engine, uint16_t echo_port) {
    auto ex = co_await asio::this_coro::executor;
    tunio::tun_acceptor acceptor(engine);
    for (;;) {
        tunio::tun_stream client(ex);
        boost::system::error_code ec;
        co_await acceptor.async_accept(client, asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            co_return;
        }
        asio::co_spawn(ex, bidirectional_bridge(std::move(client),
                                                {asio::ip::address_v4::loopback(), echo_port}),
                       asio::detached);
    }
}

// ---- UDP 回显会话（DESIGN.md §10.2）----
asio::awaitable<void> udp_echo_handler(tunio::tun_udp_socket session) {
    std::array<char, 2048> buf;
    try {
        for (;;) {
            size_t n = co_await session.async_receive(asio::buffer(buf), asio::use_awaitable);
            co_await session.async_send(asio::buffer(buf, n), asio::use_awaitable);
        }
    } catch (...) {
        session.close();
    }
}

asio::awaitable<void> udp_listener(tunio::tunio& engine) {
    auto ex = co_await asio::this_coro::executor;
    tunio::tun_udp_acceptor acceptor(engine);
    for (;;) {
        tunio::tun_udp_socket session(ex);
        boost::system::error_code ec;
        co_await acceptor.async_accept(session, asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            co_return;
        }
        asio::co_spawn(ex, udp_echo_handler(std::move(session)), asio::detached);
    }
}

} // namespace

int main(int argc, char** argv) {
    options opt;
    try {
        opt = parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    asio::io_context io(1);
    tunio::tunio engine(io);

    tunio::tun_config cfg;
    cfg.dev_name = opt.dev_name;
    cfg.ipv4_addr = opt.ipv4_addr;
    cfg.netmask = opt.netmask;
    cfg.mtu = opt.mtu;
    if (opt.inject_fd >= 0) {
        cfg.external_handle = opt.inject_fd;
        cfg.external_mtu = opt.mtu;
    }

    boost::system::error_code ec;
    if (!engine.open(cfg, ec)) {
        std::cerr << "open TUN failed: " << ec.message() << std::endl;
        return 1;
    }
    std::cout << "tun_echo: " << cfg.dev_name << " " << cfg.ipv4_addr << std::endl;

    asio::co_spawn(io, tcp_listener(engine, opt.echo_port), asio::detached);
    asio::co_spawn(io, udp_listener(engine), asio::detached);

    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code&, int) {
        engine.close();
    });

    io.run();
    return 0;
}
