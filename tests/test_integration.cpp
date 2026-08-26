//
// test_integration.cpp
// ~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// 端到端集成测试：模拟 tun2socks 的桥接模式
//
// 客户端（经虚拟设备）通过引擎建立 TCP 连接，应用层把虚拟连接桥接到
// 本地回显服务，验证完整数据通路与 C++20 协程 API。
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <string>
#include <vector>

#include "test_harness.hpp"

using namespace test;
namespace asio = boost::asio;

namespace {
constexpr uint32_t CLIENT_IP = 0x0a000002; // 10.0.0.2
constexpr uint32_t DEST_IP = 0x08080808;   // 8.8.8.8
constexpr uint16_t CLIENT_PORT = 20000;
constexpr uint16_t DEST_PORT = 8080;
} // namespace

static asio::awaitable<void> echo_server(asio::ip::tcp::acceptor& srv) {
    auto ex = co_await asio::this_coro::executor;
    asio::ip::tcp::socket s(ex);
    boost::system::error_code ec;
    co_await srv.async_accept(s, asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return;
    }
    std::array<char, 4096> buf;
    for (;;) {
        size_t n = co_await s.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            co_return;
        }
        co_await asio::async_write(s, asio::buffer(buf, n), asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            co_return;
        }
    }
}

static asio::awaitable<void> bridge(tun_stream client, asio::ip::tcp::endpoint target) {
    auto ex = co_await asio::this_coro::executor;
    auto c = std::make_shared<tun_stream>(std::move(client));
    auto p = std::make_shared<asio::ip::tcp::socket>(ex);
    boost::system::error_code ec;

    co_await p->async_connect(target, asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        c->reset(); // 后端连接失败：RST 客户端
        co_return;
    }

    // 客户端 -> 后端
    asio::co_spawn(ex, [c, p]() -> asio::awaitable<void> {
        std::array<char, 8192> buf;
        boost::system::error_code ec;
        for (;;) {
            size_t n = co_await c->async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
            if (ec || n == 0) {
                break;
            }
            co_await asio::async_write(*p, asio::buffer(buf, n), asio::redirect_error(asio::use_awaitable, ec));
            if (ec) {
                break;
            }
        }
        p->shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    }, asio::detached);

    // 后端 -> 客户端
    asio::co_spawn(ex, [c, p]() -> asio::awaitable<void> {
        std::array<char, 8192> buf;
        boost::system::error_code ec;
        for (;;) {
            size_t n = co_await p->async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
            if (ec || n == 0) {
                break;
            }
            co_await asio::async_write(*c, asio::buffer(buf, n), asio::redirect_error(asio::use_awaitable, ec));
            if (ec) {
                break;
            }
        }
        c->close();
    }, asio::detached);
}

int main() {
    engine_env env;
    auto& io = env.io;

    // 本地回显服务
    asio::ip::tcp::acceptor srv(io, {asio::ip::tcp::v4(), 0});
    const uint16_t port = srv.local_endpoint().port();
    asio::co_spawn(io, echo_server(srv), asio::detached);

    // 桥接器：接受虚拟连接并转发到回显服务
    tun_acceptor acceptor(env.engine);
    asio::co_spawn(io, [&]() -> asio::awaitable<void> {
        auto ex = co_await asio::this_coro::executor;
        tun_stream client(ex);
        boost::system::error_code ec;
        co_await acceptor.async_accept(client, asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            co_return;
        }
        (void)client.original_destination(); // 原始目标（本例忽略，固定转发到本地服务）
        asio::co_spawn(ex, bridge(std::move(client), {asio::ip::address_v4::loopback(), port}), asio::detached);
    }, asio::detached);

    // ---- 客户端握手 ----
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x02, 5000, 0, 65535, {}));
    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no SYN-ACK");
    }
    ip_hdr_info ipi;
    tcp_hdr_info ti;
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    const uint32_t engine_iss = ti.seq;
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x10, 5001, engine_iss + 1, 65535, {}));

    // ---- 客户端发送数据，等待回显 ----
    const std::string msg = "ping-through-tun";
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x18, 5001, engine_iss + 1, 65535,
                          std::vector<uint8_t>(msg.begin(), msg.end())));

    // 第一个包：引擎对客户端数据的 ACK
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no ack");
    }
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert((ti.flags & 0x10) != 0 && ti.ack == 5001 + msg.size());

    // 第二个包：回显数据（后端 -> 客户端）
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no echo packet");
    }
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert(ipi.src == DEST_IP && ipi.dst == CLIENT_IP);
    assert(ti.sport == DEST_PORT && ti.dport == CLIENT_PORT);
    assert(std::string(reinterpret_cast<const char*>(ti.data), ti.len) == msg);

    // ---- 客户端 FIN 关闭 ----
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x11, 5001 + msg.size(),
                          engine_iss + 1 + msg.size(), 65535, {}));
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no fin ack");
    }
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert((ti.flags & 0x10) != 0 && ti.ack == 5001 + msg.size() + 1);

    // 引擎应最终发送 FIN（桥接器检测到 EOF 后关闭虚拟流）
    bool fin_seen = false;
    for (int i = 0; i < 4 && !fin_seen; ++i) {
        if (!env.dev.read_packet(pkt, 2000)) {
            break;
        }
        assert(parse_ip(pkt, ipi));
        assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
        if ((ti.flags & 0x01) != 0) {
            fin_seen = true;
        }
    }
    assert(fin_seen);

    // 客户端 ACK 引擎 FIN
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x10, 5001 + msg.size() + 1,
                          engine_iss + 1 + msg.size() + 1, 65535, {}));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    return 0;
}
