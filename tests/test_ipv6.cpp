//
// test_ipv6.cpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// IPv6 专项测试：TCP 握手/数据/FIN、UDP 会话收发、ICMPv6 Echo 回显，
// 以及 IPv4/IPv6 双栈会话共存。

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_harness.hpp"

using namespace test;

namespace {
namespace net = boost::asio;
const auto CLIENT_V6 = v6("fd00::2");
const auto DEST_V6 = v6("2001:4860:4860::8888");
constexpr uint16_t CLIENT_PORT = 12345;
constexpr uint16_t DEST_PORT = 80;
} // namespace

static void test_tcp6_handshake_data_fin() {
    engine_env env;
    auto& io = env.io;
    tun_acceptor acceptor(env.engine);
    tun_stream peer(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(peer, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });

    // 客户端 SYN
    env.dev.send(make_tcp6(CLIENT_V6, DEST_V6, CLIENT_PORT, DEST_PORT, 0x02, 1000, 0, 65535, {}, true));

    // 引擎 SYN-ACK（携带 MSS 选项，IPv6 下 MSS = MTU - 60）
    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no IPv6 SYN-ACK");
    }
    assert(verify_packet6(pkt));
    ip6_hdr_info i6;
    assert(parse_ip6(pkt, i6));
    assert(i6.src == DEST_V6 && i6.dst == CLIENT_V6 && i6.proto == 6);
    tcp_hdr_info ti;
    assert(parse_tcp(i6.payload, i6.payload_len, ti));
    assert((ti.flags & 0x12) == 0x12); // SYN|ACK
    assert(ti.ack == 1001);
    const uint32_t engine_iss = ti.seq;
    assert(i6.payload_len >= 24); // MSS 选项
    assert(static_cast<size_t>((i6.payload[22] << 8) | i6.payload[23]) == 1440);

    // 客户端 ACK
    env.dev.send(make_tcp6(CLIENT_V6, DEST_V6, CLIENT_PORT, DEST_PORT, 0x10, 1001, engine_iss + 1, 65535, {}));

    // accept 完成，原始目标地址为 IPv6
    auto aec = future_get(accept_done.get_future());
    assert(!aec);
    const auto dest = peer.original_destination();
    assert(dest.address().is_v6());
    const auto b = dest.address().to_v6().to_bytes();
    assert(std::equal(b.begin(), b.end(), DEST_V6.begin()));
    assert(dest.port() == DEST_PORT);

    // 客户端发送数据 "hello"
    const std::string hello = "hello";
    env.dev.send(make_tcp6(CLIENT_V6, DEST_V6, CLIENT_PORT, DEST_PORT, 0x18, 1001, engine_iss + 1, 65535,
                           std::vector<uint8_t>(hello.begin(), hello.end())));

    // 应用读取到字节流
    std::promise<std::pair<boost::system::error_code, size_t>> read_done;
    char buf[64];
    peer.async_read_some(net::buffer(buf), [&](boost::system::error_code ec, size_t n) {
        read_done.set_value({ec, n});
    });
    auto [rec, rn] = future_get(read_done.get_future());
    assert(!rec && rn == hello.size());
    assert(std::string(buf, rn) == hello);

    // 消费引擎对数据的 ACK
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no IPv6 data ack");
    }
    assert(verify_packet6(pkt));
    assert(parse_ip6(pkt, i6));
    assert(parse_tcp(i6.payload, i6.payload_len, ti));
    assert((ti.flags & 0x10) != 0 && ti.ack == 1006);

    // 客户端发送 FIN（与数据同段序号语义：FIN 序号 = 1001 + 5）
    env.dev.send(make_tcp6(CLIENT_V6, DEST_V6, CLIENT_PORT, DEST_PORT, 0x11, 1006, engine_iss + 6, 65535, {}));
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no IPv6 FIN ack");
    }
    assert(verify_packet6(pkt));
    assert(parse_ip6(pkt, i6));
    assert(parse_tcp(i6.payload, i6.payload_len, ti));
    assert((ti.flags & 0x10) != 0 && ti.ack == 1007);

    // 应用关闭后引擎应发送 FIN
    boost::system::error_code sec;
    peer.shutdown(net::ip::tcp::socket::shutdown_both, sec);
    bool fin_seen = false;
    for (int i = 0; i < 4 && !fin_seen; ++i) {
        if (!env.dev.read_packet(pkt, 2000)) {
            break;
        }
        assert(parse_ip6(pkt, i6));
        assert(parse_tcp(i6.payload, i6.payload_len, ti));
        if ((ti.flags & 0x01) != 0) {
            fin_seen = true;
        }
    }
    assert(fin_seen);

    // 客户端 ACK 引擎 FIN
    env.dev.send(make_tcp6(CLIENT_V6, DEST_V6, CLIENT_PORT, DEST_PORT, 0x10, 1007, engine_iss + 2, 65535, {}));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

static void test_udp6_roundtrip() {
    engine_env env;
    auto& io = env.io;
    tun_udp_acceptor acceptor(env.engine);
    tun_udp_socket session(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(session, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });

    const std::string query = "ipv6-dns-query";
    env.dev.send(make_udp6(CLIENT_V6, DEST_V6, 53000, 53,
                           std::vector<uint8_t>(query.begin(), query.end())));

    // 新会话通知
    auto aec = future_get(accept_done.get_future());
    assert(!aec);
    const auto key = session.remote_key();
    assert(key.family == 6);
    assert(std::equal(key.src_ip.begin(), key.src_ip.end(), CLIENT_V6.begin()));
    assert(std::equal(key.dst_ip.begin(), key.dst_ip.end(), DEST_V6.begin()));
    assert(key.src_port == htons(53000) && key.dst_port == htons(53));
    assert(key.protocol == 17);

    // 接收完整数据报
    std::promise<std::pair<boost::system::error_code, size_t>> recv_done;
    char buf[512];
    session.async_receive(net::buffer(buf), [&](boost::system::error_code ec, size_t n) {
        recv_done.set_value({ec, n});
    });
    auto [rec, rn] = future_get(recv_done.get_future());
    assert(!rec && rn == query.size());
    assert(std::string(buf, rn) == query);

    // 发送回复数据报
    const std::string reply = "ipv6-dns-answer";
    std::promise<std::pair<boost::system::error_code, size_t>> send_done;
    session.async_send(net::buffer(reply), [&](boost::system::error_code ec, size_t n) {
        send_done.set_value({ec, n});
    });
    auto [sec, sn] = future_get(send_done.get_future());
    assert(!sec && sn == reply.size());

    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no IPv6 UDP reply packet");
    }
    assert(verify_packet6(pkt));
    ip6_hdr_info i6;
    assert(parse_ip6(pkt, i6));
    assert(i6.src == DEST_V6 && i6.dst == CLIENT_V6 && i6.proto == 17);
    udp_hdr_info ui;
    assert(parse_udp(i6.payload, i6.payload_len, ui));
    assert(ui.sport == 53 && ui.dport == 53000);
    assert(std::string(reinterpret_cast<const char*>(ui.data), ui.n) == reply);

    session.close();
}

static void test_icmp6_echo() {
    engine_env env;
    auto& io = env.io;
    (void)io;

    // 对引擎本地虚拟 IPv6 地址的 Echo Request
    const auto local = v6("fd00::1");
    const std::vector<uint8_t> payload = {0xde, 0xad, 0xbe, 0xef};
    env.dev.send(make_icmp6_echo(CLIENT_V6, local, 0x1234, 0x0001, payload));

    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no ICMPv6 reply");
    }
    assert(verify_packet6(pkt));
    ip6_hdr_info i6;
    assert(parse_ip6(pkt, i6));
    assert(i6.src == local && i6.dst == CLIENT_V6 && i6.proto == 58);

    // Echo Reply：type=129，ID/序号/数据保持
    const uint8_t* icmp = i6.payload;
    assert(icmp[0] == 129);
    assert(icmp[1] == 0);
    assert(icmp[4] == 0x12 && icmp[5] == 0x34);
    assert(icmp[6] == 0x00 && icmp[7] == 0x01);
    assert(i6.payload_len == 8 + payload.size());
    assert(std::memcmp(icmp + 8, payload.data(), payload.size()) == 0);

    // 发给其他地址的 Echo 不应响应
    env.dev.send(make_icmp6_echo(CLIENT_V6, v6("fd00::3"), 0x0001, 0x0002, {}));
    std::vector<uint8_t> ignored;
    if (env.dev.read_packet(ignored, 300)) {
        throw std::runtime_error("unexpected reply to non-local address");
    }
}

static void test_v4_v6_coexist() {
    engine_env env;
    auto& io = env.io;
    tun_udp_acceptor acceptor(env.engine);
    tun_udp_socket s4(io.get_executor());
    tun_udp_socket s6(io.get_executor());

    std::promise<boost::system::error_code> a4, a6;
    acceptor.async_accept(s4, [&](boost::system::error_code ec) { a4.set_value(ec); });
    acceptor.async_accept(s6, [&](boost::system::error_code ec) { a6.set_value(ec); });

    // 相同端口号的 IPv4 与 IPv6 会话（地址族参与五元组区分）
    env.dev.send(make_udp(0x0a000002, 0x08080808, 53000, 53, {1, 2, 3}));
    env.dev.send(make_udp6(CLIENT_V6, DEST_V6, 53000, 53, {4, 5, 6}));

    assert(!future_get(a4.get_future()));
    assert(!future_get(a6.get_future()));
    assert(s4.remote_key().family == 4);
    assert(s6.remote_key().family == 6);

    s4.close();
    s6.close();
}

int main() {
    test_tcp6_handshake_data_fin();
    test_udp6_roundtrip();
    test_icmp6_echo();
    test_v4_v6_coexist();
    return 0;
}
