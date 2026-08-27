//
// test_udp_engine.cpp
// ~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include "test_harness.hpp"

using namespace test;

namespace {
namespace net = boost::asio;
constexpr uint32_t CLIENT_IP = 0x0a000002; // 10.0.0.2
constexpr uint32_t DEST_IP = 0x08080808;   // 8.8.8.8
} // namespace

static void test_datagram_roundtrip()
{
    engine_env env;
    auto &io = env.io;
    tun_udp_acceptor acceptor(env.engine);
    tun_udp_socket session(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(session, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });

    const std::string query = "dns-query-bytes";
    env.dev.send(make_udp(CLIENT_IP, DEST_IP, 53000, 53,
                          std::vector<uint8_t>(query.begin(), query.end())));

    // 新会话通知
    auto aec = future_get(accept_done.get_future());
    assert(!aec);
    auto key = session.remote_key();
    const uint32_t csrc = htonl(CLIENT_IP);
    const uint32_t cdst = htonl(DEST_IP);
    assert(key.family == 4);
    assert(std::memcmp(key.src_ip.data(), &csrc, 4) == 0);
    assert(std::memcmp(key.dst_ip.data(), &cdst, 4) == 0);
    assert(key.src_port == htons(53000));
    assert(key.dst_port == htons(53));
    assert(key.protocol == 17);

    // 接收完整数据报
    std::promise<std::pair<boost::system::error_code, size_t>> recv_done;
    char buf[512];
    session.async_receive(net::buffer(buf),
                          [&](boost::system::error_code ec, size_t n) {
                              recv_done.set_value({ec, n});
                          });
    auto [rec, rn] = future_get(recv_done.get_future());
    assert(!rec && rn == query.size());
    assert(std::string(buf, rn) == query);

    // 发送回复数据报
    const std::string reply = "dns-answer";
    std::promise<std::pair<boost::system::error_code, size_t>> send_done;
    session.async_send(net::buffer(reply),
                       [&](boost::system::error_code ec, size_t n) {
                           send_done.set_value({ec, n});
                       });
    auto [sec, sn] = future_get(send_done.get_future());
    assert(!sec && sn == reply.size());

    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no UDP reply packet");
    }
    if (!verify_packet(pkt)) {
        throw std::runtime_error("verify_packet failed");
    }
    ip_hdr_info ipi;
    if (!parse_ip(pkt, ipi)) {
        throw std::runtime_error("parse_ip failed");
    }
    assert(ipi.src == DEST_IP && ipi.dst == CLIENT_IP && ipi.proto == 17);
    udp_hdr_info ui;
    if (!parse_udp(ipi.payload, ipi.payload_len, ui)) {
        throw std::runtime_error("parse_udp failed");
    }
    assert(ui.sport == 53 && ui.dport == 53000);
    assert(std::string(reinterpret_cast<const char *>(ui.data), ui.n) == reply);

    session.close();
}

static void test_session_timeout()
{
    // 短空闲超时（500ms）
    engine_env env(1500, std::chrono::seconds(1));
    auto &io = env.io;
    tun_udp_acceptor acceptor(env.engine);
    tun_udp_socket session(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(session, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });

    env.dev.send(make_udp(CLIENT_IP, DEST_IP, 53001, 53, {1, 2, 3}));
    future_get(accept_done.get_future());

    // 消费首个数据报
    std::promise<std::pair<boost::system::error_code, size_t>> first_read;
    char buf[512];
    session.async_receive(net::buffer(buf),
                          [&](boost::system::error_code ec, size_t n) {
                              first_read.set_value({ec, n});
                          });
    auto [fec, fn] = future_get(first_read.get_future());
    assert(!fec && fn == 3);

    // 挂起第二个读取，等待空闲超时唤醒
    std::promise<std::pair<boost::system::error_code, size_t>> timeout_read;
    session.async_receive(net::buffer(buf),
                          [&](boost::system::error_code ec, size_t n) {
                              timeout_read.set_value({ec, n});
                          });
    auto [tec, tn] = future_get(timeout_read.get_future(), 5000);
    assert(tec == net::error::operation_aborted);
    assert(!session.is_open());
}

static void test_session_recreated_after_expiry()
{
    engine_env env(1500, std::chrono::seconds(1));
    auto &io = env.io;
    tun_udp_acceptor acceptor(env.engine);

    // 第一个会话
    {
        tun_udp_socket s1(io.get_executor());
        std::promise<boost::system::error_code> a1;
        acceptor.async_accept(
            s1, [&](boost::system::error_code ec) { a1.set_value(ec); });
        env.dev.send(make_udp(CLIENT_IP, DEST_IP, 53002, 53, {9}));
        future_get(a1.get_future());
        s1.close();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2200));

    // 相同五元组的新流量应创建全新会话
    tun_udp_socket s2(io.get_executor());
    std::promise<boost::system::error_code> a2;
    acceptor.async_accept(
        s2, [&](boost::system::error_code ec) { a2.set_value(ec); });
    env.dev.send(make_udp(CLIENT_IP, DEST_IP, 53002, 53, {7, 7}));
    future_get(a2.get_future());
    s2.close();
}

int main(int argc, char **argv)
{
    if (argc > 1 && std::string(argv[1]) == "roundtrip") {
        test_datagram_roundtrip();
        return 0;
    }
    if (argc > 1 && std::string(argv[1]) == "timeout") {
        test_session_timeout();
        return 0;
    }
    if (argc > 1 && std::string(argv[1]) == "recreate") {
        test_session_recreated_after_expiry();
        return 0;
    }
    test_datagram_roundtrip();
    test_session_timeout();
    test_session_recreated_after_expiry();
    return 0;
}
