#include <chrono>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <future>
#include <string>
#include <vector>

#include "test_harness.hpp"

using namespace test;
namespace asio = boost::asio;

namespace {
constexpr uint32_t CLIENT_IP = 0x0a000002; // 10.0.0.2
constexpr uint32_t DEST_IP = 0x08080808;   // 8.8.8.8
constexpr uint16_t CLIENT_PORT = 12345;
constexpr uint16_t DEST_PORT = 80;
} // namespace

static void test_handshake_data_fin() {
    engine_env env;
    auto& io = env.io;
    tun_acceptor acceptor(env.engine);
    tun_stream peer(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(peer, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });

    // 客户端 SYN
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x02, 1000, 0, 65535, {}));

    // 引擎 SYN-ACK（携带 MSS 选项）
    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no SYN-ACK");
    }
    assert(verify_packet(pkt));
    ip_hdr_info ipi;
    assert(parse_ip(pkt, ipi));
    assert(ipi.src == DEST_IP && ipi.dst == CLIENT_IP && ipi.proto == 6);
    tcp_hdr_info ti;
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert((ti.flags & 0x12) == 0x12); // SYN|ACK
    assert(ti.ack == 1001);
    const uint32_t engine_iss = ti.seq;
    assert(ipi.payload_len >= 24); // MSS 选项

    // 客户端 ACK
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x10, 1001, engine_iss + 1, 65535, {}));

    // accept 完成，原始目标地址正确
    auto aec = future_get(accept_done.get_future());
    assert(!aec);
    auto dest = peer.original_destination();
    assert(dest.address().to_v4().to_uint() == DEST_IP);
    assert(dest.port() == DEST_PORT);
    assert(peer.is_open());

    // 客户端发送数据 "hello"
    const std::string hello = "hello";
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x18, 1001, engine_iss + 1, 65535,
                          std::vector<uint8_t>(hello.begin(), hello.end())));

    // 应用读取到字节流
    std::promise<std::pair<boost::system::error_code, size_t>> read_done;
    char buf[64];
    peer.async_read_some(asio::buffer(buf), [&](boost::system::error_code ec, size_t n) {
        read_done.set_value({ec, n});
    });
    auto [rec, rn] = future_get(read_done.get_future());
    assert(!rec && rn == hello.size());
    assert(std::string(buf, rn) == hello);

    // 引擎 ACK 客户端数据
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no ACK");
    }
    assert(verify_packet(pkt));
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert((ti.flags & 0x10) != 0 && ti.ack == 1001 + hello.size());

    // 应用写入 "world"，设备收到数据段
    const std::string world = "world";
    std::promise<std::pair<boost::system::error_code, size_t>> write_done;
    peer.async_write_some(asio::buffer(world), [&](boost::system::error_code ec, size_t n) {
        write_done.set_value({ec, n});
    });
    auto [wec, wn] = future_get(write_done.get_future());
    assert(!wec && wn == world.size());

    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no data packet");
    }
    assert(verify_packet(pkt));
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert(ipi.src == DEST_IP && ipi.dst == CLIENT_IP);
    assert(ti.sport == DEST_PORT && ti.dport == CLIENT_PORT);
    assert(ti.seq == engine_iss + 1); // 首个数据段 seq = iss + 1（SYN 消耗一个序号）
    assert(ti.ack == 1001 + hello.size());
    assert((ti.flags & 0x18) == 0x18); // PSH|ACK
    assert(std::string(reinterpret_cast<const char*>(ti.data), ti.len) == world);

    // 客户端 FIN -> 应用读到 EOF
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x11, 1001 + hello.size(),
                          engine_iss + 1 + world.size(), 65535, {}));
    std::promise<std::pair<boost::system::error_code, size_t>> eof_done;
    peer.async_read_some(asio::buffer(buf), [&](boost::system::error_code ec, size_t n) {
        eof_done.set_value({ec, n});
    });
    auto [eec, en] = future_get(eof_done.get_future());
    assert(!eec && en == 0); // EOF

    // 引擎 ACK FIN
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no FIN ACK");
    }
    assert(verify_packet(pkt));
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert(ti.ack == 1001 + hello.size() + 1);

    // 应用关闭 -> 引擎发送 FIN
    peer.close();
    for (int i = 0; i < 100 && peer.is_open(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(!peer.is_open());
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no FIN from engine");
    }
    assert(verify_packet(pkt));
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert((ti.flags & 0x01) != 0);
    const uint32_t fin_seq = ti.seq;

    // 客户端 ACK 引擎 FIN
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, CLIENT_PORT, DEST_PORT, 0x10, 1001 + hello.size() + 1,
                          fin_seq + 1, 65535, {}));
}

static void test_zero_window_flow_control() {
    engine_env env;
    auto& io = env.io;
    tun_acceptor acceptor(env.engine);
    tun_stream peer(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(peer, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });

    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12346, DEST_PORT, 0x02, 2000, 0, 0, {}));
    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no SYN-ACK");
    }
    assert(verify_packet(pkt));
    ip_hdr_info ipi;
    assert(parse_ip(pkt, ipi));
    tcp_hdr_info ti;
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    const uint32_t engine_iss = ti.seq;

    // 客户端 ACK（窗口 0）
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12346, DEST_PORT, 0x10, 2001, engine_iss + 1, 0, {}));
    future_get(accept_done.get_future());

    // 写入应因窗口为 0 而挂起
    std::promise<std::pair<boost::system::error_code, size_t>> write_done;
    peer.async_write_some(asio::buffer("x", 1), [&](boost::system::error_code ec, size_t n) {
        write_done.set_value({ec, n});
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto wf = write_done.get_future();
    if (wf.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
        throw std::runtime_error("write should be blocked by zero window");
    }

    // 窗口更新 ACK -> 写入恢复
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12346, DEST_PORT, 0x10, 2001, engine_iss + 1, 4096, {}));
    auto [wec, wn] = future_get(std::move(wf));
    assert(!wec && wn == 1);

    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no data after window update");
    }
    assert(verify_packet(pkt));
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert(ti.len == 1 && ti.data[0] == 'x');
    peer.close();
}

static void test_rst() {
    engine_env env;
    auto& io = env.io;
    tun_acceptor acceptor(env.engine);
    tun_stream peer(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(peer, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });

    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12347, DEST_PORT, 0x02, 3000, 0, 65535, {}));
    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no SYN-ACK");
    }
    assert(verify_packet(pkt));
    ip_hdr_info ipi;
    tcp_hdr_info ti;
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    const uint32_t engine_iss = ti.seq;
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12347, DEST_PORT, 0x10, 3001, engine_iss + 1, 65535, {}));
    future_get(accept_done.get_future());

    // 挂起读取，等待 RST
    std::promise<std::pair<boost::system::error_code, size_t>> read_done;
    char buf[64];
    peer.async_read_some(asio::buffer(buf), [&](boost::system::error_code ec, size_t n) {
        read_done.set_value({ec, n});
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12347, DEST_PORT, 0x04, 3001, engine_iss + 1, 0, {}));
    auto [rec, rn] = future_get(read_done.get_future());
    assert(rec == boost::asio::error::connection_reset);
    assert(!peer.is_open());
}

static void test_app_reset() {
    engine_env env;
    auto& io = env.io;
    tun_acceptor acceptor(env.engine);
    tun_stream peer(io.get_executor());

    std::promise<boost::system::error_code> accept_done;
    acceptor.async_accept(peer, [&](boost::system::error_code ec) {
        accept_done.set_value(ec);
    });
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12348, DEST_PORT, 0x02, 4000, 0, 65535, {}));
    std::vector<uint8_t> pkt;
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no SYN-ACK");
    }
    assert(verify_packet(pkt));
    ip_hdr_info ipi;
    tcp_hdr_info ti;
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    const uint32_t engine_iss = ti.seq;
    env.dev.send(make_tcp(CLIENT_IP, DEST_IP, 12348, DEST_PORT, 0x10, 4001, engine_iss + 1, 65535, {}));
    future_get(accept_done.get_future());

    // 应用主动 reset()：后端连接失败等场景
    peer.reset();
    if (!env.dev.read_packet(pkt)) {
        throw std::runtime_error("no RST");
    }
    assert(verify_packet(pkt));
    assert(parse_ip(pkt, ipi));
    assert(parse_tcp(ipi.payload, ipi.payload_len, ti));
    assert((ti.flags & 0x04) != 0); // RST
    assert(!peer.is_open());
}

int main() {
    test_handshake_data_fin();
    test_zero_window_flow_control();
    test_rst();
    test_app_reset();
    return 0;
}
