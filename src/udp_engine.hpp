//
// udp_engine.hpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/asio.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

#include "tunio/tun_config.hpp"
#include "tunio/detail/handler_util.hpp"
#include "device_writer.hpp"
#include "ip_headers.hpp"
#include "tcp_engine.hpp"

namespace tunio {
namespace net = boost::asio;
namespace detail {

class device_writer;
struct buffer_accountant;

class udp_engine;

// UDP 会话：由五元组唯一标识，承载数据报收发与空闲超时
struct udp_session : public std::enable_shared_from_this<udp_session> {
    five_tuple key;
    udp_engine* eng = nullptr;

    bool closed = false;
    bool accepted = false;
    std::chrono::seconds timeout{30};
    std::chrono::steady_clock::time_point expiry;
    uint64_t expiry_gen = 0;   // 与堆条目配对，用于懒失效

    std::deque<std::vector<uint8_t>> rx_datagrams;
    size_t rx_bytes = 0;

    struct read_op {
        std::vector<net::mutable_buffer> buffers;
        size_t total = 0;
        std::function<void(boost::system::error_code, size_t)> handler;
    };
    std::deque<read_op> pending_reads;

    bool is_open() const { return !closed; }
};

template <typename Handler>
void udp_session_start_receive(std::shared_ptr<udp_session>,
                               std::vector<net::mutable_buffer>, size_t, Handler);
template <typename Handler>
void udp_session_start_send(std::shared_ptr<udp_session>, std::vector<uint8_t>, Handler);

class udp_engine : public std::enable_shared_from_this<udp_engine> {
public:
    udp_engine(net::any_io_executor strand, device_writer& writer,
               const tun_config& cfg, engine_stats& stats,
               std::shared_ptr<buffer_accountant> account);
    ~udp_engine();

    // 处理一个 UDP 数据报（Strand 上调用）
    void on_packet(const ip_packet_info& ip, const uint8_t* payload, size_t len);

    // 等待新会话；完成回调签名 void(error_code, shared_ptr<udp_session>)
    template <typename Handler>
    void async_accept(Handler handler);
    void cancel_accepts();
    void close_all();
    size_t session_count() const { return sessions_.size(); }

    net::any_io_executor strand() const { return strand_; }
    device_writer& writer() { return writer_; }
    engine_stats& stats() { return stats_; }
    buffer_accountant& account() { return *account_; }
    size_t mtu() const { return mtu_; }

private:
    friend struct udp_session;
    template <typename Handler>
    friend void udp_session_start_receive(std::shared_ptr<udp_session>,
                                          std::vector<net::mutable_buffer>, size_t, Handler);
    template <typename Handler>
    friend void udp_session_start_send(std::shared_ptr<udp_session>, std::vector<uint8_t>, Handler);
    friend void udp_session_close(std::shared_ptr<udp_session>);
    friend void udp_session_set_timeout(std::shared_ptr<udp_session>, std::chrono::seconds);

    void deliver_datagram(const std::shared_ptr<udp_session>& s, std::vector<uint8_t> datagram);
    void refresh_expiry(const std::shared_ptr<udp_session>& s);
    void arm_expiry_timer();
    void on_expiry_timer(const boost::system::error_code& ec);
    void remove_session(std::shared_ptr<udp_session> s);

    net::any_io_executor strand_;
    device_writer& writer_;
    tun_config cfg_;
    engine_stats& stats_;
    std::shared_ptr<buffer_accountant> account_;
    size_t mtu_ = 1500;

    std::unordered_map<five_tuple, std::shared_ptr<udp_session>> sessions_;
    std::deque<std::function<void(boost::system::error_code, std::shared_ptr<udp_session>)>> pending_accepts_;
    std::deque<std::shared_ptr<udp_session>> pending_new_sessions_;

    // 最小堆：堆顶为最早即将过期的会话
    struct expiry_entry {
        std::chrono::steady_clock::time_point at;
        uint64_t gen;
        std::weak_ptr<udp_session> session;
    };
    struct expiry_entry_cmp {
        bool operator()(const expiry_entry& lhs, const expiry_entry& rhs) const {
            return lhs.at > rhs.at;
        }
    };
    std::vector<expiry_entry> expiry_heap_;
    net::steady_timer expiry_timer_;
    bool timer_waiting_ = false;
    std::chrono::steady_clock::time_point armed_target_{};
    uint64_t wait_gen_ = 0;
};

// ---- 供 tun_udp_socket 调用的入口（内部自动派发到 Strand）----
template <typename Handler>
void udp_session_start_receive(std::shared_ptr<udp_session> session,
                               std::vector<net::mutable_buffer> buffers,
                               size_t total,
                               Handler handler) {
    if (!session || !session->eng) {
        handler(boost::system::error_code(net::error::bad_descriptor), 0);
        return;
    }
    auto strand = session->eng->strand();
    net::dispatch(strand, [s = std::move(session), buffers = std::move(buffers), total,
                           handler = std::move(handler)]() mutable {
        auto& session = *s;
        if (session.closed) {
            handler(boost::system::error_code(net::error::bad_descriptor), 0);
            return;
        }
        if (total == 0) {
            handler(boost::system::error_code{}, 0);
            return;
        }
        if (!session.rx_datagrams.empty()) {
            auto dg = std::move(session.rx_datagrams.front());
            session.rx_datagrams.pop_front();
            session.rx_bytes -= dg.size();
            s->eng->account().release(dg.size());
            if (dg.size() > total) {
                handler(boost::system::error_code(net::error::message_size), 0);
                return;
            }
            size_t copied = 0;
            for (auto& buf : buffers) {
                if (copied >= dg.size()) {
                    break;
                }
                const size_t take = std::min(buf.size(), dg.size() - copied);
                std::memcpy(buf.data(), dg.data() + copied, take);
                copied += take;
            }
            handler(boost::system::error_code{}, dg.size());
            return;
        }
        session.pending_reads.push_back({std::move(buffers), total,
            std::function<void(boost::system::error_code, size_t)>(
                make_copyable(std::move(handler)))});
    });
}

template <typename Handler>
void udp_session_start_send(std::shared_ptr<udp_session> session, std::vector<uint8_t> data,
                            Handler handler) {
    if (!session || !session->eng) {
        handler(boost::system::error_code(net::error::bad_descriptor), 0);
        return;
    }
    auto strand = session->eng->strand();
    net::dispatch(strand, [s = std::move(session), data = std::move(data),
                           handler = std::move(handler)]() mutable {
        auto& session = *s;
        if (session.closed) {
            handler(boost::system::error_code(net::error::bad_descriptor), 0);
            return;
        }
        const int family = session.key.family;
        const size_t ip_hdr_len = ip_header_size(family);
        const size_t mtu = s->eng->mtu();
        if (data.size() > mtu - ip_hdr_len - sizeof(udp_header)) {
            handler(boost::system::error_code(net::error::message_size), 0);
            return;
        }
        s->eng->refresh_expiry(s);

        // 构造 IP + UDP 报文（源地址为客户端请求的目标地址）
        const size_t total = ip_hdr_len + sizeof(udp_header) + data.size();
        packet_buffer pkt = s->eng->writer().acquire(mtu + 64, 64);
        pkt.resize(total);
        uint8_t* base = pkt.data();

        build_ip_header(base, family, session.key.dst_ip.data(), session.key.src_ip.data(),
                        IPPROTO_UDP_V, total, s->eng->writer().alloc_ip_id());

        auto* uh = reinterpret_cast<udp_header*>(base + ip_hdr_len);
        uh->src_port = session.key.dst_port;
        uh->dst_port = session.key.src_port;
        uh->length = htons(static_cast<uint16_t>(sizeof(udp_header) + data.size()));
        uh->checksum = 0;
        if (!data.empty()) {
            std::memcpy(base + ip_hdr_len + sizeof(udp_header), data.data(), data.size());
        }
        uint16_t csum = tcp_udp_checksum(family, session.key.dst_ip.data(), session.key.src_ip.data(),
                                         IPPROTO_UDP_V, base + ip_hdr_len,
                                         sizeof(udp_header) + data.size());
        // IPv6 下 UDP 校验和不可为 0；按 RFC 768/8200 以 0xffff 替代
        if (csum == 0) {
            csum = 0xffff;
        }
        uh->checksum = htons(csum);

        using handler_t = std::decay_t<Handler>;
        auto sp = std::make_shared<handler_t>(std::move(handler));
        const size_t sent = data.size();
        s->eng->writer().async_write(
            std::move(pkt), net::bind_executor(s->eng->strand(),
                [sp, sent](const boost::system::error_code& ec, size_t) {
                    // 设备写失败时透传错误码，避免向调用方误报成功
                    std::move(*sp)(ec, ec ? 0 : sent);
                }));
    });
}

template <typename Handler>
void udp_engine::async_accept(Handler handler) {
    while (!pending_new_sessions_.empty()) {
        auto s = std::move(pending_new_sessions_.front());
        pending_new_sessions_.pop_front();
        if (s->closed) {
            continue;
        }
        s->accepted = true;
        handler(boost::system::error_code{}, std::move(s));
        return;
    }
    pending_accepts_.push_back(
        std::function<void(boost::system::error_code, std::shared_ptr<udp_session>)>(
            make_copyable(std::move(handler))));
}

void udp_session_close(std::shared_ptr<udp_session> session);
void udp_session_set_timeout(std::shared_ptr<udp_session> session, std::chrono::seconds timeout);
bool udp_session_is_open(const std::shared_ptr<udp_session>& session);

} // namespace detail
} // namespace tunio
