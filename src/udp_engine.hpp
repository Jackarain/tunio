#pragma once

#include <boost/asio.hpp>

namespace asio = boost::asio;
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

#include "tunio/tun_config.hpp"
#include "ip_headers.hpp"

namespace tunio {
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
        std::shared_ptr<std::vector<asio::mutable_buffer>> buffers;
        size_t total = 0;
        std::function<void(boost::system::error_code, size_t)> handler;
    };
    std::deque<read_op> pending_reads;

    bool is_open() const { return !closed; }
};

class udp_engine : public std::enable_shared_from_this<udp_engine> {
public:
    udp_engine(boost::asio::any_io_executor strand, device_writer& writer,
               const tun_config& cfg, engine_stats& stats,
               std::shared_ptr<buffer_accountant> account);
    ~udp_engine();

    // 处理一个 UDP 数据报（Strand 上调用）
    void on_packet(const ipv4_header& ip, const uint8_t* payload, size_t len);

    // 等待新会话；完成回调签名 void(error_code, shared_ptr<udp_session>)
    void async_accept(std::function<void(boost::system::error_code, std::shared_ptr<udp_session>)> handler);
    void cancel_accepts();
    void close_all();
    size_t session_count() const { return sessions_.size(); }

    boost::asio::any_io_executor strand() const { return strand_; }
    device_writer& writer() { return writer_; }
    engine_stats& stats() { return stats_; }
    buffer_accountant& account() { return *account_; }
    size_t mtu() const { return mtu_; }

private:
    friend struct udp_session;
    friend void udp_session_start_receive(
        std::shared_ptr<udp_session>, std::shared_ptr<std::vector<asio::mutable_buffer>>,
        size_t, std::function<void(boost::system::error_code, size_t)>);
    friend void udp_session_start_send(std::shared_ptr<udp_session>, std::vector<uint8_t>,
                                       std::function<void(boost::system::error_code, size_t)>);
    friend void udp_session_close(std::shared_ptr<udp_session>);
    friend void udp_session_set_timeout(std::shared_ptr<udp_session>, std::chrono::seconds);

    void deliver_datagram(std::shared_ptr<udp_session> s, std::vector<uint8_t> datagram);
    void refresh_expiry(std::shared_ptr<udp_session> s);
    void arm_expiry_timer();
    void on_expiry_timer(const boost::system::error_code& ec);
    void remove_session(std::shared_ptr<udp_session> s);

    boost::asio::any_io_executor strand_;
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
    boost::asio::steady_timer expiry_timer_;
    bool timer_waiting_ = false;
    std::chrono::steady_clock::time_point armed_target_{};
    uint64_t wait_gen_ = 0;
};

// ---- 供 tun_udp_socket 调用的入口（内部自动派发到 Strand）----
void udp_session_start_receive(std::shared_ptr<udp_session> session,
                               std::shared_ptr<std::vector<asio::mutable_buffer>> buffers,
                               size_t total,
                               std::function<void(boost::system::error_code, size_t)> handler);

void udp_session_start_send(std::shared_ptr<udp_session> session, std::vector<uint8_t> data,
                            std::function<void(boost::system::error_code, size_t)> handler);

void udp_session_close(std::shared_ptr<udp_session> session);
void udp_session_set_timeout(std::shared_ptr<udp_session> session, std::chrono::seconds timeout);
bool udp_session_is_open(const std::shared_ptr<udp_session>& session);

} // namespace detail
} // namespace tunio
