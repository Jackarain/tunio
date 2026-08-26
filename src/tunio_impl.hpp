#pragma once

#include <boost/asio.hpp>

namespace asio = boost::asio;
#include <cstdint>
#include <memory>
#include <utility>

#include "tunio/packet_buffer.hpp"
#include "tunio/packet_device.hpp"
#include "tunio/tun_config.hpp"
#include "tunio/tunio.hpp"

#include "device_writer.hpp"
#include "tcp_engine.hpp"
#include "udp_engine.hpp"

namespace tunio {
namespace detail {

class tunio_impl : public std::enable_shared_from_this<tunio_impl> {
public:
    explicit tunio_impl(boost::asio::io_context& ctx);
    ~tunio_impl();

    bool open(const tun_config& cfg, boost::system::error_code& ec);
    void close();
    bool is_open() const noexcept { return open_.load(std::memory_order_acquire); }
    size_t mtu() const noexcept { return mtu_; }
    boost::asio::ip::address local_address() const noexcept {
        return boost::asio::ip::address(local_ip_);
    }
    engine_stats& stats() noexcept { return stats_; }
    boost::asio::any_io_executor strand() const noexcept { return strand_ex_; }

    // ---- accept 入口（自动派发到 Strand）----
    void async_accept_tcp(std::function<void(boost::system::error_code, std::shared_ptr<tcp_flow>)> handler) {
        asio::dispatch(strand_ex_, [tcp = tcp_, h = std::move(handler)]() mutable {
            if (tcp) {
                tcp->async_accept(std::move(h));
            } else {
                h(boost::asio::error::bad_descriptor, nullptr);
            }
        });
    }

    void async_accept_udp(std::function<void(boost::system::error_code, std::shared_ptr<udp_session>)> handler) {
        asio::dispatch(strand_ex_, [udp = udp_, h = std::move(handler)]() mutable {
            if (udp) {
                udp->async_accept(std::move(h));
            } else {
                h(boost::asio::error::bad_descriptor, nullptr);
            }
        });
    }

    void cancel_tcp_accepts() {
        asio::dispatch(strand_ex_, [tcp = tcp_]() {
            if (tcp) {
                tcp->cancel_accepts();
            }
        });
    }

    void cancel_udp_accepts() {
        asio::dispatch(strand_ex_, [udp = udp_]() {
            if (udp) {
                udp->cancel_accepts();
            }
        });
    }

private:
    void start_read();
    void on_read(const boost::system::error_code& ec, size_t n);
    void handle_packet(const uint8_t* pkt, size_t len);
    void handle_icmp(const uint8_t* pkt, size_t len);

    boost::asio::io_context& ctx_;
    boost::asio::any_io_executor strand_ex_;
    std::atomic<bool> open_{false};
    tun_config cfg_;
    engine_stats stats_;
    boost::asio::ip::address_v4 local_ip_{};
    uint32_t local_ip_net_ = 0;   // 网络字节序，用于与报文字段直接比较
    size_t mtu_ = 1500;

    std::unique_ptr<packet_device> device_;
    std::unique_ptr<device_writer> writer_;
    std::shared_ptr<tcp_engine> tcp_;
    std::shared_ptr<udp_engine> udp_;
    std::shared_ptr<buffer_accountant> account_;

    packet_buffer read_buf_;
    bool reading_ = false;
};

} // namespace detail
} // namespace tunio
