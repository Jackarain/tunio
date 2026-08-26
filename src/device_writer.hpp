#pragma once

#include <boost/asio.hpp>

namespace asio = boost::asio;
#include <deque>
#include <functional>
#include <memory>
#include <utility>

#include "tun_engine/packet_buffer.hpp"
#include "tun_engine/packet_device.hpp"
#include "tun_engine/tun_config.hpp"

namespace tun_engine {
namespace detail {

// 串行化设备写队列
//
// 底层描述符同一时刻仅允许一个未完成的异步写操作，所有写请求统一进入
// 队列，由 Strand 上的泵循环依次下发；本类所有方法都必须在 Strand 上调用。
class device_writer {
public:
    device_writer(boost::asio::any_io_executor strand, packet_device& dev, engine_stats& stats)
        : strand_(std::move(strand)), dev_(dev), stats_(stats) {}

    // 将数据包加入写队列；完成回调在调用方绑定执行器上触发
    template <typename CompletionToken>
    auto async_write(packet_buffer&& buf, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this](auto handler, packet_buffer buf) {
                using handler_t = std::decay_t<decltype(handler)>;
                auto sp = std::make_shared<handler_t>(std::move(handler));
                std::function<void(boost::system::error_code, size_t)> f =
                    [sp](boost::system::error_code ec, size_t n) mutable { std::move(*sp)(ec, n); };
                queue_.push_back(entry{std::move(buf), std::move(f)});
                pump();
            },
            token,
            std::move(buf));
    }

    // 分配 IP Identification（引擎内共享计数）
    uint16_t alloc_ip_id() { return ++ip_id_; }

    // 清空队列并以 operation_aborted 完成挂起的写操作（Strand 上调用）
    void cancel_all() {
        cancelled_ = true;
        while (!queue_.empty()) {
            auto e = std::move(queue_.front());
            queue_.pop_front();
            e.handler(boost::asio::error::operation_aborted, 0);
        }
    }

private:
    struct entry {
        packet_buffer buf;
        std::function<void(boost::system::error_code, size_t)> handler;
    };

    void pump() {
        if (writing_ || queue_.empty()) {
            return;
        }
        writing_ = true;
        auto& front = queue_.front();
        dev_.async_write_packet(front.buf, boost::asio::bind_executor(strand_, [this](boost::system::error_code ec, size_t n) {
            auto e = std::move(queue_.front());
            queue_.pop_front();
            writing_ = false;
            if (!ec) {
                stats_.tx_packets.fetch_add(1, std::memory_order_relaxed);
            }
            if (cancelled_) {
                e.handler(boost::asio::error::operation_aborted, 0);
            } else {
                e.handler(ec, n);
            }
            pump();
        }));
    }

    boost::asio::any_io_executor strand_;
    packet_device& dev_;
    engine_stats& stats_;
    std::deque<entry> queue_;
    bool writing_ = false;
    bool cancelled_ = false;
    uint16_t ip_id_ = 0;
};

} // namespace detail
} // namespace tun_engine
