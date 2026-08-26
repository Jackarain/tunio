//
// device_writer.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/asio.hpp>

#include <deque>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "tunio/packet_buffer.hpp"
#include "tunio/packet_device.hpp"
#include "tunio/tun_config.hpp"

namespace tunio {
namespace net = boost::asio;
namespace detail {

// 串行化设备写队列
//
// 底层描述符同一时刻仅允许一个未完成的异步写操作，所有写请求统一进入
// 队列，由 Strand 上的泵循环依次下发；本类所有方法都必须在 Strand 上调用。
class device_writer {
public:
    device_writer(net::any_io_executor strand, packet_device& dev, engine_stats& stats)
        : strand_(std::move(strand)), dev_(dev), stats_(stats) {}

    // 从池中获取发送缓冲：池内存在容量足够的缓冲则复用，否则新建
    packet_buffer acquire(size_t capacity, size_t headroom) {
        while (!pool_.empty()) {
            auto b = std::move(pool_.back());
            pool_.pop_back();
            if (b.capacity() >= capacity) {
                return b;
            }
        }
        return packet_buffer(capacity, headroom);
    }

    // 写完成后回收发送缓冲（必须在 Strand 上调用）
    void recycle(packet_buffer&& buf) {
        buf.reset();
        if (pool_.size() < k_pool_max) {
            pool_.push_back(std::move(buf));
        }
    }

    // 写后无需回调的发送路径（引擎内 TCP/UDP/ICMP 出包）：
    // 跳过 CompletionToken 包装与 handler 堆分配，直接在 Strand 上入队。
    void async_write_and_forget(packet_buffer&& buf) {
        queue_.push_back(entry{std::move(buf), {}});
        pump();
    }

    // 将数据包加入写队列；完成回调在调用方绑定执行器上触发
    template <typename CompletionToken>
    auto async_write(packet_buffer&& buf, CompletionToken&& token) {
        return net::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
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
            recycle(std::move(e.buf));
            e.handler(net::error::operation_aborted, 0);
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
        // 写操作持有 entry（shared_ptr 保活 buffer），cancel_all 清空队列时
        // 正在进行的写不会访问到已析构的缓冲。
        auto e = std::make_shared<entry>(std::move(queue_.front()));
        queue_.pop_front();
        dev_.async_write_packet(e->buf, net::bind_executor(strand_, [this, e](boost::system::error_code ec, size_t n) {
            writing_ = false;
            if (!ec) {
                stats_.tx_packets.fetch_add(1, std::memory_order_relaxed);
            }
            if (cancelled_) {
                if (e->handler) {
                    e->handler(net::error::operation_aborted, 0);
                }
            } else if (e->handler) {
                e->handler(ec, n);
            }
            recycle(std::move(e->buf));
            pump();
        }));
    }

    net::any_io_executor strand_;
    packet_device& dev_;
    engine_stats& stats_;
    std::deque<entry> queue_;
    std::vector<packet_buffer> pool_;
    bool writing_ = false;
    bool cancelled_ = false;
    uint16_t ip_id_ = 0;

    static constexpr size_t k_pool_max = 64;  // 池上限，避免长期闲置占用内存
};

} // namespace detail
} // namespace tunio
