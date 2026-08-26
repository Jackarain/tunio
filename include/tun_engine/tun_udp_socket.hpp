#pragma once

#include <boost/asio.hpp>

#include "tun_engine/detail/handler_util.hpp"
#include <chrono>
#include <memory>

#include "tun_engine/tun_config.hpp"

namespace tun_engine {

namespace detail {
struct udp_session;
} // namespace detail

// UDP 数据报套接字
//
// 表示引擎 NAT 会话表中的一条 UDP 会话（由五元组唯一标识）。
// async_receive / async_send 严格遵循一次收发对应一个完整数据报的语义。
class tun_udp_socket {
public:
    using executor_type = boost::asio::any_io_executor;

    explicit tun_udp_socket(executor_type ex);
    ~tun_udp_socket();

    tun_udp_socket(tun_udp_socket&&) noexcept;
    tun_udp_socket& operator=(tun_udp_socket&&) noexcept;

    executor_type get_executor() const noexcept;

    // 该会话对应的五元组（客户端地址与目标地址）
    five_tuple remote_key() const;

    // 异步接收一个完整数据报
    template <typename MutableBufferSequence, typename CompletionToken>
    auto async_receive(MutableBufferSequence&& buffers, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this](auto handler, auto buffers) mutable {
                do_receive(std::move(buffers), detail::make_copyable(std::move(handler)));
            },
            token,
            std::forward<MutableBufferSequence>(buffers));
    }

    // 异步发送一个完整数据报
    template <typename ConstBufferSequence, typename CompletionToken>
    auto async_send(ConstBufferSequence&& buffers, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this](auto handler, auto buffers) mutable {
                do_send(std::move(buffers), detail::make_copyable(std::move(handler)));
            },
            token,
            std::forward<ConstBufferSequence>(buffers));
    }

    // 设置会话空闲超时
    void set_timeout(std::chrono::seconds timeout);

    void close();
    bool is_open() const noexcept;

private:
    template <typename MutableBufferSequence>
    void do_receive(MutableBufferSequence&& buffers, std::function<void(boost::system::error_code, size_t)> handler);
    template <typename ConstBufferSequence>
    void do_send(ConstBufferSequence&& buffers, std::function<void(boost::system::error_code, size_t)> handler);

    executor_type ex_;
    std::shared_ptr<detail::udp_session> session_;

    friend class tun_udp_acceptor;
};

} // namespace tun_engine

#include "tun_engine/detail/tun_udp_ops.hpp"
