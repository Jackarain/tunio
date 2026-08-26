#pragma once

#include <boost/asio.hpp>

#include "tun_engine/detail/handler_util.hpp"

#include "tun_engine/tun_stream.hpp"

namespace tun_engine {

class tun_engine;

// TCP 连接监听器
//
// async_accept 在三次握手完成（收到客户端 ACK）时触发完成回调，
// 此时连接处于 ESTABLISHED 状态。
class tun_acceptor {
public:
    explicit tun_acceptor(tun_engine& engine) : engine_(engine) {}

    template <typename CompletionToken>
    auto async_accept(tun_stream& peer, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this, &peer](auto handler) {
                do_accept(peer, detail::make_copyable(std::move(handler)));
            },
            token);
    }

    // 取消全部挂起的 accept 操作
    void cancel();

private:
    void do_accept(tun_stream& peer, std::function<void(boost::system::error_code)> handler);

    tun_engine& engine_;
};

} // namespace tun_engine
