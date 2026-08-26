#pragma once

#include <boost/asio.hpp>

#include "tunio/detail/handler_util.hpp"

#include "tunio/tun_stream.hpp"

namespace tunio {

class tunio;

// TCP 连接监听器
//
// async_accept 在三次握手完成（收到客户端 ACK）时触发完成回调，
// 此时连接处于 ESTABLISHED 状态。
class tun_acceptor {
public:
    explicit tun_acceptor(tunio& engine) : engine_(engine) {}

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

    tunio& engine_;
};

} // namespace tunio
