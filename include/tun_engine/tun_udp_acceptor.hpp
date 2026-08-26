#pragma once

#include <boost/asio.hpp>

#include "tun_engine/detail/handler_util.hpp"
#include <functional>

#include "tun_engine/tun_udp_socket.hpp"

namespace tun_engine {

class tun_engine;

// UDP 新会话监听器
//
// 当引擎收到一个属于未知五元组的 UDP 数据报时，自动创建新的会话，
// async_accept 触发完成回调并将会话对应的 tun_udp_socket 交给调用者。
class tun_udp_acceptor {
public:
    explicit tun_udp_acceptor(tun_engine& engine) : engine_(engine) {}

    template <typename CompletionToken>
    auto async_accept(tun_udp_socket& peer, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this, &peer](auto handler) {
                do_accept(peer, detail::make_copyable(std::move(handler)));
            },
            token);
    }

    // 取消全部挂起的 accept 操作
    void cancel();

private:
    void do_accept(tun_udp_socket& peer, std::function<void(boost::system::error_code)> handler);

    tun_engine& engine_;
};

} // namespace tun_engine
