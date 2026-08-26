#include "tun_engine/tun_udp_acceptor.hpp"

#include <utility>

#include "tun_engine/detail/tun_udp_ops.hpp"
#include "tun_engine/tun_engine.hpp"
#include "tun_engine_impl.hpp"
#include "udp_engine.hpp"

namespace tun_engine {

void tun_udp_acceptor::do_accept(tun_udp_socket& peer, std::function<void(boost::system::error_code)> handler) {
    auto ex = peer.get_executor();
    auto wrapped = [ex, h = std::move(handler)](boost::system::error_code ec) mutable {
        asio::dispatch(ex, [h = std::move(h), ec]() mutable { h(ec); });
    };
    engine_.impl_->async_accept_udp([&peer, wrapped = std::move(wrapped)](boost::system::error_code ec,
                                                                          std::shared_ptr<detail::udp_session> s) mutable {
        if (!ec && s) {
            peer.session_ = std::move(s);
        }
        wrapped(ec);
    });
}

void tun_udp_acceptor::cancel() {
    engine_.impl_->cancel_udp_accepts();
}

} // namespace tun_engine
