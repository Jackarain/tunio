#include "tun_engine/tun_acceptor.hpp"

#include <utility>

#include "tcp_engine.hpp"
#include "tun_engine/detail/tun_stream_ops.hpp"
#include "tun_engine/tun_engine.hpp"
#include "tun_engine_impl.hpp"

namespace tun_engine {

void tun_acceptor::do_accept(tun_stream& peer, std::function<void(boost::system::error_code)> handler) {
    auto ex = peer.get_executor();
    auto wrapped = [ex, h = std::move(handler)](boost::system::error_code ec) mutable {
        asio::dispatch(ex, [h = std::move(h), ec]() mutable { h(ec); });
    };
    engine_.impl_->async_accept_tcp([&peer, wrapped = std::move(wrapped)](boost::system::error_code ec,
                                                                          std::shared_ptr<detail::tcp_flow> f) mutable {
        if (!ec && f) {
            peer.flow_ = std::move(f);
        }
        wrapped(ec);
    });
}

void tun_acceptor::cancel() {
    engine_.impl_->cancel_tcp_accepts();
}

} // namespace tun_engine
