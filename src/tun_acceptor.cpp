//
// tun_acceptor.cpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "tunio/tun_acceptor.hpp"

#include <utility>

#include "tcp_engine.hpp"
#include "tunio/detail/tun_stream_ops.hpp"
#include "tunio/tunio.hpp"
#include "tunio_impl.hpp"

namespace tunio {

void tun_acceptor::do_accept(tun_stream& peer, std::function<void(boost::system::error_code)> handler) {
    auto ex = peer.get_executor();
    auto wrapped = [ex, h = std::move(handler)](boost::system::error_code ec) mutable {
        net::dispatch(ex, [h = std::move(h), ec]() mutable { h(ec); });
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

} // namespace tunio
