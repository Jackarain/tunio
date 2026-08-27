//
// tun_udp_ops.hpp
// ~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include "tunio/tun_udp_socket.hpp"
#include "udp_engine.hpp"

#include <memory>
#include <vector>

namespace tunio {
namespace net = boost::asio;

namespace detail {
} // namespace detail

template <typename MutableBufferSequence, typename Handler>
void tun_udp_socket::do_receive_from(MutableBufferSequence &&buffers,
                                     net::ip::udp::endpoint &sender,
                                     Handler handler)
{
    std::vector<net::mutable_buffer> seq;
    size_t total = 0;
    for (const auto &b : buffers) {
        seq.push_back(b);
        total += b.size();
    }

    auto session = session_;
    if (!session) {
        handler(boost::system::error_code(net::error::bad_descriptor), 0);
        return;
    }
    detail::udp_session_start_receive(std::move(session), std::move(seq), total,
                                      sender, std::move(handler));
}

template <typename ConstBufferSequence, typename Handler>
void tun_udp_socket::do_send_to(const net::ip::udp::endpoint &remote,
                                ConstBufferSequence &&buffers, Handler handler)
{
    std::vector<net::const_buffer> seq;
    size_t total = 0;
    for (const auto &b : buffers) {
        seq.push_back(b);
        total += b.size();
    }

    auto session = session_;
    if (!session) {
        handler(boost::system::error_code(net::error::bad_descriptor), 0);
        return;
    }
    detail::udp_session_start_send(std::move(session), remote, std::move(seq),
                                   total, std::move(handler));
}

} // namespace tunio
