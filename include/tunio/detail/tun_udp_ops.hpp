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
void tun_udp_socket::do_receive(MutableBufferSequence &&buffers,
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
                                      std::move(handler));
}

template <typename ConstBufferSequence, typename Handler>
void tun_udp_socket::do_send(ConstBufferSequence &&buffers, Handler handler)
{
    size_t total = 0;
    for (const auto &b : buffers) {
        total += b.size();
    }

    std::vector<uint8_t> data;
    data.reserve(total);
    for (const auto &b : buffers) {
        const uint8_t *p = static_cast<const uint8_t *>(b.data());
        data.insert(data.end(), p, p + b.size());
    }

    auto session = session_;
    if (!session) {
        handler(boost::system::error_code(net::error::bad_descriptor), 0);
        return;
    }
    detail::udp_session_start_send(std::move(session), std::move(data),
                                   std::move(handler));
}

} // namespace tunio
