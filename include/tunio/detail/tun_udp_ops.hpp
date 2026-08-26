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

#include <boost/asio.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "tunio/detail/handler_util.hpp"
#include "tunio/tun_udp_socket.hpp"

namespace tunio {
namespace net = boost::asio;

namespace detail {

struct udp_session;

void udp_session_start_receive(std::shared_ptr<udp_session> session,
                               std::vector<net::mutable_buffer> buffers,
                               size_t total,
                               std::function<void(boost::system::error_code, size_t)> handler);

void udp_session_start_send(std::shared_ptr<udp_session> session,
                            std::vector<uint8_t> data,
                            std::function<void(boost::system::error_code, size_t)> handler);

} // namespace detail

template <typename MutableBufferSequence>
void tun_udp_socket::do_receive(MutableBufferSequence&& buffers,
                                std::function<void(boost::system::error_code, size_t)> handler) {
    std::vector<net::mutable_buffer> seq;
    size_t total = 0;
    for (const auto& b : buffers) {
        seq.push_back(b);
        total += b.size();
    }

    auto session = session_;
    if (!session) {
        auto ex = ex_;
        net::post(ex, [handler = std::move(handler)]() mutable {
            handler(boost::asio::error::bad_descriptor, 0);
        });
        return;
    }
    detail::udp_session_start_receive(std::move(session), std::move(seq), total,
                                      detail::bind_handler(ex_, std::move(handler)));
}

template <typename ConstBufferSequence>
void tun_udp_socket::do_send(ConstBufferSequence&& buffers,
                             std::function<void(boost::system::error_code, size_t)> handler) {
    size_t total = 0;
    for (const auto& b : buffers) {
        total += b.size();
    }

    std::vector<uint8_t> data;
    data.reserve(total);
    for (const auto& b : buffers) {
        const uint8_t* p = static_cast<const uint8_t*>(b.data());
        data.insert(data.end(), p, p + b.size());
    }

    auto session = session_;
    if (!session) {
        auto ex = ex_;
        net::post(ex, [handler = std::move(handler)]() mutable {
            handler(boost::asio::error::bad_descriptor, 0);
        });
        return;
    }
    detail::udp_session_start_send(std::move(session), std::move(data),
                                   detail::bind_handler(ex_, std::move(handler)));
}

} // namespace tunio
