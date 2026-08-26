//
// tun_stream_ops.hpp
// ~~~~~~~~~~~~~~~~~~
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
#include "tunio/tun_stream.hpp"

namespace tunio {
namespace net = boost::asio;

namespace detail {

struct tcp_flow;

void tcp_flow_start_read(std::shared_ptr<tcp_flow> flow,
                         std::vector<net::mutable_buffer> buffers,
                         size_t total,
                         std::function<void(boost::system::error_code, size_t)> handler);

void tcp_flow_start_write(std::shared_ptr<tcp_flow> flow,
                          std::vector<uint8_t> data,
                          std::function<void(boost::system::error_code, size_t)> handler);

} // namespace detail

template <typename MutableBufferSequence>
void tun_stream::do_read_some(MutableBufferSequence&& buffers,
                              std::function<void(boost::system::error_code, size_t)> handler) {
    std::vector<net::mutable_buffer> seq;
    size_t total = 0;
    for (const auto& b : buffers) {
        seq.push_back(b);
        total += b.size();
    }

    auto flow = flow_;
    if (!flow) {
        auto ex = ex_;
        net::post(ex, [handler = std::move(handler)]() mutable {
            handler(boost::asio::error::bad_descriptor, 0);
        });
        return;
    }
    detail::tcp_flow_start_read(std::move(flow), std::move(seq), total,
                                detail::bind_handler(ex_, std::move(handler)));
}

template <typename ConstBufferSequence>
void tun_stream::do_write_some(ConstBufferSequence&& buffers,
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

    auto flow = flow_;
    if (!flow) {
        auto ex = ex_;
        net::post(ex, [handler = std::move(handler)]() mutable {
            handler(boost::asio::error::bad_descriptor, 0);
        });
        return;
    }
    detail::tcp_flow_start_write(std::move(flow), std::move(data),
                                 detail::bind_handler(ex_, std::move(handler)));
}

} // namespace tunio
