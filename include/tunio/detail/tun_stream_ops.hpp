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

#include <memory>
#include <vector>

#include "tcp_engine.hpp"
#include "tunio/tun_stream.hpp"

namespace tunio {
namespace net = boost::asio;

namespace detail {
} // namespace detail

template <typename MutableBufferSequence, typename Handler>
void tun_stream::do_read_some(MutableBufferSequence&& buffers,
                              Handler handler) {
    std::vector<net::mutable_buffer> seq;
    size_t total = 0;
    for (const auto& b : buffers) {
        seq.push_back(b);
        total += b.size();
    }

    auto flow = flow_;
    if (!flow) {
        handler(boost::system::error_code(net::error::bad_descriptor), 0);
        return;
    }
    detail::tcp_flow_start_read(std::move(flow), std::move(seq), total,
                                std::move(handler));
}

template <typename ConstBufferSequence, typename Handler>
void tun_stream::do_write_some(ConstBufferSequence&& buffers,
                               Handler handler) {
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
        handler(boost::system::error_code(net::error::bad_descriptor), 0);
        return;
    }
    detail::tcp_flow_start_write(std::move(flow), std::move(data),
                                 std::move(handler));
}

} // namespace tunio
