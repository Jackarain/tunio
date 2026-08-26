//
// handler_util.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/asio.hpp>

#include <functional>
#include <memory>
#include <utility>

namespace tunio {
namespace net = boost::asio;
namespace detail {

// 将任意 CompletionHandler（含 move-only，如 use_awaitable 续体）包装为可拷贝形式
template <typename Handler>
inline auto make_copyable(Handler&& handler) {
    using handler_t = std::decay_t<Handler>;
    auto sp = std::make_shared<handler_t>(std::forward<Handler>(handler));
    return [sp](auto&&... args) mutable {
        std::move(*sp)(std::forward<decltype(args)>(args)...);
    };
}

} // namespace detail
} // namespace tunio
