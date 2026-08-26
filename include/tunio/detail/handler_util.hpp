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

namespace asio = boost::asio;
#include <functional>
#include <memory>
#include <utility>

namespace tunio {
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

// 将完成回调绑定到调用方执行器，返回可拷贝的 std::function
template <typename Handler>
inline std::function<void(boost::system::error_code, size_t)>
bind_handler(boost::asio::any_io_executor ex, Handler&& handler) {
    auto sp = std::make_shared<std::decay_t<Handler>>(asio::bind_executor(ex, std::forward<Handler>(handler)));
    return [sp](boost::system::error_code ec, size_t n) mutable {
        std::move(*sp)(ec, n);
    };
}

} // namespace detail
} // namespace tunio
