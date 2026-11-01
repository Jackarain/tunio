//
// completion.hpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/asio.hpp>

#include <tuple>
#include <utility>

namespace tunio {
namespace net = boost::asio;
namespace detail {

// 异步完成回调不得在发起函数内执行。先 post 到操作自身的回退执行器，
// 确保发起函数已经返回；再在已出栈的任务中 dispatch 到处理器的关联
// 执行器，兼顾 Asio 的非内联约束与 bind_executor 的执行器语义。
template <typename FallbackExecutor, typename Handler, typename... Args>
void post_completion_on(
    const FallbackExecutor& fallback, Handler handler, Args... args)
{
    auto ex = net::get_associated_executor(handler, fallback);
    net::post(fallback,
        [h = std::move(handler),
            args = std::tuple(std::move(args)...),
            ex = std::move(ex)]() mutable
        {
            net::dispatch(std::move(ex),
                [h = std::move(h), args = std::move(args)]() mutable
                {
                    std::apply(std::move(h), std::move(args));
                });
        });
}

// 无法提供操作执行器时使用系统执行器作为提交位置；关联执行器仍会用于
// 最终执行完成回调。
template <typename Handler, typename... Args>
void post_completion(Handler handler, Args... args)
{
    post_completion_on(net::system_executor(),
        std::move(handler),
        std::move(args)...);
}

} // namespace detail
} // namespace tunio
