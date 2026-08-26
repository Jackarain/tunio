//
// tun_udp_socket.hpp
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/asio.hpp>

#include <chrono>
#include <memory>

#include "tunio/tun_config.hpp"

namespace tunio {
namespace net = boost::asio;

namespace detail {
struct udp_session;
}

// UDP 数据报套接字
//
// 表示引擎 NAT 会话表中的一条 UDP 会话（由五元组唯一标识）。
// async_receive / async_send 严格遵循一次收发对应一个完整数据报的语义。
class tun_udp_socket {

public:
 using executor_type = net::any_io_executor;

 explicit tun_udp_socket(executor_type ex);
 ~tun_udp_socket();

 tun_udp_socket(tun_udp_socket&&) noexcept;
 tun_udp_socket& operator=(tun_udp_socket&&) noexcept;

 executor_type get_executor() const noexcept;

 // 该会话对应的五元组（客户端地址与目标地址）
 five_tuple remote_key() const;

 // 异步接收一个完整数据报
 template <typename MutableBufferSequence, typename CompletionToken>
 auto async_receive(MutableBufferSequence&& buffers, CompletionToken&& token) {
  return net::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
   [this](auto handler, auto buffers) mutable {
    do_receive(std::move(buffers), net::bind_executor(ex_, std::move(handler)));
   },
   token,
   std::forward<MutableBufferSequence>(buffers));
 }

 // 异步发送一个完整数据报
 template <typename ConstBufferSequence, typename CompletionToken>
 auto async_send(ConstBufferSequence&& buffers, CompletionToken&& token) {
  return net::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
   [this](auto handler, auto buffers) mutable {
    do_send(std::move(buffers), net::bind_executor(ex_, std::move(handler)));
   },
   token,
   std::forward<ConstBufferSequence>(buffers));
 }

 // 设置会话空闲超时
 void set_timeout(std::chrono::seconds timeout);

 void close();
 bool is_open() const noexcept;

private:
 template <typename MutableBufferSequence, typename Handler>
 void do_receive(MutableBufferSequence&& buffers, Handler handler);
 template <typename ConstBufferSequence, typename Handler>
 void do_send(ConstBufferSequence&& buffers, Handler handler);

 executor_type ex_;
 std::shared_ptr<detail::udp_session> session_;

 friend class tun_udp_acceptor;
};

}

#include "tunio/detail/tun_udp_ops.hpp"
