//
// packet_device.hpp
// ~~~~~~~~~~~~~~~~~
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
#include <variant>

#include "tunio/packet_buffer.hpp"
#include "tunio/tun_config.hpp"

namespace tunio {
namespace detail {

// ---- POSIX 实现 (Linux TUN / macOS utun) ----
#if defined(BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR)
class posix_packet_device_impl {
public:
    explicit posix_packet_device_impl(boost::asio::io_context& ctx) : desc_(ctx) {}

    // 平台相关打开逻辑，见 src/packet_device.cpp
    bool open(const device_config& cfg, boost::system::error_code& ec);
    bool assign(native_handle_type handle, size_t mtu, boost::system::error_code& ec) {
        desc_.assign(static_cast<native_handle_type>(handle), ec);
        if (!ec) {
            open_ = true;
            mtu_ = mtu;
        }
        return !ec;
    }

    void close() {
        if (open_) {
            desc_.close();
            open_ = false;
        }
    }

    size_t mtu() const { return mtu_; }
    bool is_open() const { return open_; }

    template <typename Handler>
    void async_read(packet_buffer& buf, Handler&& handler) {
        desc_.async_read_some(boost::asio::buffer(buf.writable_data(), buf.writable_size()),
                              std::forward<Handler>(handler));
    }

    template <typename Handler>
    void async_write(packet_buffer& buf, Handler&& handler) {
        desc_.async_write_some(boost::asio::buffer(buf.data(), buf.size()),
                               std::forward<Handler>(handler));
    }

    boost::asio::posix::stream_descriptor desc_;
    size_t mtu_ = 1500;
    bool open_ = false;
};

using device_impl_variant = std::variant<posix_packet_device_impl>;

#elif defined(BOOST_ASIO_HAS_WINDOWS_OVERLAPPED_PTR)

// ---- Windows 实现 (Wintun / Overlapped) ----
class windows_packet_device_impl {
public:
    explicit windows_packet_device_impl(boost::asio::io_context& ctx) : handle_(ctx) {}

    // 平台相关打开逻辑（Wintun 会话创建），见 src/packet_device.cpp
    bool open(const device_config& cfg, boost::system::error_code& ec);
    bool assign(native_handle_type handle, size_t mtu, boost::system::error_code& ec) {
        handle_.assign(handle, ec);
        if (!ec) {
            open_ = true;
            mtu_ = mtu;
        }
        return !ec;
    }

    void close() {
        if (open_) {
            handle_.close();
            open_ = false;
        }
    }

    size_t mtu() const { return mtu_; }
    bool is_open() const { return open_; }

    template <typename Handler>
    void async_read(packet_buffer& buf, Handler&& handler) {
        handle_.async_read_some_at(0, boost::asio::buffer(buf.writable_data(), buf.writable_size()),
                                   std::forward<Handler>(handler));
    }

    template <typename Handler>
    void async_write(packet_buffer& buf, Handler&& handler) {
        handle_.async_write_some_at(0, boost::asio::buffer(buf.data(), buf.size()),
                                    std::forward<Handler>(handler));
    }

    boost::asio::windows::overlapped_handle handle_;
    size_t mtu_ = 1500;
    bool open_ = false;
};

using device_impl_variant = std::variant<windows_packet_device_impl>;

#else

// ---- 无平台实现时的兜底类型 ----
class unsupported_packet_device {
public:
    explicit unsupported_packet_device(boost::asio::io_context&) {}

    bool open(const device_config&, boost::system::error_code& ec) {
        ec = make_error_code(boost::system::errc::operation_not_supported);
        return false;
    }

    bool assign(native_handle_type, size_t, boost::system::error_code& ec) {
        ec = make_error_code(boost::system::errc::operation_not_supported);
        return false;
    }

    void close() {}
    size_t mtu() const { return 0; }
    bool is_open() const { return false; }

    template <typename Handler>
    void async_read(packet_buffer&, Handler&& handler) {
        std::forward<Handler>(handler)(boost::asio::error::bad_descriptor, 0);
    }

    template <typename Handler>
    void async_write(packet_buffer&, Handler&& handler) {
        std::forward<Handler>(handler)(boost::asio::error::bad_descriptor, 0);
    }
};

using device_impl_variant = std::variant<unsupported_packet_device>;

#endif

} // namespace detail
// 跨平台设备抽象层
//
// 支持两种初始化模式：
//   ① 自主打开模式：open(device_config) -> 由引擎创建并配置 TUN 设备；
//   ② 句柄注入模式：assign(handle, mtu) -> 接管外部应用已打开的平台句柄。
//
// 异步 I/O 完全对齐 Boost.Asio 范式：async_read_packet / async_write_packet
// 使用 CompletionToken 模板参数，通过 async_initiate 实现，可与 use_awaitable、
// use_future 及自定义 CompletionToken 无缝协作。
class packet_device {
public:
    explicit packet_device(boost::asio::io_context& ctx) : ctx_(ctx), impl_(std::in_place_index<0>, ctx) {}

    // ---- 模式 1: 自主打开 ----
    bool open(const device_config& cfg, boost::system::error_code& ec) {
#if defined(BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR)
        impl_.emplace<detail::posix_packet_device_impl>(ctx_);
#elif defined(BOOST_ASIO_HAS_WINDOWS_OVERLAPPED_PTR)
        impl_.emplace<detail::windows_packet_device_impl>(ctx_);
#else
        impl_.emplace<detail::unsupported_packet_device>(ctx_);
#endif
        return std::visit([&](auto& impl) { return impl.open(cfg, ec); }, impl_);
    }

    // ---- 模式 2: 句柄注入 ----
    bool assign(native_handle_type handle, size_t mtu, boost::system::error_code& ec) {
#if defined(BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR)
        impl_.emplace<detail::posix_packet_device_impl>(ctx_);
#elif defined(BOOST_ASIO_HAS_WINDOWS_OVERLAPPED_PTR)
        impl_.emplace<detail::windows_packet_device_impl>(ctx_);
#else
        impl_.emplace<detail::unsupported_packet_device>(ctx_);
#endif
        return std::visit([&](auto& impl) { return impl.assign(handle, mtu, ec); }, impl_);
    }

    void close() {
        std::visit([](auto& impl) { impl.close(); }, impl_);
    }

    size_t mtu() const {
        return std::visit([](const auto& impl) -> size_t { return impl.mtu(); }, impl_);
    }

    bool is_open() const {
        return std::visit([](const auto& impl) -> bool { return impl.is_open(); }, impl_);
    }

    // ---- 异步读取一个完整数据包 ----
    template <typename CompletionToken>
    auto async_read_packet(packet_buffer& buf, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this, &buf](auto handler) {
                std::visit([&buf, h = std::move(handler)](auto& impl) mutable {
                    impl.async_read(buf, std::move(h));
                }, impl_);
            },
            token);
    }

    // ---- 异步写入一个完整数据包 ----
    template <typename CompletionToken>
    auto async_write_packet(packet_buffer& buf, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this, &buf](auto handler) {
                std::visit([&buf, h = std::move(handler)](auto& impl) mutable {
                    impl.async_write(buf, std::move(h));
                }, impl_);
            },
            token);
    }

private:
    boost::asio::io_context& ctx_;
    detail::device_impl_variant impl_;
};

} // namespace tunio
