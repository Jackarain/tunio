//
// proxy.cpp
// ~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// 代理 URL 解析与工厂实现。
//
// 本文件是示例中唯一包含 <boost/url/src.hpp> 的翻译单元：Boost.URL 以
// header-only 方式使用，其余 TU 只需声明，避免链接独立的 boost_url 库。

#include "proxy.hpp"

#include "direct_proxy.hpp"
#include "http_proxy.hpp"
#include "socks5_client.hpp"

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/url/src.hpp>
#include <boost/url.hpp>

#include <string>
#include <tuple>

namespace tun2socks_example {

namespace {

uint16_t default_port_for(std::string_view scheme) noexcept
{
    return scheme == "http" ? 8080 : 1080;
}

} // namespace

bool parse_proxy_url(std::string_view text, proxy_config& out, std::string& err)
{
    out = proxy_config{};
    err.clear();

    if (text.empty()) {
        err = "代理地址不能为空";
        return false;
    }

    // 无 scheme 时按 sock5 处理，兼容旧的 host:port 写法。
    std::string url(text);
    if (url.find("://") == std::string::npos) {
        url = "socks5://" + url;
    }

    auto parsed = boost::urls::parse_uri(url);
    if (!parsed) {
        err = "非法代理 URL: " + std::string(text);
        return false;
    }
    boost::urls::url_view view = *parsed;

    std::string scheme(view.scheme());
    if (scheme.empty()) {
        scheme = "socks5";
    }
    if (scheme != "socks5" && scheme != "http" && scheme != "direct" &&
        scheme != "reject") {
        err = "不支持的代理协议: " + scheme;
        return false;
    }
    out.scheme = scheme;

    if (view.has_userinfo()) {
        out.user = std::string(view.user());
        out.pass = std::string(view.password());
    }

    if (scheme == "direct" || scheme == "reject") {
        return true;
    }

    if (view.host().empty()) {
        err = "代理 URL 缺少主机名: " + std::string(text);
        return false;
    }
    out.host = std::string(view.host());
    // Boost.URL 的 host() 对 IPv6 返回带方括号形式（如 "[::1]"），
    // 解析端点需要裸地址，这里去掉方括号。
    if (out.host.size() >= 2 && out.host.front() == '[' &&
        out.host.back() == ']') {
        out.host = out.host.substr(1, out.host.size() - 2);
    }

    if (view.has_port()) {
        const std::string port(view.port());
        unsigned long value = 0;
        try {
            value = std::stoul(port);
        } catch (const std::exception&) {
            err = "非法代理端口: " + port;
            return false;
        }
        if (value == 0 || value > 65535) {
            err = "代理端口越界: " + port;
            return false;
        }
        out.port = static_cast<uint16_t>(value);
    } else {
        out.port = default_port_for(scheme);
    }
    return true;
}

net::awaitable<net::ip::tcp::socket> connect_tcp_with_timeout(
    net::any_io_executor ex, net::ip::tcp::endpoint target,
    std::chrono::milliseconds timeout)
{
    net::ip::tcp::socket sock(ex);
    net::steady_timer timer(ex);
    timer.expires_after(timeout);

    // Boost 1.81 无 cancel_after，用 awaitable_operators 的 || 做超时竞速：
    // 定时器先到则连接被取消，连接先完成则定时器被取消（两者均由库等待
    // 收尾，避免悬挂操作引用已销毁对象）。
    using namespace net::experimental::awaitable_operators;
    auto result = co_await (
        sock.async_connect(target, net::as_tuple(net::use_awaitable)) ||
        timer.async_wait(net::as_tuple(net::use_awaitable)));

    const std::string what = "connect " + target.address().to_string() + ":" +
        std::to_string(target.port());
    if (result.index() == 1) {
        throw boost::system::system_error(net::error::timed_out, what);
    }
    const auto &connect_result = std::get<0>(result);
    const boost::system::error_code ec = std::get<0>(connect_result);
    if (ec) {
        throw boost::system::system_error(ec, what);
    }
    co_return std::move(sock);
}

std::shared_ptr<proxy> make_proxy(const proxy_config& cfg,
    net::any_io_executor ex, std::chrono::milliseconds connect_timeout)
{
    if (cfg.scheme == "socks5") {
        return std::make_shared<socks5_proxy>(cfg, ex, connect_timeout);
    }
    if (cfg.scheme == "http") {
        return std::make_shared<http_proxy>(cfg, ex, connect_timeout);
    }
    if (cfg.scheme == "direct") {
        return std::make_shared<direct_proxy>(ex, connect_timeout);
    }
    if (cfg.scheme == "reject") {
        return std::make_shared<reject_proxy>();
    }
    return nullptr;
}

} // namespace tun2socks_example
