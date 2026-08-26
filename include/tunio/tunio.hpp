#pragma once

#include <boost/asio.hpp>
#include <memory>

#include "tunio/tun_config.hpp"

namespace tunio {

namespace detail {
class tunio_impl;
class tcp_engine;
class udp_engine;
} // namespace detail

// 用户态 TUN 网络引擎
//
// 引擎封装 TUN 设备 I/O、TCP/UDP 协议引擎与 NAT 会话表，向应用层暴露
// tun_stream / tun_acceptor / tun_udp_socket / tun_udp_acceptor 等异步接口。
// 所有内部状态变更均运行于引擎的 Strand 之上，支持多线程运行 io_context。
//
// 生命周期要求：引擎必须在所有 tun_stream / tun_udp_socket 销毁之后、
// io_context 停止运行之前销毁（与 Boost.Asio 对 socket 的约束一致）。
class tunio {
public:
    using executor_type = boost::asio::any_io_executor;

    explicit tunio(boost::asio::io_context& ctx);
    ~tunio();

    tunio(const tunio&) = delete;
    tunio& operator=(const tunio&) = delete;

    // 打开 TUN 设备并启动数据通路；外部句柄注入时 config.external_handle 必须有效。
    bool open(const tun_config& config, boost::system::error_code& ec);

    // 关闭引擎：停止数据通路并清理全部会话与挂起操作。
    void close();

    bool is_open() const noexcept;
    size_t mtu() const noexcept;

    // 引擎本地虚拟 IP（用于 ICMP 回显响应等）。
    boost::asio::ip::address local_address() const noexcept;

    const engine_stats& stats() const noexcept;

    // 引擎内部 Strand 的执行器；应用层也可通过其提交任务保证与引擎状态串行化。
    executor_type get_executor() const noexcept;

private:
    friend class tun_acceptor;
    friend class tun_udp_acceptor;

    std::shared_ptr<detail::tunio_impl> impl_;
};

} // namespace tunio
