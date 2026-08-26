//
// tunio.cpp
// ~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "tunio_impl.hpp"

#include <algorithm>
#include <cstring>

#include <boost/asio.hpp>

#include "ip_headers.hpp"

namespace tunio {
namespace detail {

tunio_impl::tunio_impl(boost::asio::io_context& ctx)
    : ctx_(ctx),
      strand_ex_(boost::asio::make_strand(ctx)),
      device_(std::make_unique<packet_device>(ctx)),
      read_buf_(2048, 64) {}

tunio_impl::~tunio_impl() {
    if (device_) {
        device_->close();
    }
}

bool tunio_impl::open(const tun_config& cfg, boost::system::error_code& ec) {
    if (open_.load(std::memory_order_acquire)) {
        close();
    }
    ec = {};
    cfg_ = cfg;

    // 解析本地虚拟 IP（用于 ICMP/ICMPv6 回显等），允许为空
    have_ip4_ = false;
    have_ip6_ = false;
    local_ip_ = boost::asio::ip::address();
    if (!cfg.ipv4_addr.empty()) {
        boost::system::error_code parse_ec;
        const auto v4 = boost::asio::ip::make_address_v4(cfg.ipv4_addr, parse_ec);
        if (parse_ec) {
            ec = parse_ec;
            return false;
        }
        local_ip_ = v4;
        const auto b = v4.to_bytes();
        std::copy(b.begin(), b.end(), local_ip4_);
        have_ip4_ = true;
    }
    if (!cfg.ipv6_addr.empty()) {
        boost::system::error_code parse_ec;
        const auto v6 = boost::asio::ip::make_address_v6(cfg.ipv6_addr, parse_ec);
        if (parse_ec) {
            ec = parse_ec;
            return false;
        }
        if (!have_ip4_) {
            local_ip_ = v6;
        }
        const auto b = v6.to_bytes();
        std::copy(b.begin(), b.end(), local_ip6_);
        have_ip6_ = true;
    }

    // 设备初始化：优先使用外部句柄注入
    if (cfg.external_handle != invalid_native_handle) {
        if (!device_->assign(cfg.external_handle, cfg.external_mtu, ec)) {
            return false;
        }
    } else {
        device_config dc;
        dc.name = cfg.dev_name;
        dc.ipv4 = cfg.ipv4_addr;
        dc.netmask = cfg.netmask;
        dc.ipv6 = cfg.ipv6_addr;
        dc.ipv6_prefix_len = cfg.ipv6_prefix_len;
        dc.mtu = cfg.mtu;
        if (!device_->open(dc, ec)) {
            return false;
        }
    }

    mtu_ = device_->mtu();
    read_buf_ = packet_buffer(mtu_ + 64, 64);

    account_ = std::make_shared<buffer_accountant>();
    account_->limit = cfg.max_total_buffer;
    writer_ = std::make_unique<device_writer>(strand_ex_, *device_, stats_);
    tcp_ = std::make_shared<tcp_engine>(strand_ex_, *writer_, cfg_, stats_, account_);
    udp_ = std::make_shared<udp_engine>(strand_ex_, *writer_, cfg_, stats_, account_);
    tcp_->start_sweep();

    open_.store(true, std::memory_order_release);
    start_read();
    return true;
}

void tunio_impl::close() {
    if (!open_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    net::dispatch(strand_ex_, [self = shared_from_this()]() {
        if (self->tcp_) {
            self->tcp_->close_all();
        }
        if (self->udp_) {
            self->udp_->close_all();
        }
        if (self->writer_) {
            self->writer_->cancel_all();
        }
        if (self->device_) {
            self->device_->close();
        }
    });
}

void tunio_impl::start_read() {
    if (!open_.load(std::memory_order_acquire) || reading_) {
        return;
    }
    reading_ = true;
    read_buf_.reset();
    auto self = shared_from_this();
    device_->async_read_packet(read_buf_, net::bind_executor(strand_ex_, [self](const boost::system::error_code& ec, size_t n) {
        self->on_read(ec, n);
    }));
}

void tunio_impl::on_read(const boost::system::error_code& ec, size_t n) {
    reading_ = false;
    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            open_.store(false, std::memory_order_release);
        }
        if (open_.load(std::memory_order_acquire)) {
            start_read(); // 设备被 close 后重新 open 的场景：继续读取新设备
        }
        return;
    }
    read_buf_.commit(n);
    // 注：注入设备为字节流（如 socketpair）时，一次读取可能粘合多个报文；
    // 按 IP 头中的总长度逐包解析，完整处理缓冲区内全部报文（IPv4/IPv6 均支持）。
    const uint8_t* base = read_buf_.data();
    size_t offset = 0;
    while (offset + 4 <= n) {
        size_t total_len = 0;
        switch (base[offset] >> 4) {
        case 4:
            if (offset + sizeof(ipv4_header) > n) {
                break;
            }
            total_len = static_cast<size_t>((base[offset + 2] << 8) | base[offset + 3]);
            if (total_len < sizeof(ipv4_header)) {
                break;
            }
            break;
        case 6:
            if (offset + sizeof(ipv6_header) > n) {
                break;
            }
            total_len = sizeof(ipv6_header) +
                        static_cast<size_t>((base[offset + 4] << 8) | base[offset + 5]);
            break;
        default:
            break;
        }
        if (total_len == 0 || offset + total_len > n) {
            break;
        }
        stats_.rx_packets.fetch_add(1, std::memory_order_relaxed);
        handle_packet(base + offset, total_len);
        offset += total_len;
    }
    start_read();
}

void tunio_impl::handle_packet(const uint8_t* pkt, size_t len) {
    if (len < 20) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    ip_packet_info ip;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;

    const uint8_t version = pkt[0] >> 4;
    if (version == 4) {
        if (len < sizeof(ipv4_header)) {
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        ipv4_header h;
        std::memcpy(&h, pkt, sizeof(h));
        const size_t ihl = h.header_len();
        if (ihl < sizeof(ipv4_header) || ihl > len) {
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const size_t total_len = ntohs(h.total_len);
        if (total_len < ihl || total_len > len) {
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        // 校验 IP 头部校验和
        if (verify_ipv4_checksum(pkt, ihl) != 0) {
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        ip.family = 4;
        ip.protocol = h.protocol;
        std::memcpy(ip.src_ip, pkt + 12, 4);
        std::memcpy(ip.dst_ip, pkt + 16, 4);
        payload = pkt + ihl;
        payload_len = total_len - ihl;
    } else if (version == 6) {
        if (len < sizeof(ipv6_header)) {
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        ipv6_header h;
        std::memcpy(&h, pkt, sizeof(h));
        const size_t payload_len_field = ntohs(h.payload_len);
        if (sizeof(ipv6_header) + payload_len_field > len) {
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        ip.family = 6;
        ip.protocol = h.next_header;
        std::memcpy(ip.src_ip, h.src_ip, 16);
        std::memcpy(ip.dst_ip, h.dst_ip, 16);
        payload = pkt + sizeof(ipv6_header);
        payload_len = payload_len_field;
    } else {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    switch (ip.protocol) {
    case IPPROTO_ICMP_V:
        handle_icmp(ip, payload, payload_len);
        break;
    case IPPROTO_ICMPV6_V:
        handle_icmpv6(ip, payload, payload_len);
        break;
    case IPPROTO_TCP_V:
        tcp_->on_packet(ip, payload, payload_len);
        break;
    case IPPROTO_UDP_V:
        udp_->on_packet(ip, payload, payload_len);
        break;
    default:
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        break;
    }
}

void tunio_impl::handle_icmp(const ip_packet_info& ip, const uint8_t* icmp, size_t icmp_len) {
    if (!have_ip4_ || icmp_len < 8) {
        return;
    }
    // 仅响应发往本地虚拟 IP 的 Echo Request
    if (std::memcmp(ip.dst_ip, local_ip4_, 4) != 0 || icmp[0] != 8) {
        return;
    }
    // 校验 ICMP 校验和
    if (ip_checksum(icmp, icmp_len) != 0) {
        return;
    }

    packet_buffer reply(20 + icmp_len + 64, 64);
    reply.resize(20 + icmp_len);
    uint8_t* out = reply.data();

    build_ip_header(out, 4, ip.dst_ip, ip.src_ip, IPPROTO_ICMP_V,
                    20 + icmp_len, writer_->alloc_ip_id());

    uint8_t* oicmp = out + 20;
    std::memcpy(oicmp, icmp, icmp_len);
    oicmp[0] = 0; // Type = Echo Reply
    oicmp[2] = 0; // 清零校验和字段后再计算
    oicmp[3] = 0;
    const uint16_t csum = ip_checksum(oicmp, icmp_len);
    oicmp[2] = static_cast<uint8_t>(csum >> 8);
    oicmp[3] = static_cast<uint8_t>(csum & 0xff);

    writer_->async_write(std::move(reply), net::bind_executor(strand_ex_, [](const boost::system::error_code&, size_t) {}));
    stats_.icmp_replies.fetch_add(1, std::memory_order_relaxed);
}

void tunio_impl::handle_icmpv6(const ip_packet_info& ip, const uint8_t* icmp, size_t icmp_len) {
    if (!have_ip6_ || icmp_len < 8) {
        return;
    }
    // 仅响应发往本地虚拟 IP 的 Echo Request
    if (std::memcmp(ip.dst_ip, local_ip6_, 16) != 0 || icmp[0] != 128) {
        return;
    }
    // ICMPv6 校验和必须包含 IPv6 伪头部
    if (tcp_udp_checksum(6, ip.src_ip, ip.dst_ip, IPPROTO_ICMPV6_V, icmp, icmp_len) != 0) {
        return;
    }

    packet_buffer reply(40 + icmp_len + 64, 64);
    reply.resize(40 + icmp_len);
    uint8_t* out = reply.data();

    build_ip_header(out, 6, ip.dst_ip, ip.src_ip, IPPROTO_ICMPV6_V,
                    40 + icmp_len, 0);

    uint8_t* oicmp = out + 40;
    std::memcpy(oicmp, icmp, icmp_len);
    oicmp[0] = 129; // Type = Echo Reply
    oicmp[2] = 0;   // 清零校验和字段后再计算
    oicmp[3] = 0;
    const uint16_t csum = tcp_udp_checksum(6, ip.dst_ip, ip.src_ip, IPPROTO_ICMPV6_V,
                                           oicmp, icmp_len);
    oicmp[2] = static_cast<uint8_t>(csum >> 8);
    oicmp[3] = static_cast<uint8_t>(csum & 0xff);

    writer_->async_write(std::move(reply), net::bind_executor(strand_ex_, [](const boost::system::error_code&, size_t) {}));
    stats_.icmp_replies.fetch_add(1, std::memory_order_relaxed);
}

} // namespace detail

tunio::tunio(boost::asio::io_context& ctx)
    : impl_(std::make_shared<detail::tunio_impl>(ctx)) {}

tunio::~tunio() = default;

bool tunio::open(const tun_config& config, boost::system::error_code& ec) {
    return impl_->open(config, ec);
}

void tunio::close() {
    impl_->close();
}

bool tunio::is_open() const noexcept {
    return impl_->is_open();
}

size_t tunio::mtu() const noexcept {
    return impl_->mtu();
}

boost::asio::ip::address tunio::local_address() const noexcept {
    return impl_->local_address();
}

const engine_stats& tunio::stats() const noexcept {
    return impl_->stats();
}

tunio::executor_type tunio::get_executor() const noexcept {
    return impl_->strand();
}

} // namespace tunio
