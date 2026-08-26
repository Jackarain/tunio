//
// tun_config.hpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace tunio {

// 平台原生句柄类型，支持外部句柄注入
#ifdef _WIN32
using native_handle_type = void*;
#else
using native_handle_type = int;
#endif

inline constexpr native_handle_type invalid_native_handle =
#ifdef _WIN32
    nullptr;
#else
    -1;
#endif

// 统一五元组，用于 NAT 查表与 Flow 索引，字段均为网络字节序
#pragma pack(push, 1)
struct five_tuple {
    uint32_t src_ip;      // 网络字节序
    uint32_t dst_ip;      // 网络字节序
    uint16_t src_port;    // 网络字节序
    uint16_t dst_port;    // 网络字节序
    uint8_t protocol;     // IPPROTO_TCP (6) 或 IPPROTO_UDP (17)
};
#pragma pack(pop)

inline bool operator==(const five_tuple& lhs, const five_tuple& rhs) noexcept {
    return lhs.src_ip == rhs.src_ip && lhs.dst_ip == rhs.dst_ip &&
           lhs.src_port == rhs.src_port && lhs.dst_port == rhs.dst_port &&
           lhs.protocol == rhs.protocol;
}

inline bool operator!=(const five_tuple& lhs, const five_tuple& rhs) noexcept {
    return !(lhs == rhs);
}

// 设备配置：自主打开 TUN 设备时使用
struct device_config {
    std::string name;
    std::string ipv4;
    std::string netmask;
    size_t mtu = 1500;
};

// 引擎总配置
struct tun_config {
    // ---- 网络配置 ----
    std::string dev_name;
    std::string ipv4_addr;
    std::string netmask;
    size_t mtu = 1500;

    // ---- 外部句柄注入 ----
    native_handle_type external_handle = invalid_native_handle;
    size_t external_mtu = 1500;

    // ---- 资源上限 ----
    size_t max_tcp_flows = 65536;
    size_t max_udp_flows = 65536;
    size_t max_rx_queue_per_flow = 1024 * 1024;
    size_t max_total_buffer = 512 * 1024 * 1024;

    // ---- 超时策略 ----
    std::chrono::seconds udp_idle_timeout{30};
    std::chrono::seconds tcp_time_wait_timeout{10};
    std::chrono::seconds tcp_accept_timeout{30}; // 已建立但未被 async_accept 领取的连接超时

    // ---- 可选 Checksum 控制 ----
    // 用户态 TUN 收发的报文必须由本引擎计算校验和，该开关保留用于兼容设计文档；
    // 引擎始终计算并校验 IP/TCP/UDP 校验和。
    bool enable_checksum_offload = true;
};

// 引擎统计信息
struct engine_stats {
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> rx_dropped{0};
    std::atomic<uint64_t> tcp_connections{0};
    std::atomic<uint64_t> udp_sessions{0};
    std::atomic<uint64_t> icmp_replies{0};
};

} // namespace tunio

namespace std {
template <>
struct hash<tunio::five_tuple> {
    size_t operator()(const tunio::five_tuple& k) const noexcept {
        size_t h = std::hash<uint32_t>{}(k.src_ip);
        h ^= std::hash<uint32_t>{}(k.dst_ip) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.src_port) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.dst_port) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(k.protocol) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        return h;
    }
};
} // namespace std
