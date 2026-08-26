#pragma once

#include <cstddef>
#include <cstdint>

namespace tunio {
namespace detail {

constexpr uint8_t IPPROTO_ICMP_V = 1;
constexpr uint8_t IPPROTO_TCP_V = 6;
constexpr uint8_t IPPROTO_UDP_V = 17;

// ---- 紧凑报文头部（均为网络字节序字段）----
#pragma pack(push, 1)
struct ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    uint8_t version() const { return static_cast<uint8_t>(version_ihl >> 4); }
    uint8_t ihl() const { return static_cast<uint8_t>(version_ihl & 0x0f); }
    size_t header_len() const { return static_cast<size_t>(ihl()) * 4; }
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;

    size_t header_len() const { return static_cast<size_t>(data_offset >> 4) * 4; }
};

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

// TCP 标志位
enum tcp_flag : uint8_t {
    TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20,
};

// ---- 校验和工具（RFC 1071 反码和）----
inline uint32_t checksum_sum(const uint8_t* data, size_t len, uint32_t sum = 0) {
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += static_cast<uint16_t>(data[i] << 8);
    }
    return sum;
}

inline uint16_t checksum_fold(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// 对 data[0, len) 计算反码和校验
inline uint16_t ip_checksum(const uint8_t* data, size_t len) {
    return checksum_fold(checksum_sum(data, len));
}

// IPv4 头部校验和（自动跳过 checksum 字段本身）
inline uint16_t ipv4_checksum(const uint8_t* ip, size_t hlen) {
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < hlen; i += 2) {
        uint16_t word = static_cast<uint16_t>((ip[i] << 8) | ip[i + 1]);
        if (i == 10) {
            word = 0;
        }
        sum += word;
    }
    return checksum_fold(sum);
}

// IPv4 头部校验和验证（包含 checksum 字段求和，合法头部结果为 0）
inline uint16_t verify_ipv4_checksum(const uint8_t* ip, size_t hlen) {
    return checksum_fold(checksum_sum(ip, hlen));
}

// TCP/UDP 伪头部校验和
inline uint16_t tcp_udp_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                                 const uint8_t* segment, size_t seg_len) {
    uint32_t sum = 0;
    // 地址按网络字节序存储：直接按内存字节拆成 16 位字，避免主机字节序干扰
    const uint8_t* s = reinterpret_cast<const uint8_t*>(&src_ip);
    const uint8_t* d = reinterpret_cast<const uint8_t*>(&dst_ip);
    sum += static_cast<uint16_t>((s[0] << 8) | s[1]) + static_cast<uint16_t>((s[2] << 8) | s[3]);
    sum += static_cast<uint16_t>((d[0] << 8) | d[1]) + static_cast<uint16_t>((d[2] << 8) | d[3]);
    sum += static_cast<uint16_t>(protocol);
    sum += static_cast<uint16_t>(seg_len);
    sum += checksum_sum(segment, seg_len);
    return checksum_fold(sum);
}

// 序列号比较（RFC 1982 环形比较）
inline bool seq_lt(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) < 0;
}

inline bool seq_gt(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) > 0;
}

inline bool seq_ge(uint32_t a, uint32_t b) {
    return a == b || seq_gt(a, b);
}

} // namespace detail
} // namespace tunio
