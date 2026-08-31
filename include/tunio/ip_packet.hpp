//
// ip_packet.hpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include "tunio/packet_buffer.hpp"

#include <boost/asio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#if defined(__SSE2__)
#include <emmintrin.h>
#endif

namespace tunio {
namespace net = boost::asio;

// 上层协议号（避免与系统宏 IPPROTO_* 冲突，取独立命名）
inline constexpr uint8_t ip_protocol_icmp = 1;
inline constexpr uint8_t ip_protocol_tcp = 6;
inline constexpr uint8_t ip_protocol_udp = 17;
inline constexpr uint8_t ip_protocol_icmpv6 = 58;

// ---- 紧凑报文头部（均为网络字节序字段）----
#pragma pack(push, 1)
struct ipv4_header
{
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

    uint8_t version() const
    {
        return static_cast<uint8_t>(version_ihl >> 4);
    }
    uint8_t ihl() const
    {
        return static_cast<uint8_t>(version_ihl & 0x0f);
    }
    size_t header_len() const
    {
        return static_cast<size_t>(ihl()) * 4;
    }
};

struct ipv6_header
{
    uint32_t vtc_flow;    // version(4) | traffic class(8) | flow label(20)
    uint16_t payload_len; // 不含 IPv6 头部的载荷长度
    uint8_t next_header;  // 上层协议号
    uint8_t hop_limit;
    uint8_t src_ip[16]; // 网络字节序
    uint8_t dst_ip[16]; // 网络字节序
};

struct tcp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;

    size_t header_len() const
    {
        return static_cast<size_t>(data_offset >> 4) * 4;
    }
};

struct udp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

// ---- 校验和工具（RFC 1071 反码和）----
#if defined(__SSE2__)
// SSE2 向量化：每 32 字节展开为 8 路 32 位累加器（16 位字按网络序解释），
// 避免标量实现的逐字进位链；无 SIMD 平台回退到下方标量版本。
inline uint32_t checksum_sum(const uint8_t *data, size_t len, uint32_t sum = 0)
{
    __m128i acc0 = _mm_setzero_si128();
    __m128i acc1 = _mm_setzero_si128();
    const __m128i mask = _mm_set1_epi16(0x00ff);
    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        const __m128i v0 =
            _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + i));
        const __m128i v1 =
            _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + i + 16));
        const __m128i w0 = _mm_or_si128(
            _mm_slli_epi16(_mm_and_si128(v0, mask), 8), _mm_srli_epi16(v0, 8));
        const __m128i w1 = _mm_or_si128(
            _mm_slli_epi16(_mm_and_si128(v1, mask), 8), _mm_srli_epi16(v1, 8));
        acc0 = _mm_add_epi32(acc0, _mm_unpacklo_epi16(w0, _mm_setzero_si128()));
        acc1 = _mm_add_epi32(acc1, _mm_unpackhi_epi16(w0, _mm_setzero_si128()));
        acc0 = _mm_add_epi32(acc0, _mm_unpacklo_epi16(w1, _mm_setzero_si128()));
        acc1 = _mm_add_epi32(acc1, _mm_unpackhi_epi16(w1, _mm_setzero_si128()));
    }
    uint32_t t[8];
    _mm_storeu_si128(reinterpret_cast<__m128i *>(t), acc0);
    _mm_storeu_si128(reinterpret_cast<__m128i *>(t + 4), acc1);
    sum += t[0] + t[1] + t[2] + t[3] + t[4] + t[5] + t[6] + t[7];
    for (; i + 1 < len; i += 2) {
        sum += static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += static_cast<uint16_t>(data[i] << 8);
    }
    return sum;
}

#else

inline uint32_t checksum_sum(const uint8_t *data, size_t len, uint32_t sum = 0)
{
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += static_cast<uint16_t>(data[i] << 8);
    }
    return sum;
}

#endif

inline uint16_t checksum_fold(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// 对 data[0, len) 计算反码和校验
inline uint16_t ip_checksum(const uint8_t *data, size_t len)
{
    return checksum_fold(checksum_sum(data, len));
}

// IPv4 头部校验和（自动跳过 checksum 字段本身）
inline uint16_t ipv4_checksum(const uint8_t *ip, size_t hlen)
{
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
inline uint16_t verify_ipv4_checksum(const uint8_t *ip, size_t hlen)
{
    return checksum_fold(checksum_sum(ip, hlen));
}

// TCP/UDP/ICMPv6 伪头部校验和（family: 4 或 6，地址均为网络字节序）
inline uint16_t tcp_udp_checksum(int family, const uint8_t *src_ip,
    const uint8_t *dst_ip, uint8_t protocol, const uint8_t *segment,
    size_t seg_len)
{
    uint32_t sum = 0;
    const size_t addr_len = family == 6 ? 16 : 4;
    for (size_t i = 0; i + 1 < addr_len; i += 2) {
        sum += static_cast<uint16_t>((src_ip[i] << 8) | src_ip[i + 1]);
    }
    for (size_t i = 0; i + 1 < addr_len; i += 2) {
        sum += static_cast<uint16_t>((dst_ip[i] << 8) | dst_ip[i + 1]);
    }
    sum += static_cast<uint16_t>(protocol);
    sum += static_cast<uint16_t>(seg_len);
    sum += checksum_sum(segment, seg_len);
    return checksum_fold(sum);
}

// TCP/UDP 伪头部校验和（IPv4 便捷重载，参数为网络字节序地址）
inline uint16_t tcp_udp_checksum(uint32_t src_ip, uint32_t dst_ip,
    uint8_t protocol, const uint8_t *segment, size_t seg_len)
{
    // 地址按网络字节序存储：直接按内存字节拆成 16 位字，避免主机字节序干扰
    const uint8_t *s = reinterpret_cast<const uint8_t *>(&src_ip);
    const uint8_t *d = reinterpret_cast<const uint8_t *>(&dst_ip);
    return tcp_udp_checksum(4, s, d, protocol, segment, seg_len);
}

// IP 头部长度（IPv4 20 字节 / IPv6 40 字节）
inline size_t ip_header_size(int family) noexcept
{
    return family == 6 ? 40 : 20;
}

// 构建 IP 头部（IPv4 自动计算头部校验和，IPv6 无校验和字段）；
// buf 需至少容纳 ip_header_size(family) 字节，返回头部长度。
inline size_t build_ip_header(uint8_t *buf, int family, const uint8_t *src_ip,
    const uint8_t *dst_ip, uint8_t protocol, size_t total_len,
    uint16_t ip_id)
{
    if (family == 4) {
        auto *ip = reinterpret_cast<ipv4_header *>(buf);
        ip->version_ihl = 0x45;
        ip->tos = 0;
        ip->total_len = htons(static_cast<uint16_t>(total_len));
        ip->id = htons(ip_id);
        ip->frag_off = htons(0x4000); // DF
        ip->ttl = 64;
        ip->protocol = protocol;
        ip->checksum = 0;
        std::memcpy(&ip->src_ip, src_ip, 4);
        std::memcpy(&ip->dst_ip, dst_ip, 4);
        ip->checksum = htons(ipv4_checksum(buf, 20));
        return 20;
    }
    auto *ip = reinterpret_cast<ipv6_header *>(buf);
    ip->vtc_flow = htonl(0x60000000u);
    ip->payload_len = htons(static_cast<uint16_t>(total_len - 40));
    ip->next_header = protocol;
    ip->hop_limit = 64;
    std::memcpy(ip->src_ip, src_ip, 16);
    std::memcpy(ip->dst_ip, dst_ip, 16);
    return 40;
}

// 从 TUN 设备读取/向 TUN 设备写入的一个完整 IP 报文。
//
// 读路径（async_read_ip）：设备将报文直接读入内部 packet_buffer 后立即做
// 结构解析，暴露 IP 层与传输层（TCP/UDP/ICMP/ICMPv6）的类型化视图，载荷
// 以零拷贝指针形式访问。解析只做结构校验（不验证校验和），分片包解析并
// 暴露字段（是否丢弃由调用方决定）；IPv6 扩展头不遍历，next_header 为扩展
// 头号时传输层视图为空、ip_protocol() 返回原始号。解析失败不抛出异常，
// 通过 valid()/error() 查询。
//
// 写路径（async_write_ip）：支持原始写出（buffer() 中已有字节）与字段构造
// （begin_* -> append_payload -> finalize()），finalize() 自动回填长度并计算
// IP/TCP/UDP/ICMP 校验和（含伪头部）。
class ip_packet
{
public:
    // 解析失败原因
    enum class parse_error : uint8_t
    {
        none = 0,
        invalid_version,          // 版本既不是 4 也不是 6
        packet_too_short,         // 数据不足最小头部
        buffer_too_small,         // 内部缓冲不足以容纳报文
        invalid_ip_header_length, // IPv4 IHL < 20 或超过报文长度
        invalid_total_length,     // total_len 小于头部长度或超过实际数据
        invalid_transport_header  // TCP/UDP/ICMP 头部结构非法
    };

    explicit ip_packet(size_t capacity = 2048, size_t headroom = 128)
        : buf_(capacity, headroom)
    {
    }

    // 复位缓冲与解析状态，可复用对象进行下一次读取/构造
    void reset() noexcept
    {
        buf_.reset();
        parse_error_ = parse_error::none;
        version_ = 0;
        protocol_ = 0;
        std::memset(src_ip_, 0, sizeof(src_ip_));
        std::memset(dst_ip_, 0, sizeof(dst_ip_));
        total_len_ = 0;
        fragmented_ = false;
        frag_offset_ = 0;
        std::memset(&v4_, 0, sizeof(v4_));
        std::memset(&v6_, 0, sizeof(v6_));
        std::memset(&tcp_, 0, sizeof(tcp_));
        std::memset(&udp_, 0, sizeof(udp_));
        icmp_type_ = 0;
        icmp_code_ = 0;
        icmp_checksum_ = 0;
        icmp_echo_id_ = 0;
        icmp_echo_seq_ = 0;
        payload_ = nullptr;
        payload_len_ = 0;
        transport_parsed_ = false;
        bld_ = builder_state{};
    }

    // ---- 解析（读路径）----

    // 解析外部缓冲区中的报文（拷贝进内部缓冲）；src 允许为自身 buffer()
    void parse(const packet_buffer &src, size_t len)
    {
        buf_.reset();
        if (len > buf_.writable_size()) {
            parse_error_ = parse_error::buffer_too_small;
            return;
        }
        std::memmove(buf_.data(), src.data(), len); // src 可能即 buf_ 自身
        buf_.commit(len);
        do_parse(buf_.data(), len);
    }

    // 解析裸字节报文（拷贝进内部缓冲）
    void parse(const uint8_t *data, size_t len)
    {
        buf_.reset();
        if (len > buf_.writable_size()) {
            parse_error_ = parse_error::buffer_too_small;
            return;
        }
        std::memcpy(buf_.data(), data, len);
        buf_.commit(len);
        do_parse(buf_.data(), len);
    }

    bool valid() const noexcept
    {
        return parse_error_ == parse_error::none;
    }
    parse_error error() const noexcept
    {
        return parse_error_;
    }
    static const char *error_message(parse_error e) noexcept
    {
        switch (e) {
        case parse_error::none:
            return "no error";
        case parse_error::invalid_version:
            return "invalid IP version";
        case parse_error::packet_too_short:
            return "packet too short";
        case parse_error::buffer_too_small:
            return "buffer too small";
        case parse_error::invalid_ip_header_length:
            return "invalid IP header length";
        case parse_error::invalid_total_length:
            return "invalid total length";
        case parse_error::invalid_transport_header:
            return "invalid transport header";
        }
        return "unknown error";
    }

    // ---- IP 层 ----

    // 4 / 6 / 0（解析失败时为 0）
    uint8_t version() const noexcept
    {
        return version_;
    }
    // 原始协议号（如 ip_protocol_tcp / ip_protocol_udp / ip_protocol_icmp /
    // ip_protocol_icmpv6，未知协议或 IPv6 扩展头号原样返回）
    uint8_t ip_protocol() const noexcept
    {
        return protocol_;
    }
    // 整个 IP 报文长度（IPv6 为 40 + payload_len）
    size_t total_length() const noexcept
    {
        return total_len_;
    }
    // 是否为分片报文（带分片偏移或 MF 标志）
    bool fragmented() const noexcept
    {
        return fragmented_;
    }
    // 分片偏移（字节，IPv4 首片/未分片为 0）
    uint16_t fragment_offset() const noexcept
    {
        return frag_offset_;
    }
    net::ip::address source_address() const
    {
        if (version_ == 4) {
            return net::ip::address_v4(
                std::array<uint8_t, 4>{src_ip_[0], src_ip_[1], src_ip_[2],
                    src_ip_[3]});
        }
        if (version_ == 6) {
            std::array<uint8_t, 16> b{};
            std::memcpy(b.data(), src_ip_, 16);
            return net::ip::address_v6(b);
        }
        return net::ip::address();
    }
    net::ip::address destination_address() const
    {
        if (version_ == 4) {
            return net::ip::address_v4(
                std::array<uint8_t, 4>{dst_ip_[0], dst_ip_[1], dst_ip_[2],
                    dst_ip_[3]});
        }
        if (version_ == 6) {
            std::array<uint8_t, 16> b{};
            std::memcpy(b.data(), dst_ip_, 16);
            return net::ip::address_v6(b);
        }
        return net::ip::address();
    }
    // 网络字节序地址字节（IPv4 仅前 4 字节有效），零拷贝热路径
    const uint8_t *source_ip_bytes() const noexcept
    {
        return src_ip_;
    }
    const uint8_t *destination_ip_bytes() const noexcept
    {
        return dst_ip_;
    }
    // 原始头部视图（版本不匹配时为 nullptr）
    const ipv4_header *ipv4() const noexcept
    {
        return version_ == 4 ? &v4_ : nullptr;
    }
    const ipv6_header *ipv6() const noexcept
    {
        return version_ == 6 ? &v6_ : nullptr;
    }

    // ---- 传输层 ----

    bool is_tcp() const noexcept
    {
        return protocol_ == ip_protocol_tcp;
    }
    bool is_udp() const noexcept
    {
        return protocol_ == ip_protocol_udp;
    }
    bool is_icmp() const noexcept
    {
        return protocol_ == ip_protocol_icmp;
    }
    bool is_icmpv6() const noexcept
    {
        return protocol_ == ip_protocol_icmpv6;
    }
    // 主机字节序端口（非 TCP/UDP 或传输层未解析时为 0）
    uint16_t source_port() const noexcept
    {
        if (is_tcp() && transport_parsed_) {
            return ntohs(tcp_.src_port);
        }
        if (is_udp() && transport_parsed_) {
            return ntohs(udp_.src_port);
        }
        return 0;
    }
    uint16_t destination_port() const noexcept
    {
        if (is_tcp() && transport_parsed_) {
            return ntohs(tcp_.dst_port);
        }
        if (is_udp() && transport_parsed_) {
            return ntohs(udp_.dst_port);
        }
        return 0;
    }
    // 类型化传输层头部（协议不匹配、解析失败或分片非首片时为 nullptr）
    const tcp_header *tcp() const noexcept
    {
        return is_tcp() && transport_parsed_ ? &tcp_ : nullptr;
    }
    const udp_header *udp() const noexcept
    {
        return is_udp() && transport_parsed_ ? &udp_ : nullptr;
    }
    uint8_t icmp_type() const noexcept
    {
        return icmp_type_;
    }
    uint8_t icmp_code() const noexcept
    {
        return icmp_code_;
    }
    uint16_t icmp_checksum() const noexcept
    {
        return icmp_checksum_;
    }
    // Echo 类报文（v4 type 8/0，v6 type 128/129）的 id/seq，其余为 0
    uint16_t icmp_echo_id() const noexcept
    {
        return icmp_echo_id_;
    }
    uint16_t icmp_echo_seq() const noexcept
    {
        return icmp_echo_seq_;
    }

    // ---- 载荷 ----

    // 传输层报文段（IP 头之后的全部字节，含 TCP/UDP/ICMP 头部），指向内部
    // 缓冲，零拷贝；分片非首片为分片内容。仅在 valid() 时可靠。
    const uint8_t *payload() const noexcept
    {
        return payload_;
    }
    size_t payload_size() const noexcept
    {
        return payload_len_;
    }
    // 纯应用数据（传输层头部之后）；传输层未解析（未知协议或分片非首片）
    // 时与 payload() 相同（此时无传输层视图可裁剪）。
    const uint8_t *transport_data() const noexcept
    {
        if (payload_ == nullptr) {
            return nullptr;
        }
        if (is_tcp() && transport_parsed_) {
            return payload_ + tcp_.header_len();
        }
        if (is_udp() && transport_parsed_) {
            return payload_ + sizeof(udp_header);
        }
        if ((is_icmp() || is_icmpv6()) && transport_parsed_) {
            return payload_ + 8;
        }
        return payload_;
    }
    size_t transport_data_size() const noexcept
    {
        if (payload_ == nullptr) {
            return 0;
        }
        if (is_tcp() && transport_parsed_) {
            return payload_len_ > tcp_.header_len()
                ? payload_len_ - tcp_.header_len()
                : 0;
        }
        if (is_udp() && transport_parsed_) {
            return payload_len_ > sizeof(udp_header)
                ? payload_len_ - sizeof(udp_header)
                : 0;
        }
        if ((is_icmp() || is_icmpv6()) && transport_parsed_) {
            return payload_len_ > 8 ? payload_len_ - 8 : 0;
        }
        return payload_len_;
    }

    // ---- 写路径（字段构造）----

    // 以下 begin_* 系列必须按 begin_ipv4/begin_ipv6 -> begin_tcp/udp/icmp ->
    // [append_payload] -> finalize() 的顺序使用；每个报文构造前自动复位缓冲。

    void begin_ipv4(const net::ip::address_v4 &src,
        const net::ip::address_v4 &dst, uint8_t ttl = 64)
    {
        builder_begin(4);
        const auto s = src.to_bytes();
        const auto d = dst.to_bytes();
        std::memcpy(bld_.src, s.data(), 4);
        std::memcpy(bld_.dst, d.data(), 4);
        bld_.ttl_hop = ttl;
    }

    void begin_ipv6(const net::ip::address_v6 &src,
        const net::ip::address_v6 &dst, uint8_t hop_limit = 64)
    {
        builder_begin(6);
        const auto s = src.to_bytes();
        const auto d = dst.to_bytes();
        std::memcpy(bld_.src, s.data(), 16);
        std::memcpy(bld_.dst, d.data(), 16);
        bld_.ttl_hop = hop_limit;
    }

    // options/options_len 为可选的 TCP 选项区（MSS 等），长度须为 4 的倍数且
    // 不超过 40 字节；不传表示无选项（data offset 20）。
    void begin_tcp(uint16_t src_port, uint16_t dst_port, uint32_t seq,
        uint32_t ack, uint8_t flags, uint16_t window,
        const void *options = nullptr, size_t options_len = 0)
    {
        if (bld_.version == 0) {
            throw std::logic_error(
                "ip_packet::begin_tcp: begin_ipv4/begin_ipv6 must be called first");
        }
        if (options_len % 4 != 0 || options_len > 40) {
            throw std::invalid_argument(
                "ip_packet::begin_tcp: options_len must be a multiple of 4 and <= 40");
        }
        bld_.protocol = ip_protocol_tcp;
        bld_.sport = src_port;
        bld_.dport = dst_port;
        bld_.seq = seq;
        bld_.ack = ack;
        bld_.flags = flags;
        bld_.window = window;
        bld_.transport_hlen = sizeof(tcp_header) + options_len;
        if (options_len != 0) {
            std::memcpy(bld_.tcp_options, options, options_len);
        }
        bld_.tcp_options_len = options_len;
        reserve_transport();
    }

    void begin_udp(uint16_t src_port, uint16_t dst_port)
    {
        if (bld_.version == 0) {
            throw std::logic_error(
                "ip_packet::begin_udp: begin_ipv4/begin_ipv6 must be called first");
        }
        bld_.protocol = ip_protocol_udp;
        bld_.sport = src_port;
        bld_.dport = dst_port;
        bld_.transport_hlen = sizeof(udp_header);
        reserve_transport();
    }

    // type/code 为 ICMP 头部字段；Echo 类报文（v4 8/0，v6 128/129）需再调用
    // set_icmp_echo() 设置 id/seq。
    void begin_icmp(uint8_t type, uint8_t code)
    {
        if (bld_.version == 0) {
            throw std::logic_error(
                "ip_packet::begin_icmp: begin_ipv4/begin_ipv6 must be called first");
        }
        bld_.protocol =
            bld_.version == 4 ? ip_protocol_icmp : ip_protocol_icmpv6;
        bld_.icmp_type = type;
        bld_.icmp_code = code;
        bld_.icmp_echo_set = false;
        bld_.transport_hlen = 8;
        reserve_transport();
    }

    // 仅用于 Echo 类 ICMP/ICMPv6 报文
    void set_icmp_echo(uint16_t id, uint16_t seq)
    {
        bld_.icmp_id = id;
        bld_.icmp_seq = seq;
        bld_.icmp_echo_set = true;
    }

    // 追加传输层载荷（可多次调用）
    void append_payload(const void *data, size_t len)
    {
        if (bld_.version == 0) {
            throw std::logic_error(
                "ip_packet::append_payload: begin_ipv4/begin_ipv6 must be called first");
        }
        if (buf_.writable_size() < len) {
            throw std::length_error(
                "ip_packet: payload exceeds buffer capacity");
        }
        if (len != 0) {
            std::memcpy(buf_.writable_data(), data, len);
            buf_.commit(len);
        }
    }

    // 回填 IP/传输层长度与全部校验和；完成后即可通过访问器读取各字段
    //（内部会对自身做一次解析以同步视图）。
    void finalize()
    {
        if (bld_.version == 0) {
            return;
        }
        const size_t payload_len =
            buf_.size() - bld_.ip_hlen - bld_.transport_hlen;
        const size_t total = bld_.ip_hlen + bld_.transport_hlen + payload_len;
        uint8_t *out = buf_.data();
        const int family = bld_.version == 4 ? 4 : 6;
        if (family == 4) {
            build_ip_header(out, 4, bld_.src, bld_.dst, bld_.protocol, total,
                bld_.ip_id);
            out[8] = bld_.ttl_hop;
        } else {
            build_ip_header(out, 6, bld_.src, bld_.dst, bld_.protocol, total,
                0);
            out[7] = bld_.ttl_hop;
        }
        uint8_t *seg = out + bld_.ip_hlen;
        const size_t seg_len = bld_.transport_hlen + payload_len;
        switch (bld_.protocol) {
        case ip_protocol_tcp: {
            tcp_header th{};
            th.src_port = htons(bld_.sport);
            th.dst_port = htons(bld_.dport);
            th.seq = htonl(bld_.seq);
            th.ack = htonl(bld_.ack);
            th.data_offset =
                static_cast<uint8_t>((bld_.transport_hlen / 4) << 4);
            th.flags = bld_.flags;
            th.window = htons(bld_.window);
            std::memcpy(seg, &th, sizeof(th));
            if (bld_.tcp_options_len != 0) {
                std::memcpy(seg + sizeof(th), bld_.tcp_options,
                    bld_.tcp_options_len);
            }
            const uint16_t csum = tcp_udp_checksum(
                family, bld_.src, bld_.dst, ip_protocol_tcp, seg, seg_len);
            seg[16] = static_cast<uint8_t>(csum >> 8);
            seg[17] = static_cast<uint8_t>(csum & 0xff);
            break;
        }
        case ip_protocol_udp: {
            udp_header uh{};
            uh.src_port = htons(bld_.sport);
            uh.dst_port = htons(bld_.dport);
            uh.length = htons(static_cast<uint16_t>(seg_len));
            std::memcpy(seg, &uh, sizeof(uh));
            const uint16_t csum = tcp_udp_checksum(
                family, bld_.src, bld_.dst, ip_protocol_udp, seg, seg_len);
            seg[6] = static_cast<uint8_t>(csum >> 8);
            seg[7] = static_cast<uint8_t>(csum & 0xff);
            break;
        }
        case ip_protocol_icmp:
        case ip_protocol_icmpv6: {
            seg[0] = bld_.icmp_type;
            seg[1] = bld_.icmp_code;
            seg[2] = 0;
            seg[3] = 0;
            if (bld_.icmp_echo_set) {
                seg[4] = static_cast<uint8_t>(bld_.icmp_id >> 8);
                seg[5] = static_cast<uint8_t>(bld_.icmp_id & 0xff);
                seg[6] = static_cast<uint8_t>(bld_.icmp_seq >> 8);
                seg[7] = static_cast<uint8_t>(bld_.icmp_seq & 0xff);
            }
            uint16_t csum;
            if (family == 4) {
                csum = ip_checksum(seg, seg_len);
            } else {
                csum = tcp_udp_checksum(6, bld_.src, bld_.dst,
                    ip_protocol_icmpv6, seg, seg_len);
            }
            seg[2] = static_cast<uint8_t>(csum >> 8);
            seg[3] = static_cast<uint8_t>(csum & 0xff);
            break;
        }
        default:
            break;
        }
        // 同步解析视图，使 finalize() 后访问器立即可用
        parse(buf_, buf_.size());
    }

    // 设置 IPv4 Identification 字段（v4 构造时可选，默认 0）
    void set_ip_id(uint16_t id) noexcept
    {
        bld_.ip_id = id;
    }

    // 底层缓冲：读路径设备直接读入其中；原始写路径 async_write_ip 写出其内容
    packet_buffer &buffer() noexcept
    {
        return buf_;
    }
    const packet_buffer &buffer() const noexcept
    {
        return buf_;
    }

private:
    void builder_begin(uint8_t version)
    {
        buf_.reset();
        bld_ = builder_state{};
        bld_.version = version;
        bld_.ip_hlen = version == 4 ? sizeof(ipv4_header) : sizeof(ipv6_header);
        // 预留 IP 头部空间（finalize 时回填）
        std::memset(buf_.data(), 0, bld_.ip_hlen);
        buf_.commit(bld_.ip_hlen);
    }

    void reserve_transport()
    {
        // 预留传输层头部空间（finalize 时回填）
        std::memset(buf_.writable_data(), 0, bld_.transport_hlen);
        buf_.commit(bld_.transport_hlen);
    }

    void parse_transport(uint8_t protocol, const uint8_t *seg, size_t seg_len)
    {
        transport_parsed_ = false;
        switch (protocol) {
        case ip_protocol_tcp:
            if (seg_len < sizeof(tcp_header)) {
                parse_error_ = parse_error::invalid_transport_header;
                return;
            }
            std::memcpy(&tcp_, seg, sizeof(tcp_header));
            {
                const size_t hlen = tcp_.header_len();
                if (hlen < sizeof(tcp_header) || hlen > seg_len) {
                    parse_error_ = parse_error::invalid_transport_header;
                    return;
                }
            }
            transport_parsed_ = true;
            break;
        case ip_protocol_udp:
            if (seg_len < sizeof(udp_header)) {
                parse_error_ = parse_error::invalid_transport_header;
                return;
            }
            std::memcpy(&udp_, seg, sizeof(udp_header));
            {
                const size_t ulen = ntohs(udp_.length);
                if (ulen < sizeof(udp_header) || ulen > seg_len) {
                    parse_error_ = parse_error::invalid_transport_header;
                    return;
                }
            }
            transport_parsed_ = true;
            break;
        case ip_protocol_icmp:
        case ip_protocol_icmpv6:
            if (seg_len < 8) {
                parse_error_ = parse_error::invalid_transport_header;
                return;
            }
            icmp_type_ = seg[0];
            icmp_code_ = seg[1];
            icmp_checksum_ =
                static_cast<uint16_t>((seg[2] << 8) | seg[3]);
            {
                const bool echo =
                    (protocol == ip_protocol_icmp &&
                        (icmp_type_ == 8 || icmp_type_ == 0)) ||
                    (protocol == ip_protocol_icmpv6 &&
                        (icmp_type_ == 128 || icmp_type_ == 129));
                if (echo) {
                    icmp_echo_id_ =
                        static_cast<uint16_t>((seg[4] << 8) | seg[5]);
                    icmp_echo_seq_ =
                        static_cast<uint16_t>((seg[6] << 8) | seg[7]);
                }
            }
            transport_parsed_ = true;
            break;
        default:
            // 未知协议：无类型化视图，载荷仍可访问
            break;
        }
    }

    void do_parse(const uint8_t *data, size_t len)
    {
        parse_error_ = parse_error::none;
        version_ = 0;
        protocol_ = 0;
        std::memset(src_ip_, 0, sizeof(src_ip_));
        std::memset(dst_ip_, 0, sizeof(dst_ip_));
        total_len_ = 0;
        fragmented_ = false;
        frag_offset_ = 0;
        std::memset(&v4_, 0, sizeof(v4_));
        std::memset(&v6_, 0, sizeof(v6_));
        std::memset(&tcp_, 0, sizeof(tcp_));
        std::memset(&udp_, 0, sizeof(udp_));
        icmp_type_ = 0;
        icmp_code_ = 0;
        icmp_checksum_ = 0;
        icmp_echo_id_ = 0;
        icmp_echo_seq_ = 0;
        payload_ = nullptr;
        payload_len_ = 0;
        transport_parsed_ = false;

        if (len < 20) {
            parse_error_ = parse_error::packet_too_short;
            return;
        }
        const uint8_t version = static_cast<uint8_t>(data[0] >> 4);
        if (version == 4) {
            if (len < sizeof(ipv4_header)) {
                parse_error_ = parse_error::packet_too_short;
                return;
            }
            std::memcpy(&v4_, data, sizeof(ipv4_header));
            const size_t ihl = v4_.header_len();
            if (ihl < sizeof(ipv4_header) || ihl > len) {
                parse_error_ = parse_error::invalid_ip_header_length;
                return;
            }
            const size_t total = ntohs(v4_.total_len);
            if (total < ihl || total > len) {
                parse_error_ = parse_error::invalid_total_length;
                return;
            }
            version_ = 4;
            protocol_ = v4_.protocol;
            std::memcpy(src_ip_, data + 12, 4);
            std::memcpy(dst_ip_, data + 16, 4);
            total_len_ = total;
            const uint16_t frag = ntohs(v4_.frag_off);
            fragmented_ = (frag & 0x3fff) != 0;
            frag_offset_ = static_cast<uint16_t>((frag & 0x1fff) * 8);
            payload_ = data + ihl;
            payload_len_ = total - ihl;
            // 分片非首片（偏移 > 0）的载荷从流中间开始，不解析传输层
            if (frag_offset_ == 0) {
                parse_transport(protocol_, payload_, payload_len_);
            }
        } else if (version == 6) {
            if (len < sizeof(ipv6_header)) {
                parse_error_ = parse_error::packet_too_short;
                return;
            }
            std::memcpy(&v6_, data, sizeof(ipv6_header));
            const size_t plen = ntohs(v6_.payload_len);
            if (sizeof(ipv6_header) + plen > len) {
                parse_error_ = parse_error::invalid_total_length;
                return;
            }
            version_ = 6;
            protocol_ = v6_.next_header;
            std::memcpy(src_ip_, v6_.src_ip, 16);
            std::memcpy(dst_ip_, v6_.dst_ip, 16);
            total_len_ = sizeof(ipv6_header) + plen;
            payload_ = data + sizeof(ipv6_header);
            payload_len_ = plen;
            parse_transport(protocol_, payload_, payload_len_);
        } else {
            parse_error_ = parse_error::invalid_version;
        }
    }

    packet_buffer buf_;
    parse_error parse_error_ = parse_error::none;
    uint8_t version_ = 0;
    uint8_t protocol_ = 0;
    uint8_t src_ip_[16] = {};
    uint8_t dst_ip_[16] = {};
    size_t total_len_ = 0;
    bool fragmented_ = false;
    uint16_t frag_offset_ = 0;
    ipv4_header v4_{};
    ipv6_header v6_{};
    tcp_header tcp_{};
    udp_header udp_{};
    uint8_t icmp_type_ = 0;
    uint8_t icmp_code_ = 0;
    uint16_t icmp_checksum_ = 0;
    uint16_t icmp_echo_id_ = 0;
    uint16_t icmp_echo_seq_ = 0;
    const uint8_t *payload_ = nullptr;
    size_t payload_len_ = 0;
    // 传输层头部是否已成功解析（协议号匹配但解析失败/分片非首片时为 false）
    bool transport_parsed_ = false;

    struct builder_state
    {
        uint8_t version = 0;
        uint8_t protocol = 0;
        uint8_t src[16] = {};
        uint8_t dst[16] = {};
        uint8_t ttl_hop = 64;
        uint16_t ip_id = 0;
        uint16_t sport = 0;
        uint16_t dport = 0;
        uint32_t seq = 0;
        uint32_t ack = 0;
        uint8_t flags = 0;
        uint16_t window = 0;
        uint8_t tcp_options[40] = {};
        size_t tcp_options_len = 0;
        uint8_t icmp_type = 0;
        uint8_t icmp_code = 0;
        uint16_t icmp_id = 0;
        uint16_t icmp_seq = 0;
        bool icmp_echo_set = false;
        size_t ip_hlen = 0;
        size_t transport_hlen = 0;
    } bld_{};
};

} // namespace tunio
