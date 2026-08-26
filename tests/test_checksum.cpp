#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

#include "tun_engine/tun_config.hpp"
#include "test_harness.hpp"
#include "../src/ip_headers.hpp"

// 验证引擎校验和实现与独立实现一致
int main() {
    using tun_engine::detail::ip_checksum;
    using tun_engine::detail::ipv4_checksum;
    using tun_engine::detail::verify_ipv4_checksum;
    using tun_engine::detail::tcp_udp_checksum;

    // IP 头（checksum 字段由 ipv4_checksum 自动跳过）
    const uint32_t src = test::ip("10.0.0.2");
    const uint32_t dst = test::ip("8.8.8.8");
    std::vector<uint8_t> pkt = test::make_tcp(src, dst, 12345, 80, 0x10, 100, 200, 65535, {'a', 'b', 'c'});

    // 生成器：ipv4_checksum 应等于报文中的校验和字段
    uint16_t stored = static_cast<uint16_t>((pkt[10] << 8) | pkt[11]);
    assert(ipv4_checksum(pkt.data(), 20) == stored);

    // 验证器：合法头部校验和为 0
    assert(verify_ipv4_checksum(pkt.data(), 20) == 0);

    // 损坏校验和
    std::vector<uint8_t> bad = pkt;
    bad[10] ^= 0xff;
    assert(verify_ipv4_checksum(bad.data(), 20) != 0);

    // TCP 校验
    const uint8_t* seg = pkt.data() + 20;
    const size_t seg_len = pkt.size() - 20;
    const uint32_t snet = htonl(src);
    const uint32_t dnet = htonl(dst);
    uint16_t tcp_csum = tcp_udp_checksum(snet, dnet, 6, seg, seg_len);
    assert(tcp_csum == 0);

    // 独立计算参考值
    uint32_t pseudo = (snet >> 16) + (snet & 0xffff) + (dnet >> 16) + (dnet & 0xffff) + 6 + seg_len;
    uint16_t ref = test::csum16(seg, seg_len, pseudo);
    assert(ref == 0);

    // UDP 校验
    std::vector<uint8_t> udp = test::make_udp(src, dst, 53000, 53, {1, 2, 3, 4});
    const uint8_t* useg = udp.data() + 20;
    const size_t ulen = udp.size() - 20;
    assert(tcp_udp_checksum(snet, dnet, 17, useg, ulen) == 0);

    // 单字节边界（奇数长度）
    uint8_t odd[] = {0x01, 0x02, 0x03};
    uint16_t c1 = test::csum16(odd, sizeof(odd));
    uint16_t c2 = ip_checksum(odd, sizeof(odd));
    assert(c1 == c2);

    return 0;
}
