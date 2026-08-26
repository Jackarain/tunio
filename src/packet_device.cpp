//
// packet_device.cpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "tunio/packet_device.hpp"

#include <algorithm>

namespace tunio {

#if defined(BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR)

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>

#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

namespace detail {

bool posix_packet_device_impl::open(const device_config& cfg, boost::system::error_code& ec) {
#if defined(__linux__)
    const int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, cfg.name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        ::close(fd);
        return false;
    }

    // 配置 IP / 掩码（需要 CAP_NET_ADMIN）
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        ::close(fd);
        return false;
    }

    auto set_ifr = [&](int cmd, const char* addr) -> bool {
        struct ifreq aifr;
        std::memset(&aifr, 0, sizeof(aifr));
        std::strncpy(aifr.ifr_name, cfg.name.c_str(), IFNAMSIZ - 1);
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&aifr.ifr_addr);
        sin->sin_family = AF_INET;
        if (::inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
            return false;
        }
        return ::ioctl(s, cmd, &aifr) == 0;
    };

    if (!set_ifr(SIOCSIFADDR, cfg.ipv4.c_str())) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        ::close(s);
        ::close(fd);
        return false;
    }
    if (!set_ifr(SIOCSIFNETMASK, cfg.netmask.c_str())) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        ::close(s);
        ::close(fd);
        return false;
    }

    // 设置 MTU 并启用接口
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, cfg.name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_mtu = static_cast<int>(std::max<size_t>(cfg.mtu, 576));
    if (::ioctl(s, SIOCSIFMTU, &ifr) < 0) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        ::close(s);
        ::close(fd);
        return false;
    }
    if (::ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        ::close(s);
        ::close(fd);
        return false;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (::ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        ::close(s);
        ::close(fd);
        return false;
    }
    ::close(s);

    desc_.assign(fd, ec);
    if (!ec) {
        open_ = true;
        mtu_ = static_cast<size_t>(ifr.ifr_mtu);
    }
    return !ec;
#else
    // macOS utun / 其他 POSIX 平台的自主打开尚未实现（Phase 3），
    // 句柄注入模式 assign() 在所有平台可用。
    (void)cfg;
    ec = boost::system::error_code(boost::system::errc::operation_not_supported,
                                   boost::system::generic_category());
    return false;
#endif
}

} // namespace detail
#endif // BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR

#if defined(BOOST_ASIO_HAS_WINDOWS_OVERLAPPED_PTR)

namespace detail {

bool windows_packet_device_impl::open(const device_config&, boost::system::error_code& ec) {
    // Wintun 会话创建（Phase 3），句柄注入模式 assign() 已可用。
    ec = boost::system::error_code(boost::system::errc::operation_not_supported,
                                   boost::system::generic_category());
    return false;
}

} // namespace detail
#endif // BOOST_ASIO_HAS_WINDOWS_OVERLAPPED_PTR

} // namespace tunio
