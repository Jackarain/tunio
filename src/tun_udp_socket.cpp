#include "tunio/tun_udp_socket.hpp"

#include <utility>

#include "tunio/detail/tun_udp_ops.hpp"
#include "udp_engine.hpp"

namespace tunio {

tun_udp_socket::tun_udp_socket(executor_type ex) : ex_(std::move(ex)) {}

tun_udp_socket::~tun_udp_socket() {
    close();
}

tun_udp_socket::tun_udp_socket(tun_udp_socket&&) noexcept = default;

tun_udp_socket& tun_udp_socket::operator=(tun_udp_socket&& other) noexcept {
    if (this != &other) {
        close();
        session_ = std::move(other.session_);
        ex_ = std::move(other.ex_);
    }
    return *this;
}

tun_udp_socket::executor_type tun_udp_socket::get_executor() const noexcept {
    return ex_;
}

five_tuple tun_udp_socket::remote_key() const {
    if (!session_) {
        return five_tuple{};
    }
    return session_->key;
}

void tun_udp_socket::set_timeout(std::chrono::seconds timeout) {
    if (session_) {
        detail::udp_session_set_timeout(session_, timeout);
    }
}

void tun_udp_socket::close() {
    if (session_) {
        detail::udp_session_close(session_);
    }
}

bool tun_udp_socket::is_open() const noexcept {
    return detail::udp_session_is_open(session_);
}

} // namespace tunio
