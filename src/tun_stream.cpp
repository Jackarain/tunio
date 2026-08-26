#include "tun_engine/tun_stream.hpp"

#include <utility>

#include "tcp_engine.hpp"
#include "tun_engine/detail/tun_stream_ops.hpp"

namespace tun_engine {

tun_stream::tun_stream(executor_type ex) : ex_(std::move(ex)) {}

tun_stream::~tun_stream() {
    close();
}

tun_stream::tun_stream(tun_stream&&) noexcept = default;

tun_stream& tun_stream::operator=(tun_stream&& other) noexcept {
    if (this != &other) {
        close();
        flow_ = std::move(other.flow_);
        ex_ = std::move(other.ex_);
    }
    return *this;
}

tun_stream::executor_type tun_stream::get_executor() const noexcept {
    return ex_;
}

boost::asio::ip::tcp::endpoint tun_stream::original_destination() const {
    if (!flow_) {
        return {};
    }
    return flow_->original_destination();
}

void tun_stream::shutdown(boost::asio::ip::tcp::socket::shutdown_type what, boost::system::error_code& ec) {
    ec = {};
    if (!flow_) {
        ec = boost::asio::error::bad_descriptor;
        return;
    }
    if (what == boost::asio::ip::tcp::socket::shutdown_send ||
        what == boost::asio::ip::tcp::socket::shutdown_both) {
        detail::tcp_flow_shutdown_send(flow_);
    }
    if (what == boost::asio::ip::tcp::socket::shutdown_receive ||
        what == boost::asio::ip::tcp::socket::shutdown_both) {
        detail::tcp_flow_shutdown_receive(flow_);
    }
}

void tun_stream::close() {
    if (flow_) {
        detail::tcp_flow_close(flow_);
    }
}

void tun_stream::reset() {
    if (flow_) {
        detail::tcp_flow_reset(flow_);
    }
}

bool tun_stream::is_open() const noexcept {
    return detail::tcp_flow_is_open(flow_);
}

} // namespace tun_engine
