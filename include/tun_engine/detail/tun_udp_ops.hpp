#pragma once

#include <boost/asio.hpp>

namespace asio = boost::asio;
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "tun_engine/detail/handler_util.hpp"
#include "tun_engine/tun_udp_socket.hpp"

namespace tun_engine {

namespace detail {

struct udp_session;

void udp_session_start_receive(std::shared_ptr<udp_session> session,
                               std::shared_ptr<std::vector<asio::mutable_buffer>> buffers,
                               size_t total,
                               std::function<void(boost::system::error_code, size_t)> handler);

void udp_session_start_send(std::shared_ptr<udp_session> session,
                            std::vector<uint8_t> data,
                            std::function<void(boost::system::error_code, size_t)> handler);

} // namespace detail

template <typename MutableBufferSequence>
void tun_udp_socket::do_receive(MutableBufferSequence&& buffers,
                                std::function<void(boost::system::error_code, size_t)> handler) {
    auto seq = std::make_shared<std::vector<asio::mutable_buffer>>();
    size_t total = 0;
    for (const auto& b : buffers) {
        seq->push_back(b);
        total += b.size();
    }

    auto session = session_;
    if (!session) {
        auto ex = ex_;
        asio::post(ex, [handler = std::move(handler)]() mutable {
            handler(boost::asio::error::bad_descriptor, 0);
        });
        return;
    }
    detail::udp_session_start_receive(std::move(session), std::move(seq), total,
                                      detail::bind_handler(ex_, std::move(handler)));
}

template <typename ConstBufferSequence>
void tun_udp_socket::do_send(ConstBufferSequence&& buffers,
                             std::function<void(boost::system::error_code, size_t)> handler) {
    size_t total = 0;
    for (const auto& b : buffers) {
        total += b.size();
    }

    std::vector<uint8_t> data;
    data.reserve(total);
    for (const auto& b : buffers) {
        const uint8_t* p = static_cast<const uint8_t*>(b.data());
        data.insert(data.end(), p, p + b.size());
    }

    auto session = session_;
    if (!session) {
        auto ex = ex_;
        asio::post(ex, [handler = std::move(handler)]() mutable {
            handler(boost::asio::error::bad_descriptor, 0);
        });
        return;
    }
    detail::udp_session_start_send(std::move(session), std::move(data),
                                   detail::bind_handler(ex_, std::move(handler)));
}

} // namespace tun_engine
