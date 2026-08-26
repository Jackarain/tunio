#include "udp_engine.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include <boost/asio.hpp>

#include "device_writer.hpp"
#include "tcp_engine.hpp"

namespace tunio {
namespace detail {

udp_engine::udp_engine(boost::asio::any_io_executor strand, device_writer& writer,
                       const tun_config& cfg, engine_stats& stats,
                       std::shared_ptr<buffer_accountant> account)
    : strand_(std::move(strand)),
      writer_(writer),
      cfg_(cfg),
      stats_(stats),
      account_(std::move(account)),
      mtu_(cfg.mtu),
      expiry_timer_(strand_) {}

udp_engine::~udp_engine() {
    expiry_timer_.cancel();
}

void udp_engine::on_packet(const ipv4_header& ip, const uint8_t* payload, size_t len) {
    if (len < sizeof(udp_header)) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    udp_header uh;
    std::memcpy(&uh, payload, sizeof(uh));

    const size_t udp_len = ntohs(uh.length);
    if (udp_len < sizeof(udp_header) || udp_len > len) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    len = udp_len; // 截断可能的填充字节

    // 校验 UDP 校验和（0 表示发送方未计算，IPv4 下允许）
    const uint16_t csum = ntohs(uh.checksum);
    if (csum != 0 &&
        tcp_udp_checksum(ip.src_ip, ip.dst_ip, IPPROTO_UDP_V, payload, len) != 0) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    const five_tuple key{ip.src_ip, ip.dst_ip, uh.src_port, uh.dst_port, IPPROTO_UDP_V};
    std::vector<uint8_t> datagram(payload + sizeof(udp_header), payload + len);

    auto it = sessions_.find(key);
    if (it != sessions_.end()) {
        auto s = it->second;
        if (!s->closed) {
            deliver_datagram(std::move(s), std::move(datagram));
            return;
        }
        sessions_.erase(it);
    }

    if (sessions_.size() >= cfg_.max_udp_flows) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // 新建会话并通知上层
    auto s = std::make_shared<udp_session>();
    s->key = key;
    s->eng = this;
    s->timeout = cfg_.udp_idle_timeout;
    s->expiry = std::chrono::steady_clock::now() + s->timeout;
    sessions_.emplace(key, s);
    stats_.udp_sessions.fetch_add(1, std::memory_order_relaxed);

    deliver_datagram(s, std::move(datagram));
    refresh_expiry(s);

    if (!pending_accepts_.empty()) {
        auto h = std::move(pending_accepts_.front());
        pending_accepts_.pop_front();
        s->accepted = true;
        h(boost::system::error_code{}, s);
    } else {
        pending_new_sessions_.push_back(s);
    }
}

void udp_engine::deliver_datagram(std::shared_ptr<udp_session> s, std::vector<uint8_t> datagram) {
    if (s->closed) {
        return;
    }
    refresh_expiry(s);
    if (!s->pending_reads.empty()) {
        auto op = std::move(s->pending_reads.front());
        s->pending_reads.pop_front();
        if (datagram.size() > op.total) {
            op.handler(boost::asio::error::message_size, 0);
        } else {
            size_t copied = 0;
            for (auto& buf : *op.buffers) {
                if (copied >= datagram.size()) {
                    break;
                }
                const size_t take = std::min(buf.size(), datagram.size() - copied);
                std::memcpy(buf.data(), datagram.data() + copied, take);
                copied += take;
            }
            op.handler(boost::system::error_code{}, datagram.size());
        }
        return;
    }
    if (s->rx_bytes + datagram.size() > cfg_.max_rx_queue_per_flow ||
        !account_->reserve(datagram.size())) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    s->rx_datagrams.push_back(std::move(datagram));
    s->rx_bytes += s->rx_datagrams.back().size();
}

void udp_engine::refresh_expiry(std::shared_ptr<udp_session> s) {
    if (s->closed) {
        return;
    }
    s->expiry = std::chrono::steady_clock::now() + s->timeout;
    ++s->expiry_gen;
    expiry_heap_.push_back({s->expiry, s->expiry_gen, s});
    std::push_heap(expiry_heap_.begin(), expiry_heap_.end(), expiry_entry_cmp{});
    arm_expiry_timer();
}

void udp_engine::arm_expiry_timer() {
    // 弹出失效的堆顶
    while (!expiry_heap_.empty()) {
        auto& top = expiry_heap_.front();
        auto sp = top.session.lock();
        if (sp && !sp->closed && sp->expiry_gen == top.gen) {
            break;
        }
        std::pop_heap(expiry_heap_.begin(), expiry_heap_.end(), expiry_entry_cmp{});
        expiry_heap_.pop_back();
    }
    if (expiry_heap_.empty()) {
        return;
    }
    const auto target = expiry_heap_.front().at;
    if (timer_waiting_ && target >= armed_target_) {
        // 现有等待已足够早，无需重排
        return;
    }
    // 取消旧等待并安排新等待；被取消的旧回调通过代次号丢弃
    timer_waiting_ = false;
    expiry_timer_.cancel();
    ++wait_gen_;
    const uint64_t gen = wait_gen_;
    armed_target_ = target;
    timer_waiting_ = true;
    expiry_timer_.expires_at(target);
    expiry_timer_.async_wait(asio::bind_executor(strand_, [self = shared_from_this(), gen](const boost::system::error_code& ec) {
        if (gen != self->wait_gen_) {
            return;
        }
        self->on_expiry_timer(ec);
    }));
}

void udp_engine::on_expiry_timer(const boost::system::error_code& ec) {
    timer_waiting_ = false;
    if (ec) {
        // 等待被取消（expires_at 重排）：重新按堆顶安排
        arm_expiry_timer();
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    while (!expiry_heap_.empty()) {
        auto& top = expiry_heap_.front();
        if (top.at > now) {
            break;
        }
        auto sp = top.session.lock();
        const bool stale = !sp || sp->closed || sp->expiry_gen != top.gen;
        if (!stale && sp->expiry <= now) {
            remove_session(sp);
        }
        std::pop_heap(expiry_heap_.begin(), expiry_heap_.end(), expiry_entry_cmp{});
        expiry_heap_.pop_back();
    }
    arm_expiry_timer();
}

void udp_engine::remove_session(std::shared_ptr<udp_session> s) {
    if (s->closed) {
        return;
    }
    s->closed = true;
    sessions_.erase(s->key);
    stats_.udp_sessions.fetch_sub(1, std::memory_order_relaxed);
    for (auto& op : s->pending_reads) {
        op.handler(boost::asio::error::operation_aborted, 0);
    }
    s->pending_reads.clear();
    if (s->rx_bytes > 0) {
        account_->release(s->rx_bytes);
        s->rx_bytes = 0;
    }
    s->rx_datagrams.clear();
}

void udp_engine::async_accept(std::function<void(boost::system::error_code, std::shared_ptr<udp_session>)> handler) {
    while (!pending_new_sessions_.empty()) {
        auto s = std::move(pending_new_sessions_.front());
        pending_new_sessions_.pop_front();
        if (s->closed) {
            continue;
        }
        s->accepted = true;
        handler(boost::system::error_code{}, std::move(s));
        return;
    }
    pending_accepts_.push_back(std::move(handler));
}

void udp_engine::cancel_accepts() {
    while (!pending_accepts_.empty()) {
        auto h = std::move(pending_accepts_.front());
        pending_accepts_.pop_front();
        h(boost::asio::error::operation_aborted, nullptr);
    }
}

void udp_engine::close_all() {
    expiry_timer_.cancel();
    timer_waiting_ = false;
    std::vector<std::shared_ptr<udp_session>> all;
    all.reserve(sessions_.size());
    for (auto& [key, s] : sessions_) {
        (void)key;
        all.push_back(s);
    }
    for (auto& s : all) {
        remove_session(s);
    }
    pending_new_sessions_.clear();
    cancel_accepts();
    expiry_heap_.clear();
}

// ---- tun_udp_socket 入口 ----

void udp_session_start_receive(std::shared_ptr<udp_session> session,
                               std::shared_ptr<std::vector<asio::mutable_buffer>> buffers,
                               size_t total,
                               std::function<void(boost::system::error_code, size_t)> handler) {
    if (!session || !session->eng) {
        handler(boost::asio::error::bad_descriptor, 0);
        return;
    }
    asio::dispatch(session->eng->strand(), [session, buffers = std::move(buffers), total,
                                            handler = std::move(handler)]() mutable {
        auto& s = *session;
        if (s.closed) {
            handler(boost::asio::error::bad_descriptor, 0);
            return;
        }
        if (total == 0) {
            handler(boost::system::error_code{}, 0);
            return;
        }
        if (!s.rx_datagrams.empty()) {
            auto dg = std::move(s.rx_datagrams.front());
            s.rx_datagrams.pop_front();
            s.rx_bytes -= dg.size();
            session->eng->account().release(dg.size());
            if (dg.size() > total) {
                handler(boost::asio::error::message_size, 0);
                return;
            }
            size_t copied = 0;
            for (auto& buf : *buffers) {
                if (copied >= dg.size()) {
                    break;
                }
                const size_t take = std::min(buf.size(), dg.size() - copied);
                std::memcpy(buf.data(), dg.data() + copied, take);
                copied += take;
            }
            handler(boost::system::error_code{}, dg.size());
            return;
        }
        s.pending_reads.push_back({std::move(buffers), total, std::move(handler)});
    });
}

void udp_session_start_send(std::shared_ptr<udp_session> session, std::vector<uint8_t> data,
                            std::function<void(boost::system::error_code, size_t)> handler) {
    if (!session || !session->eng) {
        handler(boost::asio::error::bad_descriptor, 0);
        return;
    }
    asio::dispatch(session->eng->strand(), [session, data = std::move(data),
                                            handler = std::move(handler)]() mutable {
        auto& s = *session;
        if (s.closed) {
            handler(boost::asio::error::bad_descriptor, 0);
            return;
        }
        const size_t mtu = session->eng->mtu();
        if (data.size() > mtu - 28) {
            handler(boost::asio::error::message_size, 0);
            return;
        }
        session->eng->refresh_expiry(session);

        // 构造 IP + UDP 报文（源地址为客户端请求的目标地址）
        const size_t total = 20 + sizeof(udp_header) + data.size();
        packet_buffer pkt(mtu + 64, 64);
        pkt.resize(total);
        uint8_t* base = pkt.data();

        auto* ip = reinterpret_cast<ipv4_header*>(base);
        ip->version_ihl = 0x45;
        ip->tos = 0;
        ip->total_len = htons(static_cast<uint16_t>(total));
        ip->id = htons(session->eng->writer().alloc_ip_id());
        ip->frag_off = htons(0x4000); // DF
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP_V;
        ip->checksum = 0;
        ip->src_ip = s.key.dst_ip;
        ip->dst_ip = s.key.src_ip;
        ip->checksum = htons(ipv4_checksum(base, 20));

        auto* uh = reinterpret_cast<udp_header*>(base + 20);
        uh->src_port = s.key.dst_port;
        uh->dst_port = s.key.src_port;
        uh->length = htons(static_cast<uint16_t>(sizeof(udp_header) + data.size()));
        uh->checksum = 0;
        if (!data.empty()) {
            std::memcpy(base + 20 + sizeof(udp_header), data.data(), data.size());
        }
        uh->checksum = htons(tcp_udp_checksum(ip->src_ip, ip->dst_ip, IPPROTO_UDP_V, base + 20,
                                              sizeof(udp_header) + data.size()));

        using handler_t = std::decay_t<decltype(handler)>;
        auto sp = std::make_shared<handler_t>(std::move(handler));
        const size_t sent = data.size();
        session->eng->writer().async_write(
            std::move(pkt), asio::bind_executor(session->eng->strand(), [sp, sent](const boost::system::error_code&, size_t) {
                std::move(*sp)(boost::system::error_code{}, sent);
            }));
    });
}

void udp_session_close(std::shared_ptr<udp_session> session) {
    if (!session || !session->eng) {
        return;
    }
    asio::dispatch(session->eng->strand(), [session]() {
        session->eng->remove_session(session);
    });
}

void udp_session_set_timeout(std::shared_ptr<udp_session> session, std::chrono::seconds timeout) {
    if (!session || !session->eng) {
        return;
    }
    asio::dispatch(session->eng->strand(), [session, timeout]() {
        if (session->closed) {
            return;
        }
        session->timeout = timeout;
        session->eng->refresh_expiry(session);
    });
}

bool udp_session_is_open(const std::shared_ptr<udp_session>& session) {
    return session && session->eng && !session->closed;
}

} // namespace detail
} // namespace tunio
