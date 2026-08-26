#include "tcp_engine.hpp"

#include <algorithm>
#include <cstring>
#include <random>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "device_writer.hpp"

namespace tunio {
namespace detail {

namespace {

uint32_t random_iss() {
    static std::mt19937 rng{std::random_device{}()};
    return rng();
}

} // namespace

tcp_engine::tcp_engine(boost::asio::any_io_executor strand, device_writer& writer,
                       const tun_config& cfg, engine_stats& stats,
                       std::shared_ptr<buffer_accountant> account)
    : strand_(std::move(strand)),
      writer_(writer),
      cfg_(cfg),
      stats_(stats),
      account_(std::move(account)),
      mss_(cfg.mtu > 40 ? cfg.mtu - 40 : 536),
      sweep_timer_(strand_) {}

tcp_engine::~tcp_engine() {
    sweep_timer_.cancel();
}

void tcp_engine::start_sweep() {
    sweep_timer_.expires_after(std::chrono::seconds(1));
    sweep_timer_.async_wait(asio::bind_executor(strand_, [self = shared_from_this()](const boost::system::error_code& ec) {
        self->on_sweep(ec);
    }));
}

void tcp_engine::on_sweep(const boost::system::error_code& ec) {
    if (ec) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::shared_ptr<tcp_flow>> victims;
    for (const auto& [key, f] : flows_) {
        (void)key;
        if (f->state == tcp_state::SYN_RCVD && now - f->created_at > std::chrono::seconds(30)) {
            // 未完成握手的半开连接，30 秒后清理
            victims.push_back(f);
        } else if (f->state == tcp_state::ESTABLISHED && !f->accepted &&
                   now - f->created_at > cfg_.tcp_accept_timeout) {
            // 应用层长期未通过 async_accept 领取的连接：发送 RST 通知客户端后回收
            victims.push_back(f);
        } else if (f->state == tcp_state::TIME_WAIT && now >= f->destroy_at) {
            victims.push_back(f);
        } else if ((f->state == tcp_state::FIN_WAIT_1 || f->state == tcp_state::FIN_WAIT_2 ||
                    f->state == tcp_state::LAST_ACK) &&
                   now - f->created_at > std::chrono::seconds(30)) {
            // 关闭流程长期未完成（对端未确认 FIN / 未回复 FIN），30 秒后强制清理
            victims.push_back(f);
        }
    }
    for (auto& f : victims) {
        if (f->state == tcp_state::ESTABLISHED && !f->accepted) {
            abort_flow(*f);
        } else {
            close_flow(*f, boost::asio::error::operation_aborted);
        }
    }
    start_sweep();
}

void tcp_engine::on_packet(const ipv4_header& ip, const uint8_t* payload, size_t len) {
    if (len < sizeof(tcp_header)) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    tcp_header th;
    std::memcpy(&th, payload, sizeof(th));

    // 校验 TCP 校验和
    if (tcp_udp_checksum(ip.src_ip, ip.dst_ip, IPPROTO_TCP_V, payload, len) != 0) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // 校验 TCP 头长（新建流与既有流统一前置检查）
    const size_t hlen = th.header_len();
    if (hlen < sizeof(tcp_header) || hlen > len) {
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    const bool is_syn = (th.flags & TCP_SYN) != 0 && (th.flags & TCP_ACK) == 0;
    const five_tuple key{ip.src_ip, ip.dst_ip, th.src_port, th.dst_port, IPPROTO_TCP_V};

    auto it = flows_.find(key);
    std::shared_ptr<tcp_flow> f;
    if (it == flows_.end()) {
        if (!is_syn) {
            // 未知流且非 SYN：丢弃
            return;
        }
        if (flows_.size() >= cfg_.max_tcp_flows) {
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        f = std::make_shared<tcp_flow>();
        f->key = key;
        f->eng = this;
        f->irs = ntohl(th.seq);
        f->iss = random_iss();
        f->rcv_nxt = f->irs + 1;
        f->snd_nxt = f->iss;
        f->snd_una = f->iss;
        f->state = tcp_state::SYN_RCVD;
        f->peer_wnd = ntohs(th.window);
        f->created_at = std::chrono::steady_clock::now();
        flows_.emplace(key, f);
        // 回复 SYN-ACK（携带 MSS 选项）
        send_segment(*f, f->iss, TCP_SYN | TCP_ACK, nullptr, 0, true);
        f->snd_nxt = f->iss + 1; // SYN 消耗一个序号
        return;
    }
    f = it->second;

    const uint8_t* data = payload + hlen;
    size_t data_len = len - hlen;
    handle_segment(std::move(f), th, data, data_len);
}

void tcp_engine::handle_segment(std::shared_ptr<tcp_flow> f, const tcp_header& th,
                                const uint8_t* data, size_t data_len) {
    const uint32_t seq = ntohl(th.seq);
    const uint32_t ack = ntohl(th.ack);
    const uint8_t flags = th.flags;
    const uint16_t wnd = ntohs(th.window);

    // ---- ACK 与窗口更新 ----
    if (flags & TCP_ACK) {
        if (seq_gt(ack, f->snd_una) && seq_ge(f->snd_nxt, ack)) {
            f->snd_una = ack;
        }
        if (f->state == tcp_state::FIN_WAIT_1 && f->fin_sent && seq_ge(ack, f->snd_nxt)) {
            // 客户端确认了我们的 FIN
            f->state = f->fin_received ? tcp_state::TIME_WAIT : tcp_state::FIN_WAIT_2;
            if (f->state == tcp_state::TIME_WAIT) {
                f->destroy_at = std::chrono::steady_clock::now() + cfg_.tcp_time_wait_timeout;
            }
        } else if (f->state == tcp_state::LAST_ACK && f->fin_sent && seq_ge(ack, f->snd_nxt)) {
            close_flow(*f, boost::system::error_code{});
            return;
        }
    }
    f->peer_wnd = wnd;

    if (flags & TCP_RST) {
        f->rst = true;
        close_flow(*f, boost::asio::error::connection_reset);
        return;
    }

    if (f->state == tcp_state::CLOSED) {
        return;
    }

    // ---- 握手状态 ----
    if (f->state == tcp_state::SYN_RCVD) {
        if ((flags & TCP_SYN) && seq == f->irs) {
            // 客户端重传 SYN：重新发送 SYN-ACK
            send_segment(*f, f->iss, TCP_SYN | TCP_ACK, nullptr, 0, true);
            return;
        }
        if ((flags & TCP_ACK) && ack == f->iss + 1) {
            f->state = tcp_state::ESTABLISHED;
            stats_.tcp_connections.fetch_add(1, std::memory_order_relaxed);
            notify_accept(*f);
            if (data_len > 0 && seq == f->rcv_nxt) {
                deliver_data(*f, data, data_len);
            }
        }
        return;
    }

    // ---- 已建立连接的数据处理 ----
    if (data_len > 0) {
        if (seq == f->rcv_nxt) {
            deliver_data(*f, data, data_len);
        } else if (seq_gt(seq, f->rcv_nxt)) {
            // 超前序列号：不缓存，发送 Dup-ACK 触发对端快速重传
            send_ack(*f);
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        } else {
            // 重复或已接收段：静默丢弃
            stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ---- FIN ----
    if (flags & TCP_FIN) {
        // FIN 序号 = seq + data_len（FIN 消耗一个序列号，可与数据同段）
        const uint32_t fin_seq = seq + static_cast<uint32_t>(data_len);
        if (fin_seq == f->rcv_nxt) {
            if (!f->fin_received) {
                f->rcv_nxt += 1;
                f->fin_received = true;
            }
            send_ack(*f);
            switch (f->state) {
            case tcp_state::ESTABLISHED:
                f->state = tcp_state::CLOSE_WAIT;
                break;
            case tcp_state::FIN_WAIT_1:
                // 等待客户端 ACK 我们的 FIN（ACK 分支推进到 FIN_WAIT_2 / TIME_WAIT）
                break;
            case tcp_state::FIN_WAIT_2:
                f->state = tcp_state::TIME_WAIT;
                f->destroy_at = std::chrono::steady_clock::now() + cfg_.tcp_time_wait_timeout;
                break;
            case tcp_state::TIME_WAIT:
                break;
            default:
                break;
            }
            flush_reads(*f);
        } else if (f->state == tcp_state::TIME_WAIT && fin_seq == f->rcv_nxt - 1) {
            // 对端重传 FIN：重新确认
            send_ack(*f);
        }
    }

    flush_writes(*f);
}

void tcp_engine::deliver_data(tcp_flow& f, const uint8_t* data, size_t len) {
    if (len == 0) {
        return;
    }
    if (f.rx_bytes + len > cfg_.max_rx_queue_per_flow || !account_->reserve(len)) {
        // 队列积压或总缓冲超限：静默丢弃，不回复 ACK 以施加背压
        stats_.rx_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    f.rx_data.insert(f.rx_data.end(), data, data + len);
    f.rx_bytes += len;
    f.rcv_nxt += len;
    send_ack(f);
    flush_reads(f);
}

void tcp_engine::flush_reads(tcp_flow& f) {
    while (!f.pending_reads.empty() && f.rx_bytes > 0) {
        auto op = std::move(f.pending_reads.front());
        f.pending_reads.pop_front();
        const size_t n = std::min(op.total, f.rx_bytes);
        size_t copied = 0;
        for (auto& buf : *op.buffers) {
            if (copied >= n) {
                break;
            }
            const size_t take = std::min(buf.size(), n - copied);
            uint8_t* dst = static_cast<uint8_t*>(buf.data());
            std::copy_n(f.rx_data.begin(), take, dst);
            f.rx_data.erase(f.rx_data.begin(), f.rx_data.begin() + static_cast<std::ptrdiff_t>(take));
            copied += take;
        }
        f.rx_bytes -= copied;
        account_->release(copied);
        op.handler(boost::system::error_code{}, copied);
    }
    // 数据耗尽后处理 EOF
    if (f.rx_bytes == 0 && f.fin_received) {
        while (!f.pending_reads.empty()) {
            auto op = std::move(f.pending_reads.front());
            f.pending_reads.pop_front();
            op.handler(boost::system::error_code{}, 0);
        }
    }
}

void tcp_engine::flush_writes(tcp_flow& f) {
    while (!f.pending_writes.empty()) {
        auto& op = f.pending_writes.front();
        const uint32_t in_flight = f.snd_nxt - f.snd_una;
        if (in_flight >= f.peer_wnd) {
            // 窗口耗尽：等待客户端 ACK 更新窗口
            break;
        }
        const size_t remaining = op.data.size() - op.offset;
        const size_t chunk =
            std::min({remaining, mss_, static_cast<size_t>(f.peer_wnd - in_flight)});
        if (chunk == 0) {
            break;
        }
        send_segment(f, f.snd_nxt, TCP_ACK | TCP_PSH, op.data.data() + op.offset, chunk, false);
        f.snd_nxt += static_cast<uint32_t>(chunk);
        op.offset += chunk;
        if (op.offset == op.data.size()) {
            auto h = std::move(op.handler);
            f.pending_writes.pop_front();
            h(boost::system::error_code{}, op.data.size());
        }
    }
}

void tcp_engine::send_segment(tcp_flow& f, uint32_t seq, uint8_t flags,
                              const uint8_t* payload, size_t len, bool with_mss) {
    const size_t tcp_hdr_len = with_mss ? 24 : 20;
    const size_t total = 20 + tcp_hdr_len + len;
    packet_buffer pkt(cfg_.mtu + 64, 64);
    pkt.resize(total);
    uint8_t* base = pkt.data();

    auto* ip = reinterpret_cast<ipv4_header*>(base);
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_len = htons(static_cast<uint16_t>(total));
    ip->id = htons(writer_.alloc_ip_id());
    ip->frag_off = htons(0x4000); // DF
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP_V;
    ip->checksum = 0;
    ip->src_ip = f.key.dst_ip;
    ip->dst_ip = f.key.src_ip;
    ip->checksum = htons(ipv4_checksum(base, 20));

    auto* th = reinterpret_cast<tcp_header*>(base + 20);
    th->src_port = f.key.dst_port;
    th->dst_port = f.key.src_port;
    th->seq = htonl(seq);
    th->ack = htonl(f.rcv_nxt);
    th->data_offset = static_cast<uint8_t>((with_mss ? 6 : 5) << 4);
    th->flags = flags;
    th->window = htons(tcp_flow::fixed_rcv_wnd);
    th->checksum = 0;
    th->urgent = 0;

    if (with_mss) {
        uint8_t* opt = base + 20 + 20;
        opt[0] = 2; // kind = MSS
        opt[1] = 4; // len = 4
        opt[2] = static_cast<uint8_t>(mss_ >> 8);
        opt[3] = static_cast<uint8_t>(mss_ & 0xff);
    }
    if (len > 0) {
        std::memcpy(base + 20 + tcp_hdr_len, payload, len);
    }
    th->checksum = htons(tcp_udp_checksum(ip->src_ip, ip->dst_ip, IPPROTO_TCP_V, base + 20,
                                          tcp_hdr_len + len));

    writer_.async_write(std::move(pkt),
                        asio::bind_executor(strand_, [](const boost::system::error_code&, size_t) {}));
}

void tcp_engine::send_ack(tcp_flow& f) {
    send_segment(f, f.snd_nxt, TCP_ACK, nullptr, 0, false);
}

void tcp_engine::send_fin(tcp_flow& f) {
    if (f.fin_sent || f.state == tcp_state::CLOSED) {
        return;
    }
    f.fin_sent = true;
    switch (f.state) {
    case tcp_state::ESTABLISHED:
        f.state = tcp_state::FIN_WAIT_1;
        send_segment(f, f.snd_nxt, TCP_ACK | TCP_FIN, nullptr, 0, false);
        f.snd_nxt += 1;
        break;
    case tcp_state::CLOSE_WAIT:
        f.state = tcp_state::LAST_ACK;
        send_segment(f, f.snd_nxt, TCP_ACK | TCP_FIN, nullptr, 0, false);
        f.snd_nxt += 1;
        break;
    case tcp_state::SYN_RCVD:
        // 握手尚未完成：直接关闭，不发送 FIN
        close_flow(f, boost::asio::error::operation_aborted);
        break;
    default:
        break;
    }
}

void tcp_engine::abort_flow(tcp_flow& f) {
    if (f.state == tcp_state::CLOSED) {
        return;
    }
    // RST 段：seq = snd_nxt, ack = rcv_nxt
    send_segment(f, f.snd_nxt, TCP_RST | TCP_ACK, nullptr, 0, false);
    f.rst = true;
    close_flow(f, boost::asio::error::connection_reset);
}

void tcp_engine::close_flow(tcp_flow& f, const boost::system::error_code& err) {
    if (f.state == tcp_state::CLOSED) {
        return;
    }
    for (auto& op : f.pending_reads) {
        op.handler(err, 0);
    }
    f.pending_reads.clear();
    for (auto& op : f.pending_writes) {
        op.handler(err, 0);
    }
    f.pending_writes.clear();
    if (f.rx_bytes > 0) {
        account_->release(f.rx_bytes);
        f.rx_bytes = 0;
    }
    f.rx_data.clear();
    if (f.state != tcp_state::SYN_RCVD) {
        stats_.tcp_connections.fetch_sub(1, std::memory_order_relaxed);
    }
    f.state = tcp_state::CLOSED;
    flows_.erase(f.key);
}

void tcp_engine::notify_accept(tcp_flow& f) {
    if (!pending_accepts_.empty()) {
        auto h = std::move(pending_accepts_.front());
        pending_accepts_.pop_front();
        f.accepted = true;
        h(boost::system::error_code{}, f.shared_from_this());
    } else {
        pending_flows_.push_back(f.shared_from_this());
    }
}

void tcp_engine::async_accept(std::function<void(boost::system::error_code, std::shared_ptr<tcp_flow>)> handler) {
    while (!pending_flows_.empty()) {
        auto f = std::move(pending_flows_.front());
        pending_flows_.pop_front();
        if (f->state == tcp_state::CLOSED) {
            continue;
        }
        f->accepted = true;
        handler(boost::system::error_code{}, std::move(f));
        return;
    }
    pending_accepts_.push_back(std::move(handler));
}

void tcp_engine::cancel_accepts() {
    while (!pending_accepts_.empty()) {
        auto h = std::move(pending_accepts_.front());
        pending_accepts_.pop_front();
        h(boost::asio::error::operation_aborted, nullptr);
    }
}

void tcp_engine::close_all() {
    sweep_timer_.cancel();
    std::vector<std::shared_ptr<tcp_flow>> all;
    all.reserve(flows_.size());
    for (auto& [key, f] : flows_) {
        (void)key;
        all.push_back(f);
    }
    for (auto& f : all) {
        close_flow(*f, boost::asio::error::operation_aborted);
    }
    pending_flows_.clear();
    cancel_accepts();
}

// ---- tun_stream 入口 ----

void tcp_flow_start_read(std::shared_ptr<tcp_flow> flow,
                         std::shared_ptr<std::vector<asio::mutable_buffer>> buffers,
                         size_t total,
                         std::function<void(boost::system::error_code, size_t)> handler) {
    if (!flow || !flow->eng) {
        handler(boost::asio::error::bad_descriptor, 0);
        return;
    }
    asio::dispatch(flow->eng->strand(), [flow, buffers = std::move(buffers), total,
                                         handler = std::move(handler)]() mutable {
        auto& f = *flow;
        if (f.state == tcp_state::CLOSED || f.app_closed || f.rx_shutdown) {
            handler(boost::asio::error::bad_descriptor, 0);
            return;
        }
        if (f.rst) {
            handler(boost::asio::error::connection_reset, 0);
            return;
        }
        if (total == 0) {
            handler(boost::system::error_code{}, 0);
            return;
        }
        f.pending_reads.push_back({std::move(buffers), total, std::move(handler)});
        flow->eng->flush_reads(f);
    });
}

void tcp_flow_start_write(std::shared_ptr<tcp_flow> flow, std::vector<uint8_t> data,
                          std::function<void(boost::system::error_code, size_t)> handler) {
    if (!flow || !flow->eng) {
        handler(boost::asio::error::bad_descriptor, 0);
        return;
    }
    asio::dispatch(flow->eng->strand(), [flow, data = std::move(data),
                                         handler = std::move(handler)]() mutable {
        auto& f = *flow;
        if (f.state == tcp_state::CLOSED || f.app_closed || f.fin_sent) {
            handler(boost::asio::error::bad_descriptor, 0);
            return;
        }
        if (f.rst) {
            handler(boost::asio::error::connection_reset, 0);
            return;
        }
        if (data.empty()) {
            handler(boost::system::error_code{}, 0);
            return;
        }
        f.pending_writes.push_back({std::move(data), 0, std::move(handler)});
        flow->eng->flush_writes(f);
    });
}

void tcp_flow_shutdown_send(std::shared_ptr<tcp_flow> flow) {
    if (!flow || !flow->eng) {
        return;
    }
    asio::dispatch(flow->eng->strand(), [flow]() {
        auto& f = *flow;
        if (f.state == tcp_state::CLOSED || f.app_closed) {
            return;
        }
        flow->eng->send_fin(f);
    });
}

void tcp_flow_shutdown_receive(std::shared_ptr<tcp_flow> flow) {
    if (!flow || !flow->eng) {
        return;
    }
    asio::dispatch(flow->eng->strand(), [flow]() {
        auto& f = *flow;
        if (f.state == tcp_state::CLOSED) {
            return;
        }
        f.rx_shutdown = true;
        for (auto& op : f.pending_reads) {
            op.handler(boost::asio::error::operation_aborted, 0);
        }
        f.pending_reads.clear();
        if (f.rx_bytes > 0) {
            flow->eng->account().release(f.rx_bytes);
            f.rx_bytes = 0;
        }
        f.rx_data.clear();
    });
}

void tcp_flow_close(std::shared_ptr<tcp_flow> flow) {
    if (!flow || !flow->eng) {
        return;
    }
    asio::dispatch(flow->eng->strand(), [flow]() {
        auto& f = *flow;
        if (f.state == tcp_state::CLOSED || f.app_closed) {
            return;
        }
        f.app_closed = true;
        for (auto& op : f.pending_reads) {
            op.handler(boost::asio::error::operation_aborted, 0);
        }
        f.pending_reads.clear();
        for (auto& op : f.pending_writes) {
            op.handler(boost::asio::error::operation_aborted, 0);
        }
        f.pending_writes.clear();
        if (f.rx_bytes > 0) {
            flow->eng->account().release(f.rx_bytes);
            f.rx_bytes = 0;
        }
        f.rx_data.clear();
        flow->eng->send_fin(f);
    });
}

void tcp_flow_reset(std::shared_ptr<tcp_flow> flow) {
    if (!flow || !flow->eng) {
        return;
    }
    asio::dispatch(flow->eng->strand(), [flow]() {
        auto& f = *flow;
        if (f.state == tcp_state::CLOSED || f.app_closed) {
            return;
        }
        flow->eng->abort_flow(f);
    });
}

bool tcp_flow_is_open(const std::shared_ptr<tcp_flow>& flow) {
    return flow && flow->eng && flow->state != tcp_state::CLOSED && !flow->app_closed && !flow->rst;
}

boost::asio::ip::tcp::endpoint tcp_flow::original_destination() const {
    return {boost::asio::ip::address_v4(ntohl(key.dst_ip)), ntohs(key.dst_port)};
}

bool tcp_flow::is_open() const {
    return state != tcp_state::CLOSED && !app_closed && !rst;
}

} // namespace detail
} // namespace tunio
