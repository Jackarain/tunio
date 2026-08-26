# 基于 Boost.Asio 范式的用户态 TUN 虚拟网络引擎
## 架构与设计说明书

**版本**：3.0
**状态**：正式发布版
**适用场景**：tun2socks、透明代理、轻量级 VPN 网关

---

### 1. 概述

本设计定义了一个高性能、跨平台的用户态 TUN 网络引擎（以下简称 `tun_engine`）。该引擎将 Linux TUN、macOS utun 及 Windows Wintun 设备产生的 L3 原始 IP 包处理全面封装于内部，向上层应用暴露一套完全对齐 Boost.Asio 网络编程范式的现代 C++ 异步接口。

引擎在设计上具备高度的**设备管理灵活性**：既支持由引擎内部自主创建并配置 TUN 设备，也支持接管由外部应用预先打开的平台原生句柄（文件描述符或 HANDLE）。后者对于需要特殊权限提升（如 Linux CAP_NET_ADMIN 提前提权）、多实例共享同一设备或集成于现有网络管理框架的场景尤为关键。

本引擎在 TCP 层面采取 **"尽力而为"的轻量级转发策略**：不维护复杂的重传队列、RTO 定时器或乱序重组缓冲区，而是依赖底层 IP 网络和通信对端的内核协议栈来保证最终可靠性。这种设计大幅降低了引擎的 CPU 开销与内存占用，特别适用于低延迟局域网、UDP 密集型 VPN 以及对丢包容忍度较高的透明代理场景。

上层开发者能够像操作普通 `asio::ip::tcp::socket` 一样处理 VPN 拦截流量，无缝接入 C++20 协程（`co_await`），从而极大地简化透明代理、tun2socks 及轻量级 VPN 网关的开发复杂度。

---

### 2. 整体架构

系统采用四层解耦架构，自底向上分别为设备抽象层、协议引擎层、异步 API 层和应用层。为保证多线程并发安全（`io_context` 运行于线程池），引擎内部所有状态变更、NAT 表操作及定时器销毁均强制运行于一个 **Boost.Asio Strand** 之上，彻底避免锁竞争。

```
+-----------------------------------------------------------------------------+
|                        应用层 (Proxy Logic / SOCKS5 Client)                  |
|              (使用 Boost.Asio, co_await, 业务路由逻辑)                       |
+-----------------------------------------------------------------------------+
                                    ▲
               Async API Boundary   │  tun_stream / tun_acceptor
                                    │  tun_udp_socket / tun_udp_acceptor
                                    ▼
+-----------------------------------------------------------------------------+
|                           异步 API 接口层                                    |
|  +----------------------------+   +---------------------------------------+ |
|  |       tun_stream           |   |         tun_udp_socket               | |
|  |  (TCP Virtual Socket)      |   |  (UDP Datagram Socket)              | |
|  +----------------------------+   +---------------------------------------+ |
|  +----------------------------+   +---------------------------------------+ |
|  |       tun_acceptor         |   |         tun_udp_acceptor             | |
|  |  (TCP Listener)            |   |  (UDP Session Listener)              | |
|  +----------------------------+   +---------------------------------------+ |
+-----------------------------------------------------------------------------+
                                    ▲
                                    ▼
+-----------------------------------------------------------------------------+
|                           协议引擎层 (Core Engine)                           |
|  +-------------------------------------+ +--------------------------------+ |
|  |       TCP Flow Engine               | |     UDP Flow Engine            | |
|  | - 顺序转发 (无乱序缓存)             | | - Datagram 收发                 | |
|  | - 基础 SEQ/ACK 校验                 | | - Session 表 (5-Tuple)          | |
|  | - Dup-ACK 触发对端重传             | | - Min-Heap 空闲超时             | |
|  | - 固定接收窗口                     | | - 新会话通知队列               | |
|  +-------------------------------------+ +--------------------------------+ |
|  +-----------------------------------------------------------------------+ |
|  |          Flow Dispatcher & NAT Table (five_tuple indexing)            | |
|  |          (运行于 Strand，无锁访问)                                    | |
|  +-----------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------+
                                    ▲
                                    ▼
+-----------------------------------------------------------------------------+
|                       跨平台设备抽象层 (Packet Device)                       |
|  +-----------------------------------------------------------------------+ |
|  | 支持两种初始化模式:                                                    | |
|  |  ① 自主打开: open(device_config) → 创建并配置设备                    | |
|  |  ② 句柄注入: assign(handle, mtu) → 接管外部已打开的句柄              | |
|  |                                                                       | |
|  |  异步 I/O 完全对齐 Asio 范式:                                        | |
|  |  async_read_packet(CompletionToken)                                   | |
|  |  async_write_packet(CompletionToken)                                  | |
|  +-----------------------------------------------------------------------+ |
|  +------------------+  +------------------+  +----------------------------+ |
|  | Linux TUN (fd)   |  | macOS utun       |  | Windows Wintun (Overlapped)| |
|  +------------------+  +------------------+  +----------------------------+ |
+-----------------------------------------------------------------------------+
```

**线程模型**：所有内部数据结构（TCP 控制块表、UDP NAT 表、新会话队列等）均通过 `net::strand<net::any_io_executor>` 串行化访问。任何修改这些共享状态的操作（包括异步回调中触发的状态变更）都必须通过 `strand::dispatch` 或 `strand::post` 提交，确保线程安全。设备 I/O（`async_read_packet`/`async_write_packet`）本身由底层 `io_context` 并行调度，其完成回调同样会在 Strand 中执行。

---

### 3. 核心基础类型定义

#### 3.1 平台原生句柄类型

支持外部句柄注入，定义跨平台句柄别名。

```cpp
#ifdef _WIN32
    using native_handle_type = void*;   // Windows HANDLE
#else
    using native_handle_type = int;     // POSIX 文件描述符
#endif

constexpr native_handle_type invalid_native_handle =
#ifdef _WIN32
    nullptr;
#else
    -1;
#endif
```

#### 3.2 统一五元组

用于 NAT 查表与 Flow 索引，基于纯内存块进行哈希计算以保证高性能，避免字符串分配。

```cpp
#pragma pack(push, 1)
struct five_tuple {
    uint32_t src_ip;      // 网络字节序
    uint32_t dst_ip;
    uint16_t src_port;    // 网络字节序
    uint16_t dst_port;
    uint8_t  protocol;    // IPPROTO_TCP (6) 或 IPPROTO_UDP (17)
};
#pragma pack(pop)

namespace std {
    template<> struct hash<five_tuple> {
        size_t operator()(const five_tuple& k) const noexcept {
            const uint64_t* p = reinterpret_cast<const uint64_t*>(&k);
            // 混合散列，充分利用 64 位字宽
            return p[0] ^ (p[1] << 7) ^ (static_cast<uint64_t>(k.protocol) << 56);
        }
    };
}
```

#### 3.3 零拷贝数据包缓冲区

支持头部预留（Headroom）机制，便于高效封装 IP/TCP 头部，避免频繁的内存分配与拷贝。

```cpp
class packet_buffer {
    std::unique_ptr<uint8_t[]> storage_;
    size_t capacity_;
    size_t headroom_;     // 预设头部空间 (如 128 字节)
    size_t data_offset_;  // 实际数据起始偏移
    size_t data_size_;
public:
    explicit packet_buffer(size_t cap = 2048, size_t headroom = 128);

    uint8_t* data() noexcept { return storage_.get() + data_offset_; }
    const uint8_t* data() const noexcept { return storage_.get() + data_offset_; }
    size_t size() const noexcept { return data_size_; }

    // 零拷贝前置头部
    void prepend(size_t len) noexcept { data_offset_ -= len; data_size_ += len; }
    // 零拷贝裁剪头部
    void trim(size_t len) noexcept { data_offset_ += len; data_size_ -= len; }

    size_t headroom_available() const noexcept { return data_offset_; }
};
```

#### 3.4 TCP 最小控制块

引擎仅维护最精简的状态信息，用于生成正确的 ACK 与处理 RST/FIN。

```cpp
struct tcp_minimal_state {
    // ---- 序列号跟踪 ----
    uint32_t snd_nxt;      // 本端将要发送的下一个序列号
    uint32_t rcv_nxt;      // 本端期望接收的下一个序列号

    // ---- 初始序列号 ----
    uint32_t iss;          // 本端初始发送序号
    uint32_t irs;          // 对端初始发送序号

    // ---- 固定窗口通告 ----
    static constexpr uint32_t fixed_rcv_wnd = 65535;

    // ---- 状态机 ----
    enum State : uint8_t {
        CLOSED, SYN_SENT, SYN_RCVD,
        ESTABLISHED,
        FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT,
        LAST_ACK, TIME_WAIT
    } state;
};
```

---

### 4. 跨平台设备抽象层

引擎核心不直接依赖任何平台特定的系统调用，通过 `std::variant` 持有平台具体实现，在统一的外壳类中完成 I/O 调度。该外壳支持两种初始化模式：

- **自主打开模式**：传入设备配置（设备名、IP 等），内部根据平台构造对应的实现类。
- **句柄注入模式**：传入外部已打开的平台原生句柄及 MTU，直接构造对应的实现类。

所有异步 I/O 接口完全对齐 Boost.Asio 规范：使用 `CompletionToken` 模板参数，通过 `async_initiate` 实现。

```cpp
struct device_config {
    std::string name;
    std::string ipv4;
    std::string netmask;
    size_t mtu = 1500;
};

class packet_device {
public:
    explicit packet_device(boost::asio::io_context& ctx) : ctx_(ctx) {}

    // ---- 模式 1: 自主打开 ----
    bool open(const device_config& cfg, boost::system::error_code& ec) {
#if defined(BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR)
        impl_.emplace<posix_impl>(ctx_);
#elif defined(BOOST_ASIO_HAS_WINDOWS_OVERLAPPED_PTR)
        impl_.emplace<windows_impl>(ctx_);
#endif
        return std::visit([&](auto& impl) -> bool {
            return impl.open(cfg, ec);
        }, impl_);
    }

    // ---- 模式 2: 句柄注入 ----
    bool assign(native_handle_type handle, size_t mtu, boost::system::error_code& ec) {
#if defined(BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR)
        impl_.emplace<posix_impl>(ctx_);
#elif defined(BOOST_ASIO_HAS_WINDOWS_OVERLAPPED_PTR)
        impl_.emplace<windows_impl>(ctx_);
#endif
        return std::visit([&](auto& impl) -> bool {
            return impl.assign(handle, mtu, ec);
        }, impl_);
    }

    void close() {
        std::visit([](auto& impl) { impl.close(); }, impl_);
    }

    size_t mtu() const {
        return std::visit([](const auto& impl) -> size_t { return impl.mtu(); }, impl_);
    }

    bool is_open() const {
        return std::visit([](const auto& impl) -> bool { return impl.is_open(); }, impl_);
    }

    // ---- 异步读取 ----
    template <typename CompletionToken>
    auto async_read_packet(packet_buffer& buf, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this, &buf](auto handler) {
                std::visit([&](auto& impl) {
                    impl.async_read(buf, std::move(handler));
                }, impl_);
            },
            token
        );
    }

    // ---- 异步写入 ----
    template <typename CompletionToken>
    auto async_write_packet(packet_buffer& buf, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this, &buf](auto handler) {
                std::visit([&](auto& impl) {
                    impl.async_write(buf, std::move(handler));
                }, impl_);
            },
            token
        );
    }

private:
    boost::asio::io_context& ctx_;

    // ---- POSIX 实现 (Linux/macOS) ----
    struct posix_impl {
        boost::asio::posix::stream_descriptor desc_;
        size_t mtu_ = 1500;
        bool open_ = false;

        explicit posix_impl(boost::asio::io_context& ctx) : desc_(ctx) {}

        bool open(const device_config& cfg, boost::system::error_code& ec) {
            // 实际 TUN 打开逻辑 (ioctl / dev/net/tun)
            // 成功后将 fd 通过 desc_.assign(fd, ec) 绑定
            open_ = true;
            mtu_ = cfg.mtu;
            return true;
        }

        bool assign(native_handle_type handle, size_t mtu, boost::system::error_code& ec) {
            desc_.assign(static_cast<int>(reinterpret_cast<intptr_t>(handle)), ec);
            if (!ec) { open_ = true; mtu_ = mtu; }
            return !ec;
        }

        void close() { desc_.close(); open_ = false; }
        size_t mtu() const { return mtu_; }
        bool is_open() const { return open_; }

        void async_read(packet_buffer& buf, std::function<void(boost::system::error_code, size_t)> handler) {
            desc_.async_read_some(boost::asio::buffer(buf.data(), buf.size()), std::move(handler));
        }

        void async_write(packet_buffer& buf, std::function<void(boost::system::error_code, size_t)> handler) {
            desc_.async_write_some(boost::asio::buffer(buf.data(), buf.size()), std::move(handler));
        }
    };

    // ---- Windows 实现 (Wintun / Overlapped) ----
    struct windows_impl {
        boost::asio::windows::overlapped_handle handle_;
        size_t mtu_ = 1500;
        bool open_ = false;

        explicit windows_impl(boost::asio::io_context& ctx) : handle_(ctx) {}

        bool open(const device_config& cfg, boost::system::error_code& ec) {
            // 实际 Wintun 打开逻辑 (WintunCreateAdapter / CreateFile)
            // 成功后将 HANDLE 通过 handle_.assign(h, ec) 绑定
            open_ = true;
            mtu_ = cfg.mtu;
            return true;
        }

        bool assign(native_handle_type handle, size_t mtu, boost::system::error_code& ec) {
            handle_.assign(handle, ec);
            if (!ec) { open_ = true; mtu_ = mtu; }
            return !ec;
        }

        void close() { handle_.close(); open_ = false; }
        size_t mtu() const { return mtu_; }
        bool is_open() const { return open_; }

        void async_read(packet_buffer& buf, std::function<void(boost::system::error_code, size_t)> handler) {
            handle_.async_read_some_at(0, boost::asio::buffer(buf.data(), buf.size()), std::move(handler));
        }

        void async_write(packet_buffer& buf, std::function<void(boost::system::error_code, size_t)> handler) {
            handle_.async_write_some_at(0, boost::asio::buffer(buf.data(), buf.size()), std::move(handler));
        }
    };

    std::variant<posix_impl, windows_impl> impl_;
};
```

---

### 5. TCP 协议引擎

本引擎在 TCP 处理上采取轻量级"尽力而为"策略，不进行数据缓存与重传，以最低开销完成 L3/L4 拦截。

#### 5.1 握手阶段

- 收到客户端 SYN 后，引擎分配一个 `tcp_minimal_state` 实例，记录 `irs = SYN.seq`。
- 引擎立即回复 SYN-ACK，携带本端 `iss`（随机生成）与固定 MSS 值（由 MTU 推导，默认 `MSS = MTU - 40`）。
- 收到客户端 ACK 后，状态切换为 `ESTABLISHED`，并触发 `tun_acceptor::async_accept` 完成事件。

#### 5.2 数据接收与转发

- **顺序检查**：收到数据段后，检查 `SEQ == rcv_nxt`。
  - **若顺序正确**：提取应用层 Payload，推送到 `tun_stream` 的读取队列中，唤醒挂起的 `async_read` 操作；随后 `rcv_nxt += payload_len`，并立即回复一个 ACK。
  - **若序列号超前（`SEQ > rcv_nxt`）**：引擎**不缓存**该数据段，直接丢弃，并回复一个 **Dup-ACK**（重复确认，携带期望的 `rcv_nxt`）。该机制会触发客户端内核的快速重传（Fast Retransmit），由客户端负责重发丢失的数据。
  - **若序列号小于 `rcv_nxt`**：视为重复包，直接丢弃，不回复任何内容。

#### 5.3 数据发送

- 应用层调用 `tun_stream::async_write` 时，引擎直接获取数据，封装为 TCP 载荷，分配 `snd_nxt` 序列号，构造 IP 包后通过 `packet_device::async_write_packet` 写入 TUN 设备。
- **不维护重传队列，不设置 RTO 定时器**。如果该数据包在传输途中丢失，客户端未收到响应时会主动重发之前的请求，引擎收到重发的请求后再重新生成响应，或由上层代理逻辑处理超时。

#### 5.4 接收窗口

- 引擎通告一个**固定的接收窗口**（65535 字节），不随内部缓冲区水位变化而动态调整。
- 若应用层消费不及时，队列积压达到上限时，引擎将静默丢弃后续到达的按序数据（不再回复 ACK），迫使客户端降低发送速率。

#### 5.5 连接终止

- 收到 FIN 段时，引擎回复 ACK，状态进入 `CLOSE_WAIT`，并向应用层指示 `EOF`。
- 当应用层关闭 `tun_stream` 时，引擎发送 FIN 段，完成四次挥手。
- 收到 RST 段时，直接销毁 TCB 并通知应用层连接重置。

---

### 6. UDP 协议引擎

UDP 引擎将无连接的 UDP 协议映射为有状态的会话，采用标准数据报语义。

#### 6.1 Datagram 语义

UDP 是数据报协议，其 API 严格遵循一次收发对应一个完整数据报的语义。一次 `async_receive` 返回且仅返回一个完整的原始 UDP Datagram（包含 UDP 头载荷）。

#### 6.2 新会话通知机制

当引擎收到一个属于未知五元组的 UDP 数据包时，会自动创建一个新的 `udp_session`，并将其加入一个**新会话通知队列**。上层应用通过 `tun_udp_acceptor::async_accept` 等待并获取这个新会话对应的 `tun_udp_socket` 对象。

#### 6.3 NAT 会话管理

- **映射表**：`std::unordered_map<five_tuple, std::shared_ptr<udp_session>>`，运行于 Strand 中。
- **会话结构**：

```cpp
struct udp_session {
    five_tuple key;
    std::queue<std::shared_ptr<packet_buffer>> rx_datagram_queue;
    std::chrono::steady_clock::time_point expiry;
    bool active = true;
};
```

- **老化策略**：采用**最小堆（Min-Heap）** 管理会话超时。堆顶元素为最早即将过期的会话，定时器仅等待堆顶超时，避免轮询扫描全表。每次收到数据包时更新会话的 `expiry` 并调整堆位置。

---

### 7. 公开异步 API 定义

所有 API 严格遵循 Boost.Asio 的 `async_initiate` 模型，保证与 `use_awaitable`、`use_future` 及自定义 CompletionToken 的完全兼容。

#### 7.1 `tun_stream`（TCP 虚拟流套接字）

```cpp
class tun_stream {
public:
    using executor_type = boost::asio::any_io_executor;

    explicit tun_stream(executor_type ex);
    ~tun_stream();

    tun_stream(tun_stream&&) noexcept;
    tun_stream& operator=(tun_stream&&) noexcept;

    executor_type get_executor() const noexcept;

    // 获取客户端请求的原始目标地址
    boost::asio::ip::tcp::endpoint original_destination() const;

    template <typename MutableBufferSequence, typename CompletionToken>
    auto async_read_some(MutableBufferSequence&& buffers, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(error_code, size_t)>(
            [this](auto handler, auto buffers) mutable {
                this->do_read_some(std::move(buffers), std::move(handler));
            },
            token,
            std::forward<MutableBufferSequence>(buffers)
        );
    }

    template <typename ConstBufferSequence, typename CompletionToken>
    auto async_write_some(ConstBufferSequence&& buffers, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(error_code, size_t)>(
            [this](auto handler, auto buffers) mutable {
                this->do_write_some(std::move(buffers), std::move(handler));
            },
            token,
            std::forward<ConstBufferSequence>(buffers)
        );
    }

    void shutdown(boost::asio::ip::tcp::socket::shutdown_type what, error_code& ec);
    void close();
    bool is_open() const noexcept;

private:
    class impl;
    std::shared_ptr<impl> impl_;
    friend class tun_acceptor;
};
```

#### 7.2 `tun_acceptor`（TCP 连接监听器）

`async_accept` 在三次握手完成（收到 ACK）时触发完成回调，此时连接处于 `ESTABLISHED` 状态。

```cpp
class tun_acceptor {
public:
    explicit tun_acceptor(tun_engine& engine);

    template <typename CompletionToken>
    auto async_accept(tun_stream& peer, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(error_code)>(
            [this, &peer](auto handler) {
                this->do_accept(peer, std::move(handler));
            },
            token
        );
    }
private:
    tun_engine& engine_;
};
```

#### 7.3 `tun_udp_socket`（UDP 数据报套接字）

```cpp
class tun_udp_socket {
public:
    using executor_type = boost::asio::any_io_executor;

    explicit tun_udp_socket(executor_type ex);
    ~tun_udp_socket();

    tun_udp_socket(tun_udp_socket&&) noexcept;
    tun_udp_socket& operator=(tun_udp_socket&&) noexcept;

    executor_type get_executor() const noexcept;

    // 获取该会话对应的五元组（客户端地址与目标地址）
    five_tuple remote_key() const;

    // 异步接收一个完整的数据报
    template <typename MutableBufferSequence, typename CompletionToken>
    auto async_receive(MutableBufferSequence&& buffers, CompletionToken&& token);

    // 异步发送一个完整的数据报
    template <typename ConstBufferSequence, typename CompletionToken>
    auto async_send(ConstBufferSequence&& buffers, CompletionToken&& token);

    // 设置会话空闲超时
    void set_timeout(std::chrono::seconds timeout);
    void close();
    bool is_open() const noexcept;

private:
    class impl;
    std::shared_ptr<impl> impl_;
    friend class tun_udp_acceptor;
};
```

#### 7.4 `tun_udp_acceptor`（UDP 新会话监听器）

`async_accept` 在引擎检测到新的 UDP 五元组流量时触发完成回调，并将新创建的 `tun_udp_socket` 传递给调用者。

```cpp
class tun_udp_acceptor {
public:
    explicit tun_udp_acceptor(tun_engine& engine);

    template <typename CompletionToken>
    auto async_accept(tun_udp_socket& peer, CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken, void(error_code)>(
            [this, &peer](auto handler) {
                this->do_accept(peer, std::move(handler));
            },
            token
        );
    }
private:
    tun_engine& engine_;
};
```

---

### 8. 错误处理与网络诊断支持

#### 8.1 后端连接失败处理

当引擎尝试连接后端代理失败时（如 `ECONNREFUSED`）：
- 由于客户端已收到 SYN-ACK 并进入 ESTABLISHED 状态，**绝不能**静默关闭连接。
- 引擎**必须**向客户端发送 TCP **RST** 包，强制客户端立即中断连接。

#### 8.2 ICMP Echo 响应

引擎自动响应发往自身虚拟 IP 地址的 ICMP Echo Request（Ping）：
- 识别 IP 协议字段为 1（ICMP）且 Type=8。
- 直接构造 Type=0（Echo Reply）的 ICMP 包，计算校验和，通过 `packet_device::async_write_packet` 写回，不经过上层应用层。

#### 8.3 统计接口

```cpp
struct engine_stats {
    std::atomic<uint64_t> rx_packets;
    std::atomic<uint64_t> tx_packets;
    std::atomic<uint64_t> rx_dropped;
    std::atomic<uint64_t> tcp_connections;
    std::atomic<uint64_t> udp_sessions;
    std::atomic<uint64_t> icmp_replies;
};

class tun_engine {
public:
    const engine_stats& stats() const noexcept;
};
```

---

### 9. 配置与资源限制

```cpp
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

    // ---- 可选 Checksum 硬件卸载控制 ----
    bool enable_checksum_offload = true;
};
```

**初始化逻辑**：
1. 若 `external_handle != invalid_native_handle`，引擎调用 `packet_device::assign(external_handle, external_mtu, ec)`。
2. 否则，引擎调用 `packet_device::open(cfg)`。
3. 所有内部表、定时器及 Strand 在构造时初始化。

---

### 10. 完整使用示例（C++20 Coroutine）

#### 10.1 TCP 全双工数据泵

```cpp
#include <boost/asio.hpp>
#include <iostream>
#include <memory>

namespace asio = boost::asio;

asio::awaitable<void> bidirectional_bridge(tun_stream client, asio::ip::tcp::socket proxy) {
    auto executor = co_await asio::this_coro::executor;
    auto client_ptr = std::make_shared<tun_stream>(std::move(client));
    auto proxy_ptr  = std::make_shared<asio::ip::tcp::socket>(std::move(proxy));

    asio::co_spawn(executor, [client_ptr, proxy_ptr]() -> asio::awaitable<void> {
        std::array<char, 8192> buf;
        try {
            for (;;) {
                size_t n = co_await client_ptr->async_read_some(asio::buffer(buf), asio::use_awaitable);
                co_await asio::async_write(*proxy_ptr, asio::buffer(buf, n), asio::use_awaitable);
            }
        } catch (...) { }
    }, asio::detached);

    asio::co_spawn(executor, [client_ptr, proxy_ptr]() -> asio::awaitable<void> {
        std::array<char, 8192> buf;
        try {
            for (;;) {
                size_t n = co_await proxy_ptr->async_read_some(asio::buffer(buf), asio::use_awaitable);
                co_await asio::async_write(*client_ptr, asio::buffer(buf, n), asio::use_awaitable);
            }
        } catch (...) { }
    }, asio::detached);

    co_return;
}

asio::awaitable<void> tcp_listener(tun_engine& engine) {
    tun_acceptor acceptor(engine);
    auto executor = co_await asio::this_coro::executor;

    for (;;) {
        tun_stream client(executor);
        co_await acceptor.async_accept(client, asio::use_awaitable);

        auto dest = client.original_destination();
        asio::ip::tcp::socket proxy(executor);
        co_await proxy.async_connect(dest, asio::use_awaitable);

        asio::co_spawn(executor, bidirectional_bridge(std::move(client), std::move(proxy)), asio::detached);
    }
}
```

#### 10.2 UDP 回显服务示例

```cpp
asio::awaitable<void> udp_echo_handler(tun_udp_socket session) {
    std::array<char, 2048> buf;
    try {
        for (;;) {
            size_t n = co_await session.async_receive(asio::buffer(buf), asio::use_awaitable);
            co_await session.async_send(asio::buffer(buf, n), asio::use_awaitable);
        }
    } catch (...) {
        session.close();
    }
}

asio::awaitable<void> udp_listener(tun_engine& engine) {
    tun_udp_acceptor acceptor(engine);
    auto executor = co_await asio::this_coro::executor;

    for (;;) {
        tun_udp_socket session(executor);
        co_await acceptor.async_accept(session, asio::use_awaitable);
        asio::co_spawn(executor, udp_echo_handler(std::move(session)), asio::detached);
    }
}
```

#### 10.3 主函数

```cpp
int main() {
    asio::io_context io_context(1);
    tun_engine engine(io_context);

    tun_config config;
    config.dev_name = "tun0";
    config.ipv4_addr = "10.0.0.1";
    config.netmask = "255.255.255.0";
    config.mtu = 1500;

    asio::error_code ec;
    if (!engine.open(config, ec)) {
        std::cerr << "Failed to open TUN: " << ec.message() << std::endl;
        return -1;
    }

    asio::co_spawn(io_context, tcp_listener(engine), asio::detached);
    asio::co_spawn(io_context, udp_listener(engine), asio::detached);
    io_context.run();
    return 0;
}
```

---

### 11. 实施路线图

| 阶段 | 周期 | 核心交付物 |
| :--- | :--- | :--- |
| **Phase 1：核心骨架** | 1.5 周 | 实现 `packet_device`（Linux）、自主打开与句柄注入、TCP 三次握手与 `async_accept`。 |
| **Phase 2：TCP/UDP 数据通路** | 1.5 周 | TCP 顺序转发与 Dup-ACK、UDP Datagram 收发、UDP 新会话通知与 `tun_udp_acceptor`。 |
| **Phase 3：跨平台适配** | 1 周 | macOS utun、Windows Wintun，验证句柄注入。 |
| **Phase 4：健壮性** | 1 周 | 资源上限、ICMP Ping、最小堆老化、统计接口、Strand 线程安全加固。 |

---

### 12. 总结

本设计文档定义了一个**极简、高性能且设备管理方式灵活**的用户态 TUN 网络引擎。其核心特征在于：

1. **统一的双模设备管理**：支持引擎自主打开设备与外部句柄注入，句柄注入时需显式指定 MTU 以确保 `packet_device` 返回正确参数。

2. **完全 Asio 风格的异步接口**：`packet_device` 的 I/O 及所有公开 API 均采用 `CompletionToken` 与 `async_initiate`，与 `use_awaitable`、`use_future` 等无缝协作。

3. **TCP 与 UDP 的对称抽象**：TCP 提供 `tun_stream`/`tun_acceptor`，UDP 提供 `tun_udp_socket`/`tun_udp_acceptor`，两者均遵循 Asio 的命名与行为习惯，降低学习成本。

4. **极低的协议开销**：放弃复杂的重传与重组，通过 Dup-ACK 触发客户端快速重传，将可靠性交还给对端内核，实现低 CPU 占用的高速转发。

5. **生产级线程安全**：所有内部状态通过 Strand 串行化，支持多线程 `io_context` 运行，无锁竞争。

该设计尤其适用于对转发延迟敏感、网络环境相对稳定或上层应用已具备重试机制的代理场景。

