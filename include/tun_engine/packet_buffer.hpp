#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace tun_engine {

// 零拷贝数据包缓冲区：支持头部预留（Headroom）、前置头部与裁剪头部，
// 避免封装 IP/TCP 头部时频繁的内存分配与拷贝。
class packet_buffer {
public:
    explicit packet_buffer(size_t capacity = 2048, size_t headroom = 128)
        : storage_(new uint8_t[capacity]),
          capacity_(capacity),
          headroom_(headroom),
          data_offset_(headroom),
          data_size_(0) {}

    uint8_t* data() noexcept { return storage_.get() + data_offset_; }
    const uint8_t* data() const noexcept { return storage_.get() + data_offset_; }

    size_t size() const noexcept { return data_size_; }
    size_t capacity() const noexcept { return capacity_; }
    size_t headroom() const noexcept { return headroom_; }

    // 可写区域（供 async_read_packet 使用，读取成功后调用 commit）
    uint8_t* writable_data() noexcept { return storage_.get() + data_offset_ + data_size_; }
    size_t writable_size() const noexcept { return capacity_ - data_offset_ - data_size_; }

    // 复用缓冲区：回到初始状态
    void reset() noexcept {
        data_offset_ = headroom_;
        data_size_ = 0;
    }

    // 异步读取完成后推进数据长度
    void commit(size_t len) noexcept { data_size_ += len; }

    // 直接设定数据长度（写报文场景）
    void resize(size_t len) {
        if (len > tailroom()) {
            throw std::length_error("packet_buffer::resize exceeds capacity");
        }
        data_size_ = len;
    }

    // 零拷贝前置头部
    void prepend(size_t len) noexcept {
        data_offset_ -= len;
        data_size_ += len;
    }

    // 零拷贝裁剪头部
    void trim(size_t len) noexcept {
        data_offset_ += len;
        data_size_ -= len;
    }

    size_t headroom_available() const noexcept { return data_offset_; }
    size_t tailroom() const noexcept { return capacity_ - data_offset_ - data_size_; }

private:
    std::unique_ptr<uint8_t[]> storage_;
    size_t capacity_;
    size_t headroom_;
    size_t data_offset_;
    size_t data_size_;
};

} // namespace tun_engine
