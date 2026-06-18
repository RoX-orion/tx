#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>

namespace tx {

// Zero-copy friendly buffer with contiguous memory.
// Supports append, consume (from front), and direct pointer access.
class Buffer {
public:
    static constexpr size_t kInitialSize = 4096;
    static constexpr size_t kPrependSize = 8;  // space for header prepend

    explicit Buffer(size_t initial_size = kInitialSize)
        : buf_(kPrependSize + initial_size),
          read_pos_(kPrependSize),
          write_pos_(kPrependSize) {}

    // Readable data
    const uint8_t* data() const { return buf_.data() + read_pos_; }
    size_t readable() const { return write_pos_ - read_pos_; }
    bool empty() const { return readable() == 0; }

    // Writable space
    uint8_t* writable() { return buf_.data() + write_pos_; }
    size_t writable_bytes() const { return buf_.size() - write_pos_; }

    // Advance write position after external write
    void commit(size_t n) { write_pos_ += n; }

    // Consume n bytes from front
    void consume(size_t n) {
        if (n > readable()) n = readable();
        read_pos_ += n;
        if (read_pos_ == write_pos_) {
            read_pos_ = kPrependSize;
            write_pos_ = kPrependSize;
        }
    }

    // Peek without consuming
    void peek(uint8_t* dst, size_t n) const {
        if (n > readable()) n = readable();
        memcpy(dst, data(), n);
    }

    // Read and consume
    void read(uint8_t* dst, size_t n) {
        if (n > readable()) n = readable();
        memcpy(dst, data(), n);
        consume(n);
    }

    // Read as string
    std::string read_string(size_t n) {
        if (n > readable()) n = readable();
        std::string result(reinterpret_cast<const char*>(data()), n);
        consume(n);
        return result;
    }

    // Append data
    void append(const uint8_t* src, size_t n) {
        ensure_writable(n);
        memcpy(writable(), src, n);
        commit(n);
    }

    void append(const void* src, size_t n) {
        append(static_cast<const uint8_t*>(src), n);
    }

    void append(const std::string& s) {
        append(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    void append(const Buffer& other) {
        append(other.data(), other.readable());
    }

    // Prepend (for headers) — must have reserved space
    void prepend(const uint8_t* src, size_t n) {
        read_pos_ -= n;
        memcpy(buf_.data() + read_pos_, src, n);
    }

    // Access internal buffer for libuv
    char* uv_base() { return reinterpret_cast<char*>(writable()); }
    size_t uv_len() { return writable_bytes(); }

    // Shrink buffer if over-allocated
    void shrink() {
        if (buf_.size() > kInitialSize * 4 && readable() < kInitialSize) {
            std::vector<uint8_t> new_buf(kPrependSize + readable());
            memcpy(new_buf.data() + kPrependSize, data(), readable());
            buf_ = std::move(new_buf);
            write_pos_ = kPrependSize + readable();
            read_pos_ = kPrependSize;
        }
    }

    void clear() {
        read_pos_ = kPrependSize;
        write_pos_ = kPrependSize;
    }

private:
    void ensure_writable(size_t n) {
        if (writable_bytes() < n) {
            size_t new_cap = std::max(buf_.size() * 2, write_pos_ + n);
            buf_.resize(new_cap);
        }
    }

    std::vector<uint8_t> buf_;
    size_t read_pos_;
    size_t write_pos_;
};

} // namespace tx
