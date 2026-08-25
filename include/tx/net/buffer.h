#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <algorithm>
#include <limits>
#include <string>
#include <stdexcept>

namespace tx {

// Zero-copy friendly buffer with contiguous memory.
// Supports append, consume (from front), and direct pointer access.
class Buffer {
public:
    static constexpr size_t kInitialSize = 4096;
    static constexpr size_t kPrependSize = 8;  // space for header prepend

    explicit Buffer(size_t initial_size = kInitialSize)
        : buf_(checked_initial_size(initial_size)),
          read_pos_(kPrependSize),
          write_pos_(kPrependSize) {}

    // Readable data
    const uint8_t* data() const { return buf_.data() + read_pos_; }
    size_t readable() const { return write_pos_ - read_pos_; }
    bool empty() const { return readable() == 0; }

    // Writable space
    uint8_t* writable() { return buf_.data() + write_pos_; }
    size_t writable_bytes() const { return buf_.size() - write_pos_; }
    size_t capacity() const { return buf_.size(); }

    // Ensure a caller can fill a contiguous region and commit it once. This
    // avoids a temporary buffer for codecs that already know their output
    // size before encoding.
    void reserve_writable(size_t n) { ensure_writable(n); }

    // Advance write position after external write
    void commit(size_t n) {
        if (n > writable_bytes()) throw std::out_of_range("Buffer commit exceeds writable space");
        write_pos_ += n;
    }

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
        if (!src && n != 0) throw std::invalid_argument("Buffer append source is null");
        const uintptr_t source = reinterpret_cast<uintptr_t>(src);
        const uintptr_t begin = reinterpret_cast<uintptr_t>(buf_.data());
        const uintptr_t end = begin + buf_.size();
        if (n != 0 && source >= begin && source < end) {
            if (n > end - source)
                throw std::out_of_range("Buffer append source exceeds buffer storage");
            std::vector<uint8_t> snapshot(src, src + n);
            append(snapshot.data(), snapshot.size());
            return;
        }
        ensure_writable(n);
        if (n) memcpy(writable(), src, n);
        commit(n);
    }

    void append(const void* src, size_t n) {
        append(static_cast<const uint8_t*>(src), n);
    }

    void append(const std::string& s) {
        append(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    void append(const Buffer& other) {
        if (this == &other) {
            std::vector<uint8_t> snapshot(data(), data() + readable());
            append(snapshot.data(), snapshot.size());
            return;
        }
        append(other.data(), other.readable());
    }

    // Prepend (for headers) — must have reserved space
    void prepend(const uint8_t* src, size_t n) {
        if (!src && n != 0) throw std::invalid_argument("Buffer prepend source is null");
        if (n > read_pos_) throw std::out_of_range("Buffer prepend exceeds reserved space");
        read_pos_ -= n;
        if (n) memcpy(buf_.data() + read_pos_, src, n);
    }

    // Access internal buffer for libuv
    char* uv_base() { return reinterpret_cast<char*>(writable()); }
    size_t uv_len() { return writable_bytes(); }

    // Shrink buffer if over-allocated
    void shrink() {
        const size_t len = readable();
        if (buf_.size() > kInitialSize * 4 && len < kInitialSize) {
            std::vector<uint8_t> new_buf(kPrependSize + len);
            memcpy(new_buf.data() + kPrependSize, data(), len);
            buf_ = std::move(new_buf);
            write_pos_ = kPrependSize + len;
            read_pos_ = kPrependSize;
        }
    }

    void clear() {
        read_pos_ = kPrependSize;
        write_pos_ = kPrependSize;
    }

private:
    static size_t checked_initial_size(size_t initial_size) {
        if (initial_size > std::numeric_limits<size_t>::max() - kPrependSize)
            throw std::length_error("Buffer initial size overflow");
        return kPrependSize + initial_size;
    }

    void ensure_writable(size_t n) {
        if (writable_bytes() >= n) return;

        const size_t len = readable();
        if (len > std::numeric_limits<size_t>::max() - kPrependSize ||
            n > std::numeric_limits<size_t>::max() - kPrependSize - len) {
            throw std::length_error("Buffer size overflow");
        }
        const size_t required = kPrependSize + len + n;

        // Reclaim consumed space before growing.  Tunnel frames are commonly
        // split across reads, so relying on consume() to reach an exactly
        // empty buffer allows the write cursor to grow with total traffic.
        if (read_pos_ > kPrependSize && required <= buf_.size()) {
            memmove(buf_.data() + kPrependSize, data(), len);
            read_pos_ = kPrependSize;
            write_pos_ = kPrependSize + len;
            return;
        }

        const size_t doubled = buf_.size() > std::numeric_limits<size_t>::max() / 2
            ? std::numeric_limits<size_t>::max()
            : buf_.size() * 2;
        const size_t new_cap = std::max(doubled, required);
        std::vector<uint8_t> new_buf(new_cap);
        memcpy(new_buf.data() + kPrependSize, data(), len);
        buf_ = std::move(new_buf);
        read_pos_ = kPrependSize;
        write_pos_ = kPrependSize + len;
    }

    std::vector<uint8_t> buf_;
    size_t read_pos_;
    size_t write_pos_;
};

} // namespace tx
