#pragma once

#include "tx/net/buffer.h"

#include <cstddef>
#include <deque>

namespace tx {

// Bounded FIFO for complete TUN packets. TUN devices preserve packet
// boundaries, so entries are always removed as a whole and never partially
// consumed.
class TunWriteQueue {
public:
    explicit TunWriteQueue(size_t max_packets = 4096,
                           size_t max_bytes = 4 * 1024 * 1024);

    bool push(const uint8_t* data, size_t len);
    bool push(Buffer&& packet);

    const Buffer& front() const { return packets_.front(); }
    void pop();
    void clear();

    bool empty() const { return packets_.empty(); }
    size_t packet_count() const { return packets_.size(); }
    size_t byte_count() const { return bytes_; }
    size_t max_packets() const { return max_packets_; }
    size_t max_bytes() const { return max_bytes_; }

private:
    bool can_push(size_t len) const;

    std::deque<Buffer> packets_;
    size_t bytes_ = 0;
    size_t max_packets_;
    size_t max_bytes_;
};

} // namespace tx
