#include "tx/net/tun_write_queue.h"

#include <utility>

namespace tx {

TunWriteQueue::TunWriteQueue(size_t max_packets, size_t max_bytes)
    : max_packets_(max_packets), max_bytes_(max_bytes) {}

bool TunWriteQueue::can_push(size_t len) const {
    return max_packets_ != 0 && max_bytes_ != 0 &&
        packets_.size() < max_packets_ && len <= max_bytes_ - bytes_;
}

bool TunWriteQueue::push(const uint8_t* data, size_t len) {
    if ((!data && len != 0) || !can_push(len)) return false;
    Buffer packet(len);
    packet.append(data, len);
    bytes_ += len;
    packets_.push_back(std::move(packet));
    return true;
}

bool TunWriteQueue::push(Buffer&& packet) {
    const size_t len = packet.readable();
    if (!can_push(len)) return false;
    bytes_ += len;
    packets_.push_back(std::move(packet));
    return true;
}

void TunWriteQueue::pop() {
    if (packets_.empty()) return;
    bytes_ -= packets_.front().readable();
    packets_.pop_front();
}

void TunWriteQueue::clear() {
    packets_.clear();
    bytes_ = 0;
}

} // namespace tx
