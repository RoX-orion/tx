#include "tx/net/tcp_flow_bridge.h"

namespace tx {

TcpFlowBridge::TcpFlowBridge(TcpStreamPtr left, TcpStreamPtr right)
    : left_(std::move(left)), right_(std::move(right)) {}

bool TcpFlowBridge::forward(const TcpStreamPtr& source,
                            const TcpStreamPtr& destination,
                            Buffer& data, bool& paused) {
    if (!source || !destination || source->is_closed() || destination->is_closed())
        return false;
    if (destination->pending_write_bytes() + data.readable() > kHardLimit) {
        reset();
        return false;
    }
    if (!destination->write(data)) {
        reset();
        return false;
    }
    if (destination->pending_write_bytes() >= kHighWatermark && !paused) {
        source->pause_read();
        paused = true;
    }
    return true;
}

bool TcpFlowBridge::forward_from_left(Buffer& data) {
    return forward(left_, right_, data, left_paused_);
}
bool TcpFlowBridge::forward_from_right(Buffer& data) {
    return forward(right_, left_, data, right_paused_);
}
void TcpFlowBridge::on_left_writable() {
    if (right_paused_ && left_ && left_->pending_write_bytes() <= kLowWatermark) {
        right_paused_ = false;
        if (right_) right_->resume_read();
    }
}
void TcpFlowBridge::on_right_writable() {
    if (left_paused_ && right_ && right_->pending_write_bytes() <= kLowWatermark) {
        left_paused_ = false;
        if (left_) left_->resume_read();
    }
}
void TcpFlowBridge::left_eof() { if (right_) right_->shutdown_write(); }
void TcpFlowBridge::right_eof() { if (left_) left_->shutdown_write(); }
void TcpFlowBridge::reset() {
    if (left_ && !left_->is_closed()) left_->reset();
    if (right_ && !right_->is_closed()) right_->reset();
}

} // namespace tx
