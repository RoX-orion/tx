#pragma once

#include "tx/net/tcp_stream.h"

#include <cstddef>

namespace tx {

class TcpFlowBridge {
public:
    static constexpr size_t kHighWatermark = 4 * 1024 * 1024;
    static constexpr size_t kLowWatermark = 1024 * 1024;
    static constexpr size_t kHardLimit = 16 * 1024 * 1024;

    TcpFlowBridge(TcpStreamPtr left, TcpStreamPtr right);
    bool forward_from_left(Buffer& data);
    bool forward_from_right(Buffer& data);
    void on_left_writable();
    void on_right_writable();
    void left_eof();
    void right_eof();
    void reset();

private:
    bool forward(const TcpStreamPtr& source, const TcpStreamPtr& destination,
                 Buffer& data, bool& paused);
    TcpStreamPtr left_;
    TcpStreamPtr right_;
    bool left_paused_ = false;
    bool right_paused_ = false;
};

} // namespace tx
