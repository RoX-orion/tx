#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>
#include "tx/common/types.h"
#include "tx/net/buffer.h"

namespace tx {

// HTTP CONNECT proxy handler
// Parses the initial CONNECT request, extracts target, then tunnels data.
class HttpProxyHandler {
public:
    enum class Mode {
        Connect,
        Plain,
    };

    enum class State {
        Request,      // Parsing HTTP request line + headers
        Connected,    // Tunnel established, raw forwarding
        Error,
    };

    using TargetCallback = std::function<void(const TargetAddr& target)>;
    using DataCallback   = std::function<void(const uint8_t* data, size_t len)>;

    HttpProxyHandler();

    // Feed caller-owned accumulated data. Returns bytes consumed.
    size_t feed(const uint8_t* data, size_t len);

    // Build HTTP 200 response for CONNECT success
    void build_connect_response(Buffer& out);

    // Build HTTP error response
    void build_error_response(int status_code, Buffer& out);

    State state() const { return state_; }
    Mode mode() const { return mode_; }
    const TargetAddr& target() const { return target_; }
    const Buffer& initial_payload() const { return initial_payload_; }

    void set_target_callback(TargetCallback cb) { target_cb_ = std::move(cb); }

private:
    // Try to parse a complete HTTP CONNECT request from caller buffer
    bool try_parse_request(const uint8_t* data, size_t len);

    State state_;
    TargetAddr target_;
    TargetCallback target_cb_;
    size_t header_end_;       // Position after headers (start of body/tunnel data)
    Mode mode_;
    Buffer initial_payload_;
};

} // namespace tx
