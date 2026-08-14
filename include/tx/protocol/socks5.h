#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>
#include "tx/common/types.h"
#include "tx/net/buffer.h"

namespace tx {

// SOCKS5 protocol states
enum class Socks5State {
    Handshake,       // Waiting for auth method selection
    Auth,            // Username/password auth (not implemented yet)
    Request,         // Waiting for CONNECT/BIND/UDP request
    Connected,       // Tunnel established, forwarding data
    Error,
};

// SOCKS5 proxy handler for a single connection
class Socks5Handler {
public:
    using TargetCallback = std::function<void(const TargetAddr& target)>;
    using DataCallback   = std::function<void(const uint8_t* data, size_t len)>;
    enum class Command {
        Connect,
        UdpAssociate,
    };
    enum class FailureStage {
        None,
        MethodNegotiation,
        Request,
    };

    Socks5Handler();

    // Feed incoming data from the local client.
    // Returns number of bytes consumed. Calls target_cb_ when CONNECT request parsed.
    size_t feed(const uint8_t* data, size_t len);

    // Build SOCKS5 response for connect result
    void build_connect_response(bool success, Buffer& out,
                                const std::string& bind_host = "0.0.0.0",
                                uint16_t bind_port = 0);

    // State
    Socks5State state() const { return state_; }

    // Callbacks
    void set_target_callback(TargetCallback cb) { target_cb_ = std::move(cb); }

    // Get parsed target
    const TargetAddr& target() const { return target_; }
    Command command() const { return command_; }
    FailureStage failure_stage() const { return failure_stage_; }
    uint8_t failure_reply() const { return failure_reply_; }

private:
    size_t parse_handshake(const uint8_t* data, size_t len);
    size_t parse_request(const uint8_t* data, size_t len);

    Socks5State state_;
    TargetAddr  target_;
    Command     command_;
    FailureStage failure_stage_ = FailureStage::None;
    uint8_t failure_reply_ = 0x01;
    TargetCallback target_cb_;
};

} // namespace tx
