#pragma once

#include "tx/common/types.h"
#include "tx/net/tcp_stream.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace tx {

class LwipTcpStream;

// UDP-only TUN frontend backed by HEV's lwIP Pretend UDP extension.
// All methods must be called from the owning libuv loop thread.
class LwipUdpStack {
public:
    using DatagramCallback = std::function<void(
        uint64_t flow_id, const IpAddr& source, const IpAddr& destination,
        const uint8_t* payload, size_t payload_len)>;
    using PacketOutputCallback =
        std::function<bool(const uint8_t* packet, size_t packet_len)>;
    using TcpAcceptCallback = std::function<void(
        const std::shared_ptr<LwipTcpStream>& stream,
        const IpAddr& source, const TargetAddr& target)>;

    LwipUdpStack();
    ~LwipUdpStack();

    LwipUdpStack(const LwipUdpStack&) = delete;
    LwipUdpStack& operator=(const LwipUdpStack&) = delete;

    bool initialize(const std::string& ipv4_cidr, int mtu,
                    DatagramCallback datagram_callback,
                    PacketOutputCallback output_callback,
                    std::string& error);
    bool initialize(const std::vector<std::string>& addresses, int mtu,
                    DatagramCallback datagram_callback,
                    TcpAcceptCallback tcp_accept_callback,
                    PacketOutputCallback output_callback,
                    std::string& error);
    void shutdown();

    // Returns true when the packet is a UDP IP packet accepted for processing.
    bool input(const uint8_t* packet, size_t packet_len);
    bool send_response(uint64_t flow_id, const IpAddr& source,
                       const uint8_t* payload, size_t payload_len);
    void close_flow(uint64_t flow_id);
    void poll_timers();
    uint32_t next_timeout_ms() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Raw lwIP TCP PCB exposed through the common stream contract. All methods
// run on the owning libuv loop thread.
class LwipTcpStream final : public TcpStream,
                            public std::enable_shared_from_this<LwipTcpStream> {
public:
    struct Impl;
    explicit LwipTcpStream(std::unique_ptr<Impl> impl);
    ~LwipTcpStream() override;
    bool write(const uint8_t* data, size_t len) override;
    bool write(Buffer& data) override;
    void pause_read() override;
    void resume_read() override;
    void shutdown_write() override;
    void close() override;
    void reset() override;
    size_t pending_write_bytes() const override;
    bool is_closed() const override;
    bool is_read_eof() const override;
    bool is_write_shutdown() const override;

    void set_data_callback(DataCallback callback);
    void set_writable_callback(EventCallback callback);
    void set_eof_callback(EventCallback callback);
    void set_close_callback(EventCallback callback);
    void set_error_callback(ErrorCallback callback);

    // Internal state is exposed to the owning stack implementation only; it
    // is not part of the stable public API.
    std::unique_ptr<Impl> impl_;
};

using LwipTunStack = LwipUdpStack;

} // namespace tx
