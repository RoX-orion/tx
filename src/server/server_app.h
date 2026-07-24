#pragma once

#include <uv.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <atomic>
#include "tx/net/tcp_server.h"
#include "tx/net/buffer.h"
#include "tx/protocol/tunnel.h"
#include "config.h"

namespace tx {

// Server application: accepts tunnel connections from clients,
// decrypts requests, and proxies traffic to the target.
class ServerApp {
public:
    ServerApp();
    ~ServerApp();

    bool init(const ServerConfig& config);
    int run();
    void stop();

    uv_loop_t* loop() const { return loop_; }

private:
    // A tunnel session from one client
    struct TunnelClient {
        SessionPtr       session;
        TunnelCodec      codec;
        Buffer           handshake_buf;
        Buffer           recv_buf;
        bool             closed = false;
        bool             authenticated = false;
        std::string      source_ip;
        uv_timer_t*      handshake_timer = nullptr;
        uint64_t         rate_window_started_ms = 0;
        uint64_t         rate_window_bytes = 0;
        bool             outbounds_paused = false;
        bool             inbound_paused = false;
        uint64_t         next_tcp_generation = 1;
        uint64_t         next_udp_generation = 1;

        // Outbound connections by session ID
        struct Outbound {
            SessionPtr remote_session;
            SessionId  session_id;
            uint64_t   generation;
            Buffer     pending_data;   // buffered before remote connected
            bool       connected;      // remote fully connected?
            bool       client_eof = false;
            bool       remote_eof = false;
        };
        struct UdpOutbound {
            uv_udp_t* udp;
            SessionId session_id;
            uint64_t generation;
            uint64_t last_activity_ms;
        };
        std::unordered_map<SessionId, Outbound> outbounds;
        std::unordered_map<SessionId, UdpOutbound> udp_outbounds;
    };
    using TunnelClientPtr = std::shared_ptr<TunnelClient>;

    struct UdpCtx {
        ServerApp* app;
        TunnelClientPtr client;
        SessionId sid;
        uint64_t generation;
    };
    struct UdpResolveCtx {
        ServerApp* app;
        TunnelClientPtr client;
        SessionId sid;
        uint64_t generation;
        TargetAddr target;
        std::vector<uint8_t> payload;
    };
    struct HandshakeTimerCtx {
        ServerApp* app;
        TunnelClientPtr client;
    };

    void on_tunnel_accept(SessionPtr session);
    void on_tunnel_handshake_read(TunnelClientPtr client, Buffer& data);
    void on_tunnel_read(TunnelClientPtr client, Buffer& data);
    void on_tunnel_close(TunnelClientPtr client);

    // Handle decoded tunnel message
    void handle_connect(TunnelClientPtr client, SessionId sid, const TargetAddr& target);
    void handle_data(TunnelClientPtr client, SessionId sid, Buffer& payload);
    void handle_udp_packet(TunnelClientPtr client, SessionId sid,
                           const TargetAddr& target, Buffer& payload);
    void handle_disconnect(TunnelClientPtr client, SessionId sid);
    void handle_half_close(TunnelClientPtr client, SessionId sid);
    bool start_udp_cleanup_timer();
    void stop_udp_cleanup_timer();
    void cleanup_idle_udp_outbounds(uint64_t now_ms);
    bool consume_client_rate(TunnelClientPtr client, size_t bytes);
    void start_handshake_timer(TunnelClientPtr client);
    void stop_handshake_timer(TunnelClientPtr client);

    // Send encrypted data back to client
    void tunnel_send_data(TunnelClientPtr client, SessionId sid,
                          const uint8_t* data, size_t len);
    void tunnel_send_udp_packet(TunnelClientPtr client, SessionId sid,
                                const TargetAddr& target,
                                const uint8_t* data, size_t len);
    void tunnel_send_disconnect(TunnelClientPtr client, SessionId sid);
    void tunnel_send_half_close(TunnelClientPtr client, SessionId sid);
    void tunnel_send_connect_result(TunnelClientPtr client, SessionId sid, bool success);
    void pause_outbound_reads(TunnelClientPtr client);
    void resume_outbound_reads(TunnelClientPtr client);
    static void udp_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void on_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                            const struct sockaddr* addr, unsigned flags);
    static void on_udp_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
    static void on_udp_send_done(uv_udp_send_t* req, int status);
    static void on_udp_closed(uv_handle_t* handle);
    static void on_udp_cleanup_timer(uv_timer_t* timer);
    static void on_handshake_timer(uv_timer_t* timer);
    static void on_handshake_timer_closed(uv_handle_t* handle);
    void stop_on_loop();
    static void on_stop_async(uv_async_t* handle);

    std::unique_ptr<uv_loop_t> owned_loop_;
    uv_loop_t*         loop_;
    bool               loop_closed_;
    ServerConfig       config_;
    TcpServer          server_;
    uv_timer_t         udp_cleanup_timer_;
    bool               udp_cleanup_timer_started_;
    uv_async_t         stop_async_;
    bool               stop_async_initialized_;
    bool               ready_to_run_;
    std::atomic<bool>  stop_requested_;
    bool               stopping_;

    // Active tunnel clients
    std::unordered_map<uv_tcp_t*, TunnelClientPtr> clients_;
    std::unordered_map<std::string, uint32_t> unauthenticated_by_ip_;
    uint64_t new_client_window_started_ms_ = 0;
    uint32_t new_client_window_count_ = 0;
};

} // namespace tx
