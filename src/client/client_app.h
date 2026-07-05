#pragma once

#include <uv.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <deque>
#include <atomic>
#include "tx/net/tcp_server.h"
#include "tx/net/buffer.h"
#include "tx/protocol/tunnel.h"
#include "tx/protocol/socks5.h"
#include "tx/protocol/http_proxy.h"
#include "tx/router/router.h"
#include "config.h"

namespace tx {

struct ClientTrafficStats {
    uint64_t direct_upload_bytes;
    uint64_t direct_download_bytes;
    uint64_t proxy_upload_bytes;
    uint64_t proxy_download_bytes;
};

// Client application: runs HTTP/SOCKS5 proxies and tunnels traffic to server.
class ClientApp {
public:
    ClientApp();
    ~ClientApp();

    // Initialize with configuration
    bool init(const ClientConfig& config);

    // Run the event loop (blocks)
    int run();

    // Stop the event loop
    void stop();

    ClientTrafficStats traffic_stats() const;

private:
    struct RouteDnsCtx;
    struct TunnelTimerCtx;
    struct UdpResolveCtx;

    // ---- Proxy connection handling ----

    struct ProxyConn {
        SessionPtr           local_session;      // Connection from local app
        SessionPtr           tunnel_session;      // Connection to server (for proxy route)
        SessionPtr           direct_session;      // Direct connection (for direct route)
        std::unique_ptr<Socks5Handler>   socks5;
        std::unique_ptr<HttpProxyHandler> http;
        TargetAddr           target;
        RouteAction          route;
        SessionId            session_id;
        Buffer               pending_data;        // Data buffered before tunnel connected
        Buffer               proto_buf;           // Protocol parsing buffer (survives across reads)
        TunnelCodec          tunnel_codec;        // Per-proxy tunnel codec
        TunnelHandshakeState tunnel_handshake_state;
        Buffer               tunnel_handshake_buf;
        Buffer               tunnel_recv_buf;
        uv_timer_t*          tunnel_timer;
        bool                 connected;
        bool                 connect_result_sent;
        bool                 target_dispatched;
        bool                 tunnel_connected;
        bool                 tunnel_connecting;
    };
    using ProxyConnPtr = std::shared_ptr<ProxyConn>;

    struct PendingUdpPacket {
        SessionId session_id;
        TargetAddr target;
        std::vector<uint8_t> payload;
    };

    struct UdpFlow {
        SessionId session_id;
        sockaddr_storage client_addr;
        int client_addr_len;
    };

    struct UdpTunnel {
        SessionPtr tunnel_session;
        TunnelCodec codec;
        TunnelHandshakeState handshake_state;
        Buffer handshake_buf;
        Buffer recv_buf;
        bool connected = false;
        bool connecting = false;
        std::deque<PendingUdpPacket> pending;
    };

    // Accept handlers for HTTP and SOCKS5 listeners
    void on_http_accept(SessionPtr session);
    void on_socks5_accept(SessionPtr session);
    void on_proxy_read(ProxyConnPtr conn, Buffer& data);
    void on_proxy_close(ProxyConnPtr conn);

    // Target resolved callback (from SOCKS5/HTTP CONNECT parsing)
    void on_target_resolved(ProxyConnPtr conn);

    // Route decision
    void connect_direct(ProxyConnPtr conn);
    void connect_via_tunnel(ProxyConnPtr conn);

    // Tunnel connection
    bool start_tunnel(ProxyConnPtr conn);
    void on_tunnel_read(ProxyConnPtr conn, Buffer& data);
    void on_tunnel_handshake_read(ProxyConnPtr conn, Buffer& data);
    void finish_tunnel_handshake(ProxyConnPtr conn,
                                 const TunnelTrafficKeys& keys);
    void tunnel_send(ProxyConnPtr conn, const uint8_t* data, size_t len);
    void tunnel_send_connect(ProxyConnPtr conn);
    void tunnel_send_disconnect(ProxyConnPtr conn);
    void activate_tunnel_connection(ProxyConnPtr conn);
    void complete_tunnel_connection(ProxyConnPtr conn);
    void fail_tunnel_connection(ProxyConnPtr conn);
    void close_tunnel_session(ProxyConnPtr conn);
    void start_tunnel_timer(ProxyConnPtr conn, uint64_t timeout_ms, const char* phase);
    void stop_tunnel_timer(ProxyConnPtr conn);
    static void on_tunnel_timer(uv_timer_t* timer);
    static void on_tunnel_timer_closed(uv_handle_t* handle);

    // DNS resolution for routing
    void resolve_and_route(ProxyConnPtr conn);
    void resolve_domain_and_route(ProxyConnPtr conn);
    static void on_route_dns_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

    void record_traffic(RouteAction route, bool upload, size_t bytes);

    // SOCKS5 UDP ASSOCIATE / QUIC forwarding
    bool start_udp_listener();
    void stop_udp_listener();
    bool ensure_udp_tunnel();
    void send_udp_packet(SessionId sid, const TargetAddr& target,
                         const uint8_t* data, size_t len);
    void flush_pending_udp_packets();
    void on_udp_tunnel_handshake_read(Buffer& data);
    void on_udp_tunnel_read(Buffer& data);
    void close_udp_tunnel();
    static void on_udp_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void on_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                            const struct sockaddr* addr, unsigned flags);
    static void on_udp_send_done(uv_udp_send_t* req, int status);

    // ---- Members ----
    uv_loop_t*         loop_;
    ClientConfig       config_;
    Router             router_;

    // Listeners
    TcpServer          http_server_;
    TcpServer          socks5_server_;
    uv_udp_t           socks5_udp_;
    bool               socks5_udp_started_;
    UdpTunnel          udp_tunnel_;
    std::unordered_map<std::string, UdpFlow> udp_flows_;
    std::unordered_map<SessionId, std::string> udp_session_keys_;

    // Tunnel crypto
    std::vector<uint8_t> tunnel_psk_;

    // Active connections by session ID
    std::unordered_map<SessionId, ProxyConnPtr> connections_;
    SessionId          next_session_id_;

    std::atomic<uint64_t> direct_upload_bytes_;
    std::atomic<uint64_t> direct_download_bytes_;
    std::atomic<uint64_t> proxy_upload_bytes_;
    std::atomic<uint64_t> proxy_download_bytes_;
};

} // namespace tx
