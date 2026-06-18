#pragma once

#include <uv.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include "tx/net/tcp_server.h"
#include "tx/net/buffer.h"
#include "tx/crypto/aes_gcm.h"
#include "tx/protocol/tunnel.h"
#include "tx/protocol/socks5.h"
#include "tx/protocol/http_proxy.h"
#include "tx/router/router.h"
#include "config.h"

namespace tx {

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

private:
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
        bool                 connected;
        bool                 connect_result_sent;
        bool                 target_dispatched;
    };
    using ProxyConnPtr = std::shared_ptr<ProxyConn>;

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
    bool ensure_tunnel();
    void on_tunnel_read(Buffer& data);
    void on_tunnel_handshake_read(Buffer& data);
    void finish_tunnel_handshake(const std::vector<uint8_t>& server_nonce);
    void tunnel_send(ProxyConnPtr conn, const uint8_t* data, size_t len);
    void tunnel_send_connect(ProxyConnPtr conn);
    void tunnel_send_disconnect(ProxyConnPtr conn);
    void activate_tunnel_connection(ProxyConnPtr conn);
    void complete_tunnel_connection(ProxyConnPtr conn);
    void fail_tunnel_connection(ProxyConnPtr conn);
    void fail_pending_tunnel_connections();

    // DNS resolution for routing
    void resolve_and_route(ProxyConnPtr conn);

    // ---- Members ----
    uv_loop_t*         loop_;
    ClientConfig       config_;
    Router             router_;

    // Listeners
    TcpServer          http_server_;
    TcpServer          socks5_server_;

    // Tunnel to server
    SessionPtr         tunnel_session_;
    TunnelCodec        tunnel_codec_;
    std::vector<uint8_t> tunnel_master_key_;
    std::vector<uint8_t> tunnel_client_nonce_;
    Buffer             tunnel_handshake_buf_;
    bool               tunnel_connected_;
    bool               tunnel_connecting_;

    // Active connections by session ID
    std::unordered_map<SessionId, ProxyConnPtr> connections_;
    SessionId          next_session_id_;

    // Pending tunnel messages (before tunnel connects)
    Buffer             tunnel_send_buf_;
    std::vector<ProxyConnPtr> pending_tunnel_conns_;
};

} // namespace tx
