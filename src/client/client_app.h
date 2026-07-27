#pragma once

#include <uv.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <atomic>
#include "platform_tun.h"
#include "tx/net/tcp_server.h"
#include "tx/net/buffer.h"
#include "tx/protocol/tunnel.h"
#include "tx/protocol/socks5.h"
#include "tx/protocol/http_proxy.h"
#include "tx/net/lwip_udp_stack.h"
#include "tx/net/fake_ip_dns.h"
#include "tx/net/tcp_flow_bridge.h"
#include "tx/net/dns_resolver.h"
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
    explicit ClientApp(SocketProtectCallback socket_protector = SocketProtectCallback(),
                       DnsResolver::HostResolveHook host_resolver = DnsResolver::HostResolveHook(),
                       DnsResolver::QueryHook dns_query = DnsResolver::QueryHook());
    ~ClientApp();

    // Initialize with configuration
    bool init(const ClientConfig& config);

    // Run the event loop (blocks)
    int run();

    // The application owns this loop. Command-line signal watchers must use
    // it instead of uv_default_loop().
    uv_loop_t* loop() const { return loop_; }

    // Stop the event loop
    void stop();
    void notify_network_changed();

    ClientTrafficStats traffic_stats() const;

private:
    friend struct ClientAppDnsTest;

    struct TunnelTimerCtx;
    struct DirectUdpRelay;

    // ---- Proxy connection handling ----

    struct ProxyConn {
        TcpStreamPtr         local_session;      // proxy socket or lwIP TUN stream
        SessionPtr           tunnel_session;      // Connection to server (for proxy route)
        SessionPtr           direct_session;      // Direct connection (for direct route)
        std::shared_ptr<TcpFlowBridge> bridge;
        std::unique_ptr<Socks5Handler>   socks5;
        std::unique_ptr<HttpProxyHandler> http;
        TargetAddr           target;
        std::string          resolved_host;
        RouteAction          route;
        const OutboundConfig* outbound;
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
        bool                 fake_ip_target = false;
        bool                 local_eof = false;
        bool                 local_half_close_sent = false;
        bool                 remote_eof = false;
        bool                 local_paused_for_tunnel = false;
        bool                 tunnel_paused_for_local = false;
        bool                 admitted = false;
    };
    using ProxyConnPtr = std::shared_ptr<ProxyConn>;

    struct PendingUdpPacket {
        SessionId session_id;
        TargetAddr target;
        std::vector<uint8_t> payload;
    };

    enum class UdpFlowKind {
        Socks5,
        Tun,
        InternalDns,
    };

    enum class InternalDnsStage {
        Udp,
        TcpConnect,
        TcpResponse,
    };

    struct UdpFlow {
        SessionId session_id;
        UdpFlowKind kind = UdpFlowKind::Socks5;
        sockaddr_storage client_addr;
        int client_addr_len;
        IpAddr tun_src_ip;
        IpAddr tun_dst_ip;
        uint64_t lwip_flow_id = 0;
        DirectUdpRelay* direct_relay = nullptr;
        uint64_t last_activity_ms = 0;
        const OutboundConfig* outbound = nullptr;
        size_t pending_proxy_bytes = 0;
        bool proxied = false;
        DnsResolver::ResolveCallback dns_callback;
        std::vector<uint8_t> dns_query;
        size_t dns_upstream_index = 0;
        TargetAddr dns_upstream;
        InternalDnsStage dns_stage = InternalDnsStage::Udp;
        uint64_t dns_deadline_ms = 0;
        Buffer dns_tcp_response;
    };

    struct UdpTunnel {
        SessionPtr tunnel_session;
        const OutboundConfig* outbound = nullptr;
        TunnelCodec codec;
        TunnelHandshakeState handshake_state;
        Buffer handshake_buf;
        Buffer recv_buf;
        bool connected = false;
        bool connecting = false;
        std::deque<PendingUdpPacket> pending;
        size_t pending_bytes = 0;
    };
    using UdpTunnelPtr = std::shared_ptr<UdpTunnel>;

    // Accept handlers for HTTP and SOCKS5 listeners
    void on_http_accept(SessionPtr session);
    void on_socks5_accept(SessionPtr session);
    void on_proxy_read(ProxyConnPtr conn, Buffer& data);
    void on_proxy_close(ProxyConnPtr conn);
    bool admit_proxy_connection(ProxyConnPtr conn);
    SessionId allocate_session_id();
    void release_session_id(SessionId session_id);

    // Target resolved callback (from SOCKS5/HTTP CONNECT parsing)
    void on_target_resolved(ProxyConnPtr conn);

    // Route decision
    void connect_direct(ProxyConnPtr conn);
    void connect_direct_candidates(ProxyConnPtr conn,
                                   std::shared_ptr<std::vector<std::string>> addresses,
                                   size_t index);
    void connect_via_tunnel(ProxyConnPtr conn);
    const OutboundConfig* find_outbound(const std::string& tag) const;
    bool apply_route_decision(ProxyConnPtr conn, const RouteDecision& decision);
    void block_connection(ProxyConnPtr conn);

    // Tunnel connection
    bool start_tunnel(ProxyConnPtr conn);
    void connect_tunnel_candidates(ProxyConnPtr conn,
                                   std::shared_ptr<std::vector<std::string>> addresses,
                                   size_t index);
    void on_tunnel_read(ProxyConnPtr conn, Buffer& data);
    void on_tunnel_handshake_read(ProxyConnPtr conn, Buffer& data);
    void finish_tunnel_handshake(ProxyConnPtr conn,
                                 const TunnelTrafficKeys& keys);
    void tunnel_send(ProxyConnPtr conn, const uint8_t* data, size_t len);
    void tunnel_send_connect(ProxyConnPtr conn);
    void tunnel_send_disconnect(ProxyConnPtr conn);
    void tunnel_send_half_close(ProxyConnPtr conn);
    void on_local_eof(ProxyConnPtr conn);
    void activate_tunnel_connection(ProxyConnPtr conn);
    void complete_tunnel_connection(ProxyConnPtr conn);
    void fail_tunnel_connection(ProxyConnPtr conn);
    void close_tunnel_session(ProxyConnPtr conn);
    void start_tunnel_timer(ProxyConnPtr conn, uint64_t timeout_ms, const char* phase);
    void stop_tunnel_timer(ProxyConnPtr conn);
    static void on_tunnel_timer(uv_timer_t* timer);
    static void on_tunnel_timer_closed(uv_handle_t* handle);

    // Routing is decided from the original host. Domain resolution occurs only
    // after a direct outbound has been selected.
    void resolve_and_route(ProxyConnPtr conn);

    void record_traffic(RouteAction route, bool upload, size_t bytes);

    // SOCKS5 UDP ASSOCIATE / QUIC forwarding
    bool start_proxy_listeners();
    bool start_udp_listener();
    void stop_udp_listener();
    UdpTunnelPtr get_udp_tunnel(const OutboundConfig* outbound);
    bool ensure_udp_tunnel(const UdpTunnelPtr& tunnel);
    void connect_udp_tunnel_candidates(
        const UdpTunnelPtr& tunnel,
        std::shared_ptr<std::vector<std::string>> addresses, size_t index);
    void send_udp_packet(const UdpTunnelPtr& tunnel, SessionId sid, const TargetAddr& target,
                         const uint8_t* data, size_t len);
    void resolve_dns_via_tunnel(std::vector<uint8_t> query,
                                DnsResolver::ResolveCallback callback);
    bool parse_dns_upstream(const std::string& upstream, TargetAddr& target) const;
    void start_internal_dns_attempt(const std::string& flow_key);
    void retry_internal_dns(const std::string& flow_key, const char* reason);
    void start_internal_dns_tcp(const std::string& flow_key,
                                const UdpTunnelPtr& tunnel);
    void send_internal_dns_tcp_query(const std::string& flow_key,
                                     const UdpTunnelPtr& tunnel);
    void handle_internal_dns_udp_response(const std::string& flow_key,
                                          const UdpTunnelPtr& tunnel,
                                          const TargetAddr& source,
                                          const uint8_t* data, size_t len);
    void handle_internal_dns_tcp_data(const std::string& flow_key,
                                      const uint8_t* data, size_t len);
    void complete_internal_dns(const std::string& flow_key,
                               std::vector<uint8_t> response,
                               bool notify_peer);
    bool rotate_internal_dns_session(const std::string& flow_key);
    void discard_pending_udp_packets(const UdpTunnelPtr& tunnel, SessionId sid);
    bool send_shared_tunnel_disconnect(const UdpTunnelPtr& tunnel, SessionId sid);
    void arm_internal_dns_timer();
    void stop_internal_dns_timer();
    bool ensure_direct_udp_relay(const std::string& flow_key, UdpFlow& flow,
                                 int target_family);
    void send_direct_udp_packet(const std::string& flow_key, UdpFlow& flow,
                                const TargetAddr& target,
                                const uint8_t* data, size_t len);
    void close_direct_udp_relay(UdpFlow& flow);
    bool start_udp_cleanup_timer();
    void stop_udp_cleanup_timer();
    void cleanup_idle_udp_flows(uint64_t now_ms);
    void remove_udp_flow(const std::string& flow_key, bool notify_peer);
    void send_udp_response_to_flow(const UdpFlow& flow, const TargetAddr& source,
                                   const uint8_t* data, size_t len,
                                   RouteAction route);
    void flush_pending_udp_packets(const UdpTunnelPtr& tunnel);
    void on_udp_tunnel_handshake_read(const UdpTunnelPtr& tunnel, Buffer& data);
    void on_udp_tunnel_read(const UdpTunnelPtr& tunnel, Buffer& data);
    void close_udp_tunnel(const UdpTunnelPtr& tunnel);
    void close_all_udp_tunnels();
    static void on_udp_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void on_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                            const struct sockaddr* addr, unsigned flags);
    static void on_udp_send_done(uv_udp_send_t* req, int status);
    static void on_direct_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                                   const struct sockaddr* addr, unsigned flags);
    static void on_direct_udp_closed(uv_handle_t* handle);
    static void on_udp_cleanup_timer(uv_timer_t* timer);
    static void on_internal_dns_timer(uv_timer_t* timer);

    // Native TUN input. Mixed mode currently handles UDP packets natively and
    // keeps TCP on the configured system-stack path.
    bool start_tun_listener();
    void stop_tun_listener();
    bool start_tun_tcp_redirect();
    void stop_tun_tcp_redirect();
    void on_tun_tcp_accept(SessionPtr session);
    void on_lwip_tcp_accept(const std::shared_ptr<LwipTcpStream>& stream,
                            const IpAddr& source, const TargetAddr& target);
    void drain_tun_packets();
    void handle_tun_packet(const uint8_t* data, size_t len);
    void handle_lwip_udp_datagram(uint64_t flow_id, const IpAddr& source,
                                  const IpAddr& destination,
                                  const uint8_t* data, size_t len);
    bool write_tun_udp_packet(const UdpFlow& flow, const TargetAddr& source,
                              const uint8_t* data, size_t len);
    static void on_tun_poll(uv_poll_t* handle, int status, int events);
    static void on_tun_timer(uv_timer_t* timer);

    // Cross-thread shutdown. Public stop requests are delivered through this
    // async handle so every libuv handle is closed by its owning loop thread.
    void stop_on_loop();
    static void on_stop_async(uv_async_t* handle);
    void network_changed_on_loop();
    static void on_network_async(uv_async_t* handle);

    // ---- Members ----
    // Keep the storage before every loop-bound member so it outlives their
    // destructors. Each app instance needs a private loop: libuv handles
    // cannot be driven concurrently from a shared default loop.
    std::unique_ptr<uv_loop_t> owned_loop_;
    uv_loop_t*         loop_;
    bool               loop_closed_;
    uv_async_t         stop_async_;
    uv_async_t         network_async_;
    bool               stop_async_initialized_;
    bool               network_async_initialized_;
    bool               ready_to_run_;
    std::atomic<bool>  stop_requested_;
    bool               stopping_;
    ClientConfig       config_;
    Router             router_;
    FakeIpDns          fake_ip_dns_;
    DnsResolver         dns_resolver_;

    // Listeners
    TcpServer          http_server_;
    TcpServer          socks5_server_;
    TcpServer          tun_tcp_server_;
    uv_udp_t           socks5_udp_;
    bool               socks5_udp_started_;
    int                tun_fd_;
    bool               tun_started_;
    uv_poll_t          tun_poll_;
    uv_timer_t         tun_timer_;
    bool               tun_timer_started_;
    bool               tun_tcp_redirect_started_;
    std::unique_ptr<PlatformTunDevice> tun_device_;
    LwipUdpStack       lwip_udp_stack_;
    std::vector<uint8_t> tun_read_buf_;
    std::unordered_map<std::string, UdpTunnelPtr> udp_tunnels_;
    std::unordered_map<std::string, UdpFlow> udp_flows_;
    std::unordered_map<SessionId, std::string> udp_session_keys_;
    uv_timer_t         udp_cleanup_timer_;
    bool               udp_cleanup_timer_started_;
    uv_timer_t         internal_dns_timer_;
    bool               internal_dns_timer_initialized_;

    // Active connections by session ID
    std::unordered_map<SessionId, ProxyConnPtr> connections_;
    SessionId          next_session_id_;
    std::unordered_set<SessionId> active_session_ids_;
    size_t             active_proxy_connections_ = 0;

    std::atomic<uint64_t> direct_upload_bytes_;
    std::atomic<uint64_t> direct_download_bytes_;
    std::atomic<uint64_t> proxy_upload_bytes_;
    std::atomic<uint64_t> proxy_download_bytes_;
    SocketProtectCallback socket_protector_;
    DnsResolver::HostResolveHook host_resolver_;
    DnsResolver::QueryHook dns_query_;
};

} // namespace tx
