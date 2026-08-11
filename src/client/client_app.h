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
#include "tx/protocol/quic_sni.h"
#include "tx/net/lwip_udp_stack.h"
#include "tx/net/fake_ip_dns.h"
#include "tx/net/tcp_flow_bridge.h"
#include "tx/net/dns_resolver.h"
#include "tx/router/router.h"
#include "config.h"

namespace tx {

// Android reports whether the selected physical Network has a usable default
// route for each address family. A zero mask means "unknown" for backwards
// compatibility, while the known bit distinguishes that from a network which
// currently has no usable IP egress route.
constexpr uint32_t kAndroidNetworkAddressFamilyIPv4 = 1u << 0;
constexpr uint32_t kAndroidNetworkAddressFamilyIPv6 = 1u << 1;
constexpr uint32_t kAndroidNetworkAddressFamilyKnown = 1u << 31;

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
                       DnsResolver::QueryHook dns_query = DnsResolver::QueryHook(),
                       uint32_t android_address_family_mask = 0);
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
    void update_android_address_family_mask(uint32_t mask);

    ClientTrafficStats traffic_stats() const;

private:
    friend struct ClientAppDnsTest;
    friend struct ClientAppUdpMuxTest;
    friend struct ClientAppTcpTest;
    friend struct ClientAppQuicTest;
    friend struct ClientAppNetworkTest;

    struct TunnelTimerCtx;
    struct DirectUdpRelay;
    struct UdpTunnelRetryCtx;
    struct UdpTunnelHandshakeCtx;

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
        bool                 local_paused_for_connect = false;
        bool                 tunnel_paused_for_local = false;
        bool                 admitted = false;
    };
    using ProxyConnPtr = std::shared_ptr<ProxyConn>;

    struct PendingUdpPacket {
        SessionId session_id;
        TargetAddr target;
        std::vector<uint8_t> payload;
        bool dns_query = false;
    };

    enum class UdpFlowKind {
        Socks5,
        Tun,
        InternalDns,
    };

    // DNS must not wait behind QUIC or other bulk UDP frames on the shared
    // TCP transport. Each TX outbound therefore owns a data tunnel and a
    // separate DNS tunnel.
    enum class UdpTunnelKind {
        Data,
        Dns,
    };

    struct UdpFlow {
        SessionId session_id;
        UdpFlowKind kind = UdpFlowKind::Socks5;
        sockaddr_storage client_addr;
        int client_addr_len;
        IpAddr tun_src_ip;
        IpAddr tun_dst_ip;
        // The application sent this flow to a fake address.  Replies must
        // retain that fake address as their TUN source so connected UDP
        // sockets (notably QUIC) accept them.
        bool fake_ip_target = false;
        uint64_t lwip_flow_id = 0;
        DirectUdpRelay* direct_relay = nullptr;
        // A UDP flow that started with a domain must use one resolved peer for
        // its entire lifetime.  This keeps QUIC packets on the same CDN node
        // and prevents concurrent datagrams from reordering around DNS.
        TargetAddr direct_resolution_target;
        TargetAddr direct_send_target;
        bool direct_target_resolving = false;
        std::deque<std::vector<uint8_t>> direct_resolution_packets;
        size_t direct_resolution_bytes = 0;
        uint64_t last_activity_ms = 0;
        const OutboundConfig* outbound = nullptr;
        std::string udp_tunnel_key;
        size_t pending_proxy_bytes = 0;
        bool proxied = false;
        // TUN QUIC routing can use a recovered domain while retaining the
        // original numeric destination. SNI is a routing hint only; packets
        // continue to use send_target on the wire.
        TargetAddr route_target;
        TargetAddr send_target;
        bool route_ready = false;
        std::unique_ptr<QuicSniSniffer> quic_sniffer;
        std::string quic_initial_dcid;
        std::deque<std::vector<uint8_t>> quic_pending_packets;
        size_t quic_pending_bytes = 0;
        uint64_t quic_sniff_deadline_ms = 0;
        DnsResolver::ResolveCallback dns_callback;
        std::vector<uint8_t> dns_query;
        uint64_t dns_deadline_ms = 0;
    };

    struct UdpTunnel {
        SessionPtr tunnel_session;
        const OutboundConfig* outbound = nullptr;
        UdpTunnelKind kind = UdpTunnelKind::Data;
        std::string key;
        bool dedicated = false;
        SessionId owner_session_id = 0;
        TunnelCodec codec;
        TunnelHandshakeState handshake_state;
        Buffer handshake_buf;
        Buffer recv_buf;
        bool connected = false;
        bool connecting = false;
        uv_timer_t* retry_timer = nullptr;
        uv_timer_t* handshake_timer = nullptr;
        uint32_t retry_delay_ms = 0;
        std::deque<PendingUdpPacket> pending;
        size_t pending_bytes = 0;
    };
    using UdpTunnelPtr = std::shared_ptr<UdpTunnel>;

    // DNS UDP sockets are long lived on Android. Multiple queries can share
    // one lwIP PCB, so their lifetimes must not be tied to the first reply.
    struct TunDnsFlow {
        uint64_t generation = 0;
        IpAddr destination;
        uint64_t last_activity_ms = 0;
        size_t pending_queries = 0;
    };

    struct QuicRouteCacheEntry {
        TargetAddr route_target;
        const OutboundConfig* outbound = nullptr;
        uint64_t expires_at_ms = 0;
        uint64_t last_used_at_ms = 0;
    };

    // Accept handlers for HTTP and SOCKS5 listeners
    void on_http_accept(SessionPtr session);
    void on_socks5_accept(SessionPtr session);
    void bind_proxy_target_callback(ProxyConnPtr conn);
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
    bool android_address_family_available(int family) const;
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
    bool append_lwip_tcp_data(ProxyConnPtr conn, Buffer& data);
    void release_local_read(ProxyConnPtr conn);
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
    bool normalize_fake_ip_target(TargetAddr& target, const char* context);
    void resolve_and_route(ProxyConnPtr conn);

    void record_traffic(RouteAction route, bool upload, size_t bytes);

    // SOCKS5 UDP ASSOCIATE / QUIC forwarding
    bool start_proxy_listeners();
    bool start_udp_listener();
    void stop_udp_listener();
    UdpTunnelPtr get_udp_tunnel(const OutboundConfig* outbound,
                                UdpTunnelKind kind = UdpTunnelKind::Data,
                                const std::string& key = std::string());
    UdpTunnelPtr select_udp_tunnel(UdpFlow& flow);
    bool ensure_udp_tunnel(const UdpTunnelPtr& tunnel);
    void connect_udp_tunnel_candidates(
        const UdpTunnelPtr& tunnel,
        std::shared_ptr<std::vector<std::string>> addresses, size_t index);
    void send_udp_packet(const UdpTunnelPtr& tunnel, SessionId sid, const TargetAddr& target,
                         const uint8_t* data, size_t len);
    void send_dns_query(const UdpTunnelPtr& tunnel, SessionId sid,
                        const uint8_t* data, size_t len);
    void resolve_dns_via_tunnel(std::vector<uint8_t> query,
                                DnsResolver::ResolveCallback callback);
    void start_dns_tunnel_query(std::vector<uint8_t> query,
                                DnsResolver::ResolveCallback callback,
                                const OutboundConfig* outbound);
    void start_internal_dns_attempt(const std::string& flow_key);
    void retry_internal_dns(const std::string& flow_key, const char* reason);
    void complete_internal_dns(const std::string& flow_key,
                               std::vector<uint8_t> response,
                               bool notify_peer);
    void discard_pending_udp_packets(const UdpTunnelPtr& tunnel, SessionId sid);
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
    void cleanup_idle_tun_dns_flows(uint64_t now_ms);
    void close_all_tun_dns_flows();
    void remove_udp_flow(const std::string& flow_key, bool notify_peer);
    void send_udp_response_to_flow(const UdpFlow& flow, const TargetAddr& source,
                                   const uint8_t* data, size_t len,
                                   RouteAction route);
    void flush_pending_udp_packets(const UdpTunnelPtr& tunnel);
    void on_udp_tunnel_handshake_read(const UdpTunnelPtr& tunnel, Buffer& data);
    void on_udp_tunnel_read(const UdpTunnelPtr& tunnel, Buffer& data);
    void close_udp_tunnel(const UdpTunnelPtr& tunnel, bool retry_pending = false);
    void close_all_udp_tunnels();
    void schedule_udp_tunnel_retry(const UdpTunnelPtr& tunnel);
    void cancel_udp_tunnel_retry(const UdpTunnelPtr& tunnel);
    bool start_udp_tunnel_handshake_timer(const UdpTunnelPtr& tunnel);
    void cancel_udp_tunnel_handshake_timer(const UdpTunnelPtr& tunnel);
    static void on_udp_tunnel_retry(uv_timer_t* timer);
    static void on_udp_tunnel_retry_closed(uv_handle_t* handle);
    static void on_udp_tunnel_handshake_timeout(uv_timer_t* timer);
    static void on_udp_tunnel_handshake_timer_closed(uv_handle_t* handle);
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
    bool finalize_tun_udp_route(UdpFlow& flow, const TargetAddr& route_target,
                                const TargetAddr& send_target);
    bool inherit_tun_quic_route(UdpFlow& flow, const uint8_t* data, size_t len);
    void remember_tun_quic_route(const UdpFlow& flow, const std::string& cid);
    void remember_tun_quic_response_route(const UdpFlow& flow,
                                          const uint8_t* data, size_t len);
    void dispatch_tun_udp_packet(const std::string& flow_key, UdpFlow& flow,
                                 const uint8_t* data, size_t len);
    void process_tun_quic_packet(const std::string& flow_key, UdpFlow& flow,
                                 const uint8_t* data, size_t len);
    void fallback_tun_quic_to_ip(const std::string& flow_key);
    void release_tun_quic_sniffer(UdpFlow& flow);
    void clear_tun_quic_pending(UdpFlow& flow);
    void flush_tun_quic_pending(const std::string& flow_key, UdpFlow& flow);
    IpAddr tun_udp_response_source(const UdpFlow& flow, const TargetAddr& source) const;
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
    // Routes application DNS to the physical resolver, TX tunnel, or block
    // decision. Direct target/bootstrap resolution uses direct_dns_resolver_.
    DnsResolver         dns_resolver_;
    // Resolves only direct targets via the selected physical Network on
    // Android, retaining device-local CDN affinity.
    DnsResolver         direct_dns_resolver_;

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
    std::unordered_map<std::string, uint32_t> udp_mux_next_slot_;
    std::unordered_map<std::string, UdpFlow> udp_flows_;
    std::unordered_map<SessionId, std::string> udp_session_keys_;
    std::unordered_map<uint64_t, TunDnsFlow> tun_dns_flows_;
    uint64_t            next_tun_dns_generation_ = 1;
    uv_timer_t         udp_cleanup_timer_;
    bool               udp_cleanup_timer_started_;
    uv_timer_t         internal_dns_timer_;
    bool               internal_dns_timer_initialized_;
    size_t             udp_tunnel_pending_bytes_ = 0;
    size_t             quic_sniff_active_flows_ = 0;
    size_t             quic_sniff_pending_bytes_ = 0;
    std::unordered_map<std::string, QuicRouteCacheEntry> quic_route_cache_;

    // Active connections by session ID
    std::unordered_map<SessionId, ProxyConnPtr> connections_;
    SessionId          next_session_id_;
    std::unordered_set<SessionId> active_session_ids_;
    size_t             active_proxy_connections_ = 0;

    std::atomic<uint64_t> direct_upload_bytes_;
    std::atomic<uint64_t> direct_download_bytes_;
    std::atomic<uint64_t> proxy_upload_bytes_;
    std::atomic<uint64_t> proxy_download_bytes_;
    std::atomic<uint32_t> android_address_family_mask_;
    SocketProtectCallback socket_protector_;
    OutboundSocketPolicy outbound_socket_policy_;
    DnsResolver::HostResolveHook host_resolver_;
    DnsResolver::QueryHook dns_query_;
};

} // namespace tx
