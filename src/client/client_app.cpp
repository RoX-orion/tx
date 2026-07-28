#include "client_app.h"
#include "tx/common/log.h"
#include "tx/common/endian.h"
#include "tx/protocol/tls_sni.h"
#include "tx/net/udp_flow_timeout.h"

#include <algorithm>
#include <atomic>
#include "tx/common/network.h"
#include <cstring>
#include <random>
#include <cstdlib>
#include <array>
#include <sstream>
#include <stdexcept>
#include <utility>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(TX_PLATFORM_LINUX)
#include <linux/netfilter_ipv4.h>
#endif

namespace tx {

namespace {

constexpr uint64_t kTunnelHandshakeTimeoutMs = 8000;
constexpr uint64_t kTunnelConnectResultTimeoutMs = 15000;
constexpr uint64_t kTcpConnectTimeoutMs = 5000;
constexpr uint64_t kInternalDnsStageTimeoutMs = 2000;
constexpr size_t kMaxDnsTcpWireSize = 2 + 65535;
constexpr size_t kMaxUdpPendingPackets = 1024;
constexpr size_t kMaxUdpPendingBytes = 4 * 1024 * 1024;
constexpr size_t kMaxUdpPendingBytesPerFlow = 512 * 1024;
constexpr size_t kMaxUdpTunnelWriteBacklog = 8 * 1024 * 1024;
constexpr uint64_t kQuicSniffTimeoutMs = 300;
constexpr size_t kMaxQuicSniffPendingBytesPerFlow = 16 * 1024;
constexpr size_t kMaxQuicSniffActiveFlows = 256;
constexpr size_t kMaxQuicSniffPendingBytes = 4 * 1024 * 1024;

bool same_numeric_target(const TargetAddr& left, const TargetAddr& right) {
    if (left.type != right.type || left.port != right.port ||
        (left.type != AddrType::IPv4 && left.type != AddrType::IPv6)) {
        return false;
    }
    return IpAddr::from_string(left.host, left.port) ==
           IpAddr::from_string(right.host, right.port);
}

std::unique_ptr<uv_loop_t> create_app_loop(const char* app_name) {
    std::unique_ptr<uv_loop_t> loop(new uv_loop_t);
    const int status = uv_loop_init(loop.get());
    if (status != 0) {
        throw std::runtime_error(std::string("Failed to initialize ") + app_name +
                                 " libuv loop: " + uv_strerror(status));
    }
    return loop;
}

void close_remaining_handle(uv_handle_t* handle, void*) {
    if (!uv_is_closing(handle)) {
        uv_close(handle, nullptr);
    }
}

void drain_and_close_loop(uv_loop_t* loop, const char* app_name) {
    if (!loop) return;

    while (uv_loop_alive(loop)) {
        uv_run(loop, UV_RUN_DEFAULT);
    }
    int status = uv_loop_close(loop);
    if (status == 0) return;

    // A failed initialization or a future shutdown path must not leave an
    // inactive handle behind. Close every remaining handle on its own loop,
    // then drain close callbacks before giving up the loop storage.
    TX_WARN("%s loop still had handles during shutdown: %s", app_name,
            uv_strerror(status));
    uv_walk(loop, close_remaining_handle, nullptr);
    while (uv_loop_alive(loop)) {
        uv_run(loop, UV_RUN_DEFAULT);
    }
    status = uv_loop_close(loop);
    if (status != 0) {
        TX_ERROR("Failed to close %s libuv loop: %s", app_name,
                 uv_strerror(status));
    }
}

std::string ipaddr_host_string(const IpAddr& ip) {
    char host[INET6_ADDRSTRLEN] = {0};
    if (ip.family == IpAddr::IPv4) {
        inet_ntop(AF_INET, ip.data.v4, host, sizeof(host));
    } else {
        inet_ntop(AF_INET6, ip.data.v6, host, sizeof(host));
    }
    return host;
}

TargetAddr sockaddr_to_target(const sockaddr* addr) {
    TargetAddr target;
    char host[INET6_ADDRSTRLEN] = {0};
    if (addr->sa_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &a4->sin_addr, host, sizeof(host));
        target.type = AddrType::IPv4;
        target.host = host;
        target.port = ntohs(a4->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &a6->sin6_addr, host, sizeof(host));
        target.type = AddrType::IPv6;
        target.host = host;
        target.port = ntohs(a6->sin6_port);
    }
    return target;
}

bool is_numeric_ip_address(const std::string& host) {
    in_addr v4{};
    in6_addr v6{};
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool target_to_sockaddr(const TargetAddr& target, sockaddr_storage& out) {
    memset(&out, 0, sizeof(out));
    if (target.type == AddrType::IPv4) {
        auto* a4 = reinterpret_cast<sockaddr_in*>(&out);
        return uv_ip4_addr(target.host.c_str(), target.port, a4) == 0;
    }
    if (target.type == AddrType::IPv6) {
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&out);
        return uv_ip6_addr(target.host.c_str(), target.port, a6) == 0;
    }
    return false;
}

#if defined(TX_PLATFORM_LINUX)
bool run_auto_redirect_cmd(const std::string& cmd) {
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        TX_WARN("auto_redirect command failed (%d): %s", rc, cmd.c_str());
        return false;
    }
    return true;
}

std::string hex_u32(uint32_t value) {
    std::ostringstream oss;
    oss << std::hex << value;
    return oss.str();
}

bool original_tcp_destination(SessionPtr session, TargetAddr& target) {
    uv_os_fd_t fd;
    if (uv_fileno(reinterpret_cast<const uv_handle_t*>(session->handle()), &fd) == 0) {
        sockaddr_in orig4;
        socklen_t len4 = sizeof(orig4);
        if (getsockopt(static_cast<int>(fd), IPPROTO_IP, SO_ORIGINAL_DST,
                       &orig4, &len4) == 0) {
            target.type = AddrType::IPv4;
            char host[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &orig4.sin_addr, host, sizeof(host));
            target.host = host;
            target.port = ntohs(orig4.sin_port);
            return true;
        }
    }

    std::string host;
    uint16_t port = 0;
    if (!session->local_addr(host, port)) {
        return false;
    }

    target.host = host;
    target.port = port;
    target.type = host.find(':') == std::string::npos ? AddrType::IPv4 : AddrType::IPv6;
    return port != 0;
}

bool install_linux_auto_redirect(uint16_t port, uint32_t mark) {
    run_auto_redirect_cmd("nft delete table inet tx_auto_redirect >/dev/null 2>&1");

    // Keep this a fixed-size array. Apart from avoiding a needless heap
    // allocation during startup, this sidesteps a false-positive
    // -Wfree-nonheap-object warning emitted by newer GCC versions for the
    // equivalent vector initializer.
    const std::array<std::string, 5> commands = {{
        "nft add table inet tx_auto_redirect",
        "nft 'add chain inet tx_auto_redirect output { type nat hook output priority dstnat; policy accept; }'",
        "nft add rule inet tx_auto_redirect output meta mark 0x" +
            hex_u32(mark) + " return",
        "nft 'add rule inet tx_auto_redirect output ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return'",
        "nft add rule inet tx_auto_redirect output ip protocol tcp redirect to :" +
            std::to_string(port),
    }};
    for (const auto& command : commands) {
        if (!run_auto_redirect_cmd(command)) {
            run_auto_redirect_cmd(
                "nft delete table inet tx_auto_redirect >/dev/null 2>&1");
            return false;
        }
    }
    return true;
}

void uninstall_linux_auto_redirect() {
    run_auto_redirect_cmd("nft delete table inet tx_auto_redirect >/dev/null 2>&1");
}
#endif

std::string sockaddr_key(const sockaddr* addr) {
    char host[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    if (addr->sa_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &a4->sin_addr, host, sizeof(host));
        port = ntohs(a4->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &a6->sin6_addr, host, sizeof(host));
        port = ntohs(a6->sin6_port);
    }
    return std::string(host) + ":" + std::to_string(port);
}

bool parse_socks5_udp_packet(const uint8_t* data, size_t len,
                             TargetAddr& target,
                             const uint8_t*& payload,
                             size_t& payload_len) {
    if (len < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0) {
        return false;
    }

    size_t pos = 3;
    uint8_t atyp = data[pos++];
    if (atyp == static_cast<uint8_t>(AddrType::IPv4)) {
        if (pos + 4 + 2 > len) return false;
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, data + pos, ipbuf, sizeof(ipbuf));
        target.type = AddrType::IPv4;
        target.host = ipbuf;
        pos += 4;
    } else if (atyp == static_cast<uint8_t>(AddrType::Domain)) {
        if (pos >= len) return false;
        uint8_t host_len = data[pos++];
        if (pos + host_len + 2 > len) return false;
        target.type = AddrType::Domain;
        target.host.assign(reinterpret_cast<const char*>(data + pos), host_len);
        pos += host_len;
    } else if (atyp == static_cast<uint8_t>(AddrType::IPv6)) {
        if (pos + 16 + 2 > len) return false;
        char ipbuf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, data + pos, ipbuf, sizeof(ipbuf));
        target.type = AddrType::IPv6;
        target.host = ipbuf;
        pos += 16;
    } else {
        return false;
    }

    target.port = load_be16(data + pos);
    pos += 2;
    payload = data + pos;
    payload_len = len - pos;
    return payload_len > 0;
}

bool build_socks5_udp_packet(const TargetAddr& target,
                             const uint8_t* payload, size_t payload_len,
                             Buffer& out) {
    uint8_t hdr[4] = {0, 0, 0, static_cast<uint8_t>(target.type)};
    out.append(hdr, sizeof(hdr));

    if (target.type == AddrType::IPv4) {
        IpAddr ip = IpAddr::from_string(target.host);
        out.append(ip.data.v4, 4);
    } else if (target.type == AddrType::IPv6) {
        IpAddr ip = IpAddr::from_string(target.host);
        out.append(ip.data.v6, 16);
    } else {
        if (target.host.size() > 255) return false;
        uint8_t host_len = static_cast<uint8_t>(target.host.size());
        out.append(&host_len, 1);
        out.append(target.host.data(), target.host.size());
    }

    uint8_t port_buf[2];
    store_be16(port_buf, target.port);
    out.append(port_buf, sizeof(port_buf));
    out.append(payload, payload_len);
    return true;
}

} // namespace

struct ClientApp::TunnelTimerCtx {
    ClientApp* app;
    ProxyConnPtr conn;
    std::string phase;
};

struct ClientApp::DirectUdpRelay {
    ClientApp* app;
    std::string flow_key;
    SessionId session_id;
    uv_udp_t handle;
    int family = AF_UNSPEC;
    bool recv_started = false;
};

ClientApp::ClientApp(SocketProtectCallback socket_protector,
                     DnsResolver::HostResolveHook host_resolver,
                     DnsResolver::QueryHook dns_query)
    : owned_loop_(create_app_loop("client")),
      loop_(owned_loop_.get()),
      loop_closed_(false),
      stop_async_initialized_(false),
      network_async_initialized_(false),
      ready_to_run_(false),
      stop_requested_(false),
      stopping_(false),
      dns_resolver_(loop_),
      http_server_(loop_),
      socks5_server_(loop_),
      tun_tcp_server_(loop_),
      socks5_udp_started_(false),
      tun_fd_(-1),
      tun_started_(false),
      tun_timer_started_(false),
      tun_tcp_redirect_started_(false),
      udp_cleanup_timer_started_(false),
      internal_dns_timer_initialized_(false),
      next_session_id_(1),
      socket_protector_(std::move(socket_protector)),
      host_resolver_(std::move(host_resolver)),
      dns_query_(std::move(dns_query)) {}

ClientApp::~ClientApp() {
    stop();
    if (!loop_closed_) {
        drain_and_close_loop(loop_, "client");
        loop_closed_ = true;
    }
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
    if (config_.tun_fd >= 0) {
        ::close(config_.tun_fd);
        config_.tun_fd = -1;
    }
#endif
}

bool ClientApp::init(const ClientConfig& config) {
    if (!stop_async_initialized_) {
        int r = uv_async_init(loop_, &stop_async_, ClientApp::on_stop_async);
        if (r != 0) {
            TX_ERROR("Failed to initialize client stop handle: %s", uv_strerror(r));
            return false;
        }
        stop_async_.data = this;
        stop_async_initialized_ = true;
    }
    if (!network_async_initialized_) {
        int r = uv_async_init(loop_, &network_async_, ClientApp::on_network_async);
        if (r != 0) return false;
        network_async_.data = this;
        network_async_initialized_ = true;
    }
    if (!internal_dns_timer_initialized_) {
        int r = uv_timer_init(loop_, &internal_dns_timer_);
        if (r != 0) {
            TX_ERROR("Failed to initialize internal DNS timer: %s", uv_strerror(r));
            return false;
        }
        internal_dns_timer_.data = this;
        internal_dns_timer_initialized_ = true;
    }

    config_ = config;

#if defined(TX_PLATFORM_ANDROID)
    // Resolving a TX endpoint before its tunnel exists would require a
    // bootstrap resolver outside the VPN.  Android deliberately has no such
    // fallback: use an IP literal for every TX endpoint instead.
    for (const auto& outbound : config_.outbounds) {
        if (outbound.type == OutboundType::Tx &&
            !is_numeric_ip_address(outbound.server_host)) {
            TX_ERROR("Android TX outbound %s must use a numeric server host; "
                     "physical DNS bootstrap is disabled", outbound.tag.c_str());
            return false;
        }
    }
    if (config_.dns_upstreams.empty()) {
        TX_ERROR("Android requires a numeric dns.upstreams entry for remote DNS");
        return false;
    }
    for (const auto& upstream : config_.dns_upstreams) {
        TargetAddr parsed;
        if (!parse_dns_upstream(upstream, parsed)) {
            TX_ERROR("Android DNS upstream must be numeric: %s", upstream.c_str());
            return false;
        }
    }
    const OutboundConfig* dns_outbound = find_outbound(config_.dns_outbound_tag);
    if (!dns_outbound || dns_outbound->type != OutboundType::Tx) {
        TX_ERROR("Android DNS outboundTag must reference a TX outbound: %s",
                 config_.dns_outbound_tag.c_str());
        return false;
    }
#endif

    std::string dns_error;
    if (!fake_ip_dns_.configure(config_.dns_fake_ipv4_range,
                                config_.dns_fake_ipv6_range,
                                config_.dns_cache_ttl, dns_error,
                                config_.dns_cache_capacity)) {
        TX_ERROR("Failed to configure fake-IP DNS: %s", dns_error.c_str());
        return false;
    }
    uint32_t dns_bypass_mark = 0;
#if defined(TX_PLATFORM_LINUX)
    // SO_MARK is needed only for the lwIP TUN policy-routing path.  Applying
    // it to ordinary HTTP/SOCKS DNS sockets makes unprivileged clients fail
    // with EPERM before they can issue a query.
    if (config_.tun_enabled && config_.tun_tcp_stack == "lwip") {
        dns_bypass_mark = config_.tun_bypass_mark;
    }
#endif
#if defined(TX_PLATFORM_ANDROID)
    // DNS upstreams are sent to the configured resolver by the TX server.
    // Do not install Android's physical-network resolver hooks here.
    dns_resolver_.configure(config_.dns_upstreams, socket_protector_,
                            dns_bypass_mark, DnsResolver::HostResolveHook(),
                            DnsResolver::QueryHook(),
                            [this](std::vector<uint8_t> query,
                                   DnsResolver::ResolveCallback callback) {
                                resolve_dns_via_tunnel(std::move(query),
                                                       std::move(callback));
                            });
#else
    dns_resolver_.configure(config_.dns_upstreams, socket_protector_,
                            dns_bypass_mark, host_resolver_, dns_query_);
#endif

    // Load router
    if (!router_.load(config.router)) {
        TX_WARN("Router load failed, all traffic will be proxied");
    }

    TX_INFO("TX Client started");
    if (config_.tun_enabled) {
        if (!start_tun_listener()) {
            return false;
        }
        TX_INFO("  TUN mixed:    fd=%d mtu=%d tcp=%s udp=%s",
                tun_fd_, config_.tun_mtu,
                config_.tun_tcp_stack.c_str(),
                config_.tun_udp_stack.c_str());
        if (!config_.tun_auto_redirect) {
            if (!start_proxy_listeners()) {
                return false;
            }
            TX_INFO("  TUN proxy bridge enabled for TCP/SOCKS compatibility");
        }
    } else {
        if (!start_proxy_listeners()) {
            return false;
        }
    }
    if (!start_udp_cleanup_timer()) {
        return false;
    }
    TX_INFO("  Outbounds:    %zu", config.outbounds.size());
    TX_INFO("  UDP timeout:  %llu seconds",
            static_cast<unsigned long long>(config_.udp_idle_timeout_ms / 1000));
    ready_to_run_ = true;
    return true;
}

int ClientApp::run() {
    return uv_run(loop_, UV_RUN_DEFAULT);
}

void ClientApp::stop() {
    if (stop_requested_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    if (ready_to_run_) {
        if (stop_async_initialized_) {
            uv_async_send(&stop_async_);
        }
        return;
    }

    // Initialization failures never enter uv_run(), so there is no loop
    // thread to receive the async request. Clean them up synchronously.
    stop_on_loop();
    uv_run(loop_, UV_RUN_NOWAIT);
}

void ClientApp::notify_network_changed() {
    if (network_async_initialized_) uv_async_send(&network_async_);
}

void ClientApp::on_network_async(uv_async_t* handle) {
    auto* app = static_cast<ClientApp*>(handle->data);
    if (app) app->network_changed_on_loop();
}

void ClientApp::network_changed_on_loop() {
    dns_resolver_.cancel_pending();
    close_all_udp_tunnels();
    std::vector<std::string> flows;
    for (const auto& item : udp_flows_) flows.push_back(item.first);
    for (const auto& key : flows) remove_udp_flow(key, false);
    std::vector<ProxyConnPtr> connections;
    connections.reserve(connections_.size());
    for (const auto& item : connections_) connections.push_back(item.second);
    connections_.clear();
    for (auto& conn : connections) {
        close_tunnel_session(conn);
        if (conn->direct_session && !conn->direct_session->is_closed())
            conn->direct_session->close();
        if (conn->local_session && !conn->local_session->is_closed())
            conn->local_session->reset();
    }
    TX_INFO("Android underlying network changed; old outbound flows closed");
}

void ClientApp::on_stop_async(uv_async_t* handle) {
    auto* app = static_cast<ClientApp*>(handle->data);
    if (app) {
        app->stop_on_loop();
    }
}

void ClientApp::stop_on_loop() {
    if (stopping_) {
        return;
    }
    stopping_ = true;

    stop_internal_dns_timer();
    stop_udp_cleanup_timer();
    stop_tun_listener();
    stop_udp_listener();
    close_all_udp_tunnels();
    http_server_.stop();
    socks5_server_.stop();
    std::vector<ProxyConnPtr> active_connections;
    active_connections.reserve(connections_.size());
    for (const auto& kv : connections_) active_connections.push_back(kv.second);
    connections_.clear();
    for (auto& conn : active_connections) {
        close_tunnel_session(conn);
        if (conn->direct_session && !conn->direct_session->is_closed()) {
            conn->direct_session->set_close_callback(nullptr);
            conn->direct_session->close();
        }
        if (conn->local_session && !conn->local_session->is_closed()) {
            conn->local_session->close();
        }
    }
    if (stop_async_initialized_ &&
        !uv_is_closing(reinterpret_cast<uv_handle_t*>(&stop_async_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&stop_async_), nullptr);
    }
    if (network_async_initialized_ &&
        !uv_is_closing(reinterpret_cast<uv_handle_t*>(&network_async_)))
        uv_close(reinterpret_cast<uv_handle_t*>(&network_async_), nullptr);
}

ClientTrafficStats ClientApp::traffic_stats() const {
    ClientTrafficStats stats;
    stats.direct_upload_bytes = direct_upload_bytes_.load(std::memory_order_relaxed);
    stats.direct_download_bytes = direct_download_bytes_.load(std::memory_order_relaxed);
    stats.proxy_upload_bytes = proxy_upload_bytes_.load(std::memory_order_relaxed);
    stats.proxy_download_bytes = proxy_download_bytes_.load(std::memory_order_relaxed);
    return stats;
}

void ClientApp::record_traffic(RouteAction route, bool upload, size_t bytes) {
    if (bytes == 0) return;
    if (route == RouteAction::Direct) {
        if (upload) {
            direct_upload_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        } else {
            direct_download_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        }
    } else if (route == RouteAction::Proxy) {
        if (upload) {
            proxy_upload_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        } else {
            proxy_download_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        }
    }
}

const OutboundConfig* ClientApp::find_outbound(const std::string& tag) const {
    auto it = config_.outbound_index.find(tag);
    if (it == config_.outbound_index.end()) {
        return nullptr;
    }
    if (it->second >= config_.outbounds.size()) {
        return nullptr;
    }
    return &config_.outbounds[it->second];
}

bool ClientApp::apply_route_decision(ProxyConnPtr conn, const RouteDecision& decision) {
    if (!conn) return false;

    const OutboundConfig* outbound = find_outbound(decision.outbound_tag);
    if (!outbound) {
        TX_ERROR("Route selected unknown outboundTag: %s", decision.outbound_tag.c_str());
        block_connection(conn);
        return false;
    }

    conn->outbound = outbound;
    if (outbound->type == OutboundType::Direct) {
        conn->route = RouteAction::Direct;
        return true;
    }
    if (outbound->type == OutboundType::Block) {
        conn->route = RouteAction::Block;
        block_connection(conn);
        return false;
    }

    conn->route = RouteAction::Proxy;
    return true;
}

void ClientApp::block_connection(ProxyConnPtr conn) {
    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    TX_INFO("[Block] %s:%u", conn->target.host.c_str(), conn->target.port);
    if (conn->socks5) {
        Buffer resp;
        conn->socks5->build_connect_response(false, resp);
        conn->local_session->send(resp);
    } else if (conn->http) {
        Buffer resp;
        conn->http->build_error_response(403, resp);
        conn->local_session->send(resp);
    }
    if (std::dynamic_pointer_cast<LwipTcpStream>(conn->local_session))
        conn->local_session->reset();
    else
        conn->local_session->close();
}

bool ClientApp::start_proxy_listeners() {
    http_server_.set_accept_callback([this](SessionPtr s) { on_http_accept(s); });
    if (!http_server_.listen(config_.http_host, config_.http_port)) {
        TX_ERROR("Failed to start HTTP proxy on %s:%u",
                 config_.http_host.c_str(), config_.http_port);
        return false;
    }

    socks5_server_.set_accept_callback([this](SessionPtr s) { on_socks5_accept(s); });
    if (!socks5_server_.listen(config_.socks5_host, config_.socks5_port)) {
        TX_ERROR("Failed to start SOCKS5 proxy on %s:%u",
                 config_.socks5_host.c_str(), config_.socks5_port);
        return false;
    }

    if (!start_udp_listener()) {
        TX_ERROR("Failed to start SOCKS5 UDP associate listener on %s:%u",
                 config_.socks5_host.c_str(), config_.socks5_port);
        return false;
    }

    TX_INFO("  HTTP   proxy: %s:%u", config_.http_host.c_str(), config_.http_port);
    TX_INFO("  SOCKS5 proxy: %s:%u", config_.socks5_host.c_str(), config_.socks5_port);
    return true;
}

bool ClientApp::start_udp_listener() {
    if (socks5_udp_started_) return true;

    int r = uv_udp_init(loop_, &socks5_udp_);
    if (r != 0) {
        TX_ERROR("uv_udp_init failed: %s", uv_strerror(r));
        return false;
    }
    socks5_udp_.data = this;

    sockaddr_in addr4;
    sockaddr_in6 addr6;
    const sockaddr* bind_addr = nullptr;
    if (uv_ip4_addr(config_.socks5_host.c_str(), config_.socks5_port, &addr4) == 0) {
        bind_addr = reinterpret_cast<const sockaddr*>(&addr4);
    } else if (uv_ip6_addr(config_.socks5_host.c_str(), config_.socks5_port, &addr6) == 0) {
        bind_addr = reinterpret_cast<const sockaddr*>(&addr6);
    } else {
        TX_ERROR("Invalid SOCKS5 UDP bind address: %s", config_.socks5_host.c_str());
        uv_close(reinterpret_cast<uv_handle_t*>(&socks5_udp_), nullptr);
        return false;
    }

    r = uv_udp_bind(&socks5_udp_, bind_addr, 0);
    if (r != 0) {
        TX_ERROR("uv_udp_bind failed: %s", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(&socks5_udp_), nullptr);
        return false;
    }

    r = uv_udp_recv_start(&socks5_udp_, ClientApp::on_udp_alloc, ClientApp::on_udp_read);
    if (r != 0) {
        TX_ERROR("uv_udp_recv_start failed: %s", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(&socks5_udp_), nullptr);
        return false;
    }

    socks5_udp_started_ = true;
    TX_INFO("  SOCKS5 UDP:   %s:%u", config_.socks5_host.c_str(), config_.socks5_port);
    return true;
}

void ClientApp::stop_udp_listener() {
    if (socks5_udp_started_) {
        socks5_udp_started_ = false;
        uv_udp_recv_stop(&socks5_udp_);
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&socks5_udp_))) {
            uv_close(reinterpret_cast<uv_handle_t*>(&socks5_udp_), nullptr);
        }
    }
    std::vector<std::string> flow_keys;
    flow_keys.reserve(udp_flows_.size());
    for (const auto& item : udp_flows_) flow_keys.push_back(item.first);
    for (const auto& flow_key : flow_keys) remove_udp_flow(flow_key, false);
}

bool ClientApp::start_udp_cleanup_timer() {
    if (udp_cleanup_timer_started_) return true;

    int r = uv_timer_init(loop_, &udp_cleanup_timer_);
    if (r != 0) {
        TX_ERROR("Failed to initialize UDP cleanup timer: %s", uv_strerror(r));
        return false;
    }
    udp_cleanup_timer_.data = this;

    uint64_t interval = udp_flow_cleanup_interval(config_.udp_idle_timeout_ms);
    r = uv_timer_start(&udp_cleanup_timer_, ClientApp::on_udp_cleanup_timer,
                       interval, interval);
    if (r != 0) {
        TX_ERROR("Failed to start UDP cleanup timer: %s", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(&udp_cleanup_timer_), nullptr);
        return false;
    }
    udp_cleanup_timer_started_ = true;
    return true;
}

void ClientApp::stop_udp_cleanup_timer() {
    if (!udp_cleanup_timer_started_) return;
    udp_cleanup_timer_started_ = false;
    uv_timer_stop(&udp_cleanup_timer_);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&udp_cleanup_timer_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&udp_cleanup_timer_), nullptr);
    }
}

void ClientApp::arm_internal_dns_timer() {
    if (stopping_) return;

    uint64_t earliest = 0;
    for (const auto& item : udp_flows_) {
        const UdpFlow& flow = item.second;
        if (flow.kind == UdpFlowKind::InternalDns && flow.dns_deadline_ms != 0) {
            if (earliest == 0 || flow.dns_deadline_ms < earliest) {
                earliest = flow.dns_deadline_ms;
            }
        }
        if (flow.kind == UdpFlowKind::Tun && flow.quic_sniffer &&
            flow.quic_sniff_deadline_ms != 0) {
            if (earliest == 0 || flow.quic_sniff_deadline_ms < earliest) {
                earliest = flow.quic_sniff_deadline_ms;
            }
        }
    }

    if (earliest == 0) {
        if (internal_dns_timer_initialized_) uv_timer_stop(&internal_dns_timer_);
        return;
    }
    if (!internal_dns_timer_initialized_) {
        const int status = uv_timer_init(loop_, &internal_dns_timer_);
        if (status != 0) {
            TX_ERROR("Failed to initialize internal DNS timer: %s", uv_strerror(status));
            return;
        }
        internal_dns_timer_.data = this;
        internal_dns_timer_initialized_ = true;
    }

    const uint64_t now = uv_now(loop_);
    const uint64_t delay = earliest > now ? earliest - now : 1;
    const int status = uv_timer_start(&internal_dns_timer_,
                                      ClientApp::on_internal_dns_timer,
                                      delay, 0);
    if (status != 0) {
        TX_ERROR("Failed to arm internal DNS timer: %s", uv_strerror(status));
    }
}

void ClientApp::stop_internal_dns_timer() {
    if (!internal_dns_timer_initialized_) return;
    internal_dns_timer_initialized_ = false;
    uv_timer_stop(&internal_dns_timer_);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&internal_dns_timer_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&internal_dns_timer_), nullptr);
    }
}

void ClientApp::on_internal_dns_timer(uv_timer_t* timer) {
    auto* app = static_cast<ClientApp*>(timer->data);
    if (!app || app->stopping_) return;

    const uint64_t now = uv_now(app->loop_);
    std::vector<std::string> expired_dns;
    std::vector<std::string> expired_quic;
    for (const auto& item : app->udp_flows_) {
        const UdpFlow& flow = item.second;
        if (flow.kind == UdpFlowKind::InternalDns && flow.dns_deadline_ms != 0 &&
            now >= flow.dns_deadline_ms) {
            expired_dns.push_back(item.first);
        }
        if (flow.kind == UdpFlowKind::Tun && flow.quic_sniffer &&
            flow.quic_sniff_deadline_ms != 0 && now >= flow.quic_sniff_deadline_ms) {
            expired_quic.push_back(item.first);
        }
    }
    for (const auto& flow_key : expired_dns) {
        app->retry_internal_dns(flow_key, "timeout");
    }
    for (const auto& flow_key : expired_quic) {
        app->fallback_tun_quic_to_ip(flow_key);
    }
    app->arm_internal_dns_timer();
}

void ClientApp::remove_udp_flow(const std::string& flow_key, bool notify_peer) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end()) return;

    UdpFlow& flow = it->second;
    const bool was_internal_dns = flow.kind == UdpFlowKind::InternalDns;
    const bool had_quic_sniff_state = flow.quic_sniffer ||
        !flow.quic_pending_packets.empty() || flow.quic_pending_bytes != 0;
    SessionId sid = flow.session_id;
    DnsResolver::ResolveCallback dns_callback = std::move(flow.dns_callback);
    UdpTunnelPtr tunnel;
    if (flow.outbound) {
        auto tunnel_it = udp_tunnels_.find(flow.outbound->tag);
        if (tunnel_it != udp_tunnels_.end() &&
            tunnel_it->second->outbound == flow.outbound) {
            tunnel = tunnel_it->second;
        }
    }
    if (notify_peer && flow.proxied && tunnel && tunnel->connected &&
        tunnel->tunnel_session && !tunnel->tunnel_session->is_closed()) {
        Buffer encoded;
        if (tunnel->codec.encode_disconnect(sid, encoded)) {
            tunnel->tunnel_session->send(encoded);
        }
    }

    close_direct_udp_relay(flow);
    release_tun_quic_sniffer(flow);
    clear_tun_quic_pending(flow);
    if (flow.kind == UdpFlowKind::Tun && flow.lwip_flow_id != 0) {
        lwip_udp_stack_.close_flow(flow.lwip_flow_id);
    }
    udp_session_keys_.erase(sid);
    release_session_id(sid);
    if (tunnel) {
        for (auto pending = tunnel->pending.begin(); pending != tunnel->pending.end();) {
            if (pending->session_id == sid) {
                tunnel->pending_bytes -= std::min(tunnel->pending_bytes,
                                                  pending->payload.size());
                pending = tunnel->pending.erase(pending);
            } else {
                ++pending;
            }
        }
    }
    udp_flows_.erase(it);
    if (was_internal_dns || had_quic_sniff_state) arm_internal_dns_timer();
    if (dns_callback) dns_callback(std::vector<uint8_t>());
}

void ClientApp::cleanup_idle_udp_flows(uint64_t now_ms) {
    std::vector<std::string> expired;
    expired.reserve(udp_flows_.size());
    for (const auto& kv : udp_flows_) {
        if (kv.second.kind != UdpFlowKind::InternalDns &&
            udp_flow_is_idle(now_ms, kv.second.last_activity_ms,
                             config_.udp_idle_timeout_ms)) {
            expired.push_back(kv.first);
        }
    }

    for (const auto& flow_key : expired) {
        remove_udp_flow(flow_key, true);
    }
    if (!expired.empty()) {
        TX_DEBUG("Cleaned up %zu idle UDP flows", expired.size());
    }
}

void ClientApp::on_udp_cleanup_timer(uv_timer_t* timer) {
    auto* app = static_cast<ClientApp*>(timer->data);
    if (app) {
        app->lwip_udp_stack_.poll_timers();
        app->cleanup_idle_udp_flows(uv_now(app->loop_));
    }
}

bool ClientApp::ensure_direct_udp_relay(const std::string& flow_key, UdpFlow& flow,
                                        int target_family) {
    if (flow.direct_relay) {
        return flow.direct_relay->family == target_family;
    }

    auto* relay = new DirectUdpRelay;
    relay->app = this;
    relay->flow_key = flow_key;
    relay->session_id = flow.session_id;
    relay->family = target_family;

    int r = uv_udp_init(loop_, &relay->handle);
    if (r != 0) {
        TX_ERROR("direct UDP init failed: %s", uv_strerror(r));
        delete relay;
        return false;
    }
    relay->handle.data = relay;

    const bool needs_explicit_socket = static_cast<bool>(socket_protector_)
#if defined(TX_PLATFORM_LINUX)
        || (config_.tun_enabled && config_.tun_tcp_stack == "lwip" &&
            config_.tun_bypass_mark != 0)
#elif defined(TX_PLATFORM_WINDOWS)
        || TcpSession::outbound_interface(target_family) != 0
#endif
        ;
    if (needs_explicit_socket) {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
        int socket_fd = ::socket(target_family, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            TX_ERROR("Failed to create direct UDP socket: %s", std::strerror(errno));
            uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                     ClientApp::on_direct_udp_closed);
            return false;
        }
        if (socket_protector_ && !socket_protector_(socket_fd)) {
            TX_ERROR("Socket protector rejected UDP fd %d", socket_fd);
            ::close(socket_fd);
            uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                     ClientApp::on_direct_udp_closed);
            return false;
        }
#if defined(TX_PLATFORM_LINUX)
        if (config_.tun_enabled && config_.tun_tcp_stack == "lwip" &&
            config_.tun_bypass_mark != 0) {
            uint32_t mark = config_.tun_bypass_mark;
            if (setsockopt(socket_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
                TX_ERROR("SO_MARK failed for direct UDP fd %d: %s",
                         socket_fd, std::strerror(errno));
                ::close(socket_fd);
                uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                         ClientApp::on_direct_udp_closed);
                return false;
            }
        }
#endif
        r = uv_udp_open(&relay->handle, static_cast<uv_os_sock_t>(socket_fd));
        if (r != 0) {
            TX_ERROR("uv_udp_open for protected socket failed: %s", uv_strerror(r));
            ::close(socket_fd);
            uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                     ClientApp::on_direct_udp_closed);
            return false;
        }
#elif defined(TX_PLATFORM_WINDOWS)
        SOCKET socket_fd = socket(target_family, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_fd == INVALID_SOCKET) {
            uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                     ClientApp::on_direct_udp_closed);
            return false;
        }
        DWORD index = htonl(TcpSession::outbound_interface(target_family));
        int level = target_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
        int option = target_family == AF_INET6 ? IPV6_UNICAST_IF : IP_UNICAST_IF;
        if (setsockopt(socket_fd, level, option,
                       reinterpret_cast<const char*>(&index), sizeof(index)) != 0 ||
            uv_udp_open(&relay->handle, socket_fd) != 0) {
            closesocket(socket_fd);
            uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                     ClientApp::on_direct_udp_closed);
            return false;
        }
#else
        TX_ERROR("Socket protection is not supported on this platform");
        uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                 ClientApp::on_direct_udp_closed);
        return false;
#endif
    }

    if (target_family == AF_INET6) {
        sockaddr_in6 any6;
        uv_ip6_addr("::", 0, &any6);
        r = uv_udp_bind(&relay->handle, reinterpret_cast<const sockaddr*>(&any6), 0);
    } else {
        sockaddr_in any4;
        uv_ip4_addr("0.0.0.0", 0, &any4);
        r = uv_udp_bind(&relay->handle, reinterpret_cast<const sockaddr*>(&any4), 0);
    }
    if (r != 0) {
        TX_ERROR("direct UDP bind failed: %s", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle), ClientApp::on_direct_udp_closed);
        return false;
    }

    r = uv_udp_recv_start(&relay->handle, ClientApp::on_udp_alloc, ClientApp::on_direct_udp_read);
    if (r != 0) {
        TX_ERROR("direct UDP recv_start failed: %s", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle), ClientApp::on_direct_udp_closed);
        return false;
    }

    relay->recv_started = true;
    flow.direct_relay = relay;
    return true;
}

void ClientApp::send_direct_udp_packet(const std::string& flow_key, UdpFlow& flow,
                                       const TargetAddr& target,
                                       const uint8_t* data, size_t len) {
    sockaddr_storage target_addr;
    if (target_to_sockaddr(target, target_addr)) {
        if (!ensure_direct_udp_relay(flow_key, flow, target_addr.ss_family)) {
            return;
        }

        auto* req = new uv_udp_send_t;
        auto* data_copy = new char[len];
        memcpy(data_copy, data, len);
        auto* send_buf = new uv_buf_t;
        *send_buf = uv_buf_init(data_copy, static_cast<unsigned int>(len));
        req->data = send_buf;

        int r = uv_udp_send(req, &flow.direct_relay->handle, send_buf, 1,
                            reinterpret_cast<const sockaddr*>(&target_addr),
                            ClientApp::on_udp_send_done);
        if (r != 0) {
            TX_WARN("[Direct][UDP] send failed to %s:%u: %s",
                    target.host.c_str(), target.port, uv_strerror(r));
            delete[] send_buf->base;
            delete send_buf;
            delete req;
            return;
        }
        record_traffic(RouteAction::Direct, true, len);
        return;
    }

    const SessionId session_id = flow.session_id;
    std::vector<uint8_t> payload(data, data + len);
    dns_resolver_.resolve_host(target.host, AF_UNSPEC,
        [this, flow_key, session_id, target, payload](std::vector<std::string> addresses) {
            auto flow_it = udp_flows_.find(flow_key);
            if (addresses.empty() || flow_it == udp_flows_.end() ||
                flow_it->second.session_id != session_id) {
                TX_WARN("[Direct][UDP] DNS lookup failed for %s", target.host.c_str());
                return;
            }
            TargetAddr resolved = target;
            resolved.host = addresses.front();
            resolved.type = resolved.host.find(':') == std::string::npos
                ? AddrType::IPv4 : AddrType::IPv6;
            send_direct_udp_packet(flow_key, flow_it->second, resolved,
                                   payload.data(), payload.size());
        });
}

void ClientApp::close_direct_udp_relay(UdpFlow& flow) {
    auto* relay = flow.direct_relay;
    flow.direct_relay = nullptr;
    if (!relay) return;
    if (relay->recv_started) {
        uv_udp_recv_stop(&relay->handle);
        relay->recv_started = false;
    }
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&relay->handle))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle), ClientApp::on_direct_udp_closed);
    }
}

void ClientApp::send_udp_response_to_flow(const UdpFlow& flow, const TargetAddr& source,
                                          const uint8_t* data, size_t len,
                                          RouteAction route) {
    if (flow.kind == UdpFlowKind::Tun) {
        if (write_tun_udp_packet(flow, source, data, len)) {
            record_traffic(route, false, len);
        }
        return;
    }

    Buffer packet;
    if (!build_socks5_udp_packet(source, data, len, packet)) {
        return;
    }

    auto* req = new uv_udp_send_t;
    auto* data_copy = new char[packet.readable()];
    memcpy(data_copy, packet.data(), packet.readable());
    auto* send_buf = new uv_buf_t;
    *send_buf = uv_buf_init(data_copy, static_cast<unsigned int>(packet.readable()));
    req->data = send_buf;

    int r = uv_udp_send(req, &socks5_udp_, send_buf, 1,
                        reinterpret_cast<const sockaddr*>(&flow.client_addr),
                        ClientApp::on_udp_send_done);
    if (r != 0) {
        TX_WARN("[%s][UDP] failed to send response to SOCKS5 client: %s",
                route == RouteAction::Direct ? "Direct" : "Proxy", uv_strerror(r));
        delete[] send_buf->base;
        delete send_buf;
        delete req;
        return;
    }
    record_traffic(route, false, len);
}

ClientApp::UdpTunnelPtr ClientApp::get_udp_tunnel(const OutboundConfig* outbound) {
    if (!outbound || outbound->type != OutboundType::Tx) return UdpTunnelPtr();
    auto it = udp_tunnels_.find(outbound->tag);
    if (it != udp_tunnels_.end() && it->second->outbound == outbound) return it->second;

    UdpTunnelPtr tunnel = std::make_shared<UdpTunnel>();
    tunnel->outbound = outbound;
    udp_tunnels_[outbound->tag] = tunnel;
    return tunnel;
}

bool ClientApp::ensure_udp_tunnel(const UdpTunnelPtr& tunnel) {
    if (!tunnel || !tunnel->outbound || tunnel->outbound->type != OutboundType::Tx) {
        TX_ERROR("UDP proxy tunnel has no TX outbound selected");
        return false;
    }
    if (tunnel->connected || tunnel->connecting) return true;

    tunnel->connecting = true;
    tunnel->handshake_buf.clear();
    tunnel->recv_buf.clear();
    TunnelCodec::cleanse_handshake_state(tunnel->handshake_state);
    std::weak_ptr<UdpTunnel> weak_tunnel = tunnel;
    dns_resolver_.resolve_host(tunnel->outbound->server_host, AF_UNSPEC,
        [this, weak_tunnel](std::vector<std::string> addresses) {
            UdpTunnelPtr current = weak_tunnel.lock();
            if (!current || !current->connecting) return;
            if (addresses.empty()) {
                TX_ERROR("UDP tunnel DNS resolution failed");
                close_udp_tunnel(current);
                return;
            }
            connect_udp_tunnel_candidates(
                current, std::make_shared<std::vector<std::string>>(std::move(addresses)), 0);
        });
    return true;
}

void ClientApp::connect_udp_tunnel_candidates(
    const UdpTunnelPtr& tunnel, std::shared_ptr<std::vector<std::string>> addresses,
    size_t index) {
    if (!tunnel || !tunnel->connecting || !tunnel->outbound || !addresses ||
        index >= addresses->size()) {
        TX_ERROR("UDP tunnel exhausted all resolved server addresses");
        close_udp_tunnel(tunnel);
        return;
    }

    auto session = std::make_shared<TcpSession>(loop_, socket_protector_);
    tunnel->tunnel_session = session;
    std::weak_ptr<UdpTunnel> weak_tunnel = tunnel;
    TcpSession* const session_identity = session.get();
    session->set_close_callback([this, weak_tunnel, session_identity](SessionPtr) {
        UdpTunnelPtr current = weak_tunnel.lock();
        if (current && current->tunnel_session.get() == session_identity) {
            TX_WARN("UDP tunnel disconnected");
            close_udp_tunnel(current);
        }
    });

    const uint16_t server_port = tunnel->outbound->server_port;
    session->connect((*addresses)[index], server_port, kTcpConnectTimeoutMs,
        [this, tunnel, session, addresses, index](bool success) {
            if (tunnel->tunnel_session != session) {
                if (!session->is_closed()) session->close();
                return;
            }
            if (!success) {
                session->set_close_callback(nullptr);
                tunnel->tunnel_session.reset();
                if (index + 1 < addresses->size()) {
                    connect_udp_tunnel_candidates(tunnel, addresses, index + 1);
                } else {
                    TX_ERROR("UDP tunnel connect failed for every resolved address");
                    close_udp_tunnel(tunnel);
                }
                return;
            }

            std::weak_ptr<UdpTunnel> weak_tunnel = tunnel;
            session->start_read([this, weak_tunnel](SessionPtr, Buffer& data) {
                if (UdpTunnelPtr current = weak_tunnel.lock())
                    on_udp_tunnel_handshake_read(current, data);
                else
                    data.clear();
            });
            Buffer hello;
            if (!tunnel->outbound ||
                !TunnelCodec::build_client_hello(tunnel->outbound->psk,
                                                  tunnel->outbound->cipher, hello,
                                                  tunnel->handshake_state) ||
                !session->send(hello)) {
                TX_ERROR("Failed to build or send UDP tunnel handshake");
                close_udp_tunnel(tunnel);
            }
        });
}

void ClientApp::send_udp_packet(const UdpTunnelPtr& tunnel, SessionId sid,
                                const TargetAddr& target, const uint8_t* data, size_t len) {
    if (!tunnel || !data || len == 0 || !ensure_udp_tunnel(tunnel)) return;

    if (!tunnel->connected) {
        auto key = udp_session_keys_.find(sid);
        auto flow = key == udp_session_keys_.end() ? udp_flows_.end()
                                                    : udp_flows_.find(key->second);
        if (flow == udp_flows_.end() || flow->second.outbound != tunnel->outbound) {
            return;
        }
        if (tunnel->pending.size() >= kMaxUdpPendingPackets ||
            len > kMaxUdpPendingBytes || tunnel->pending_bytes > kMaxUdpPendingBytes - len) {
            TX_WARN("Dropping UDP packet while %s tunnel is connecting: queue limit reached",
                    tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
            return;
        }
        if (len > kMaxUdpPendingBytesPerFlow ||
            flow->second.pending_proxy_bytes > kMaxUdpPendingBytesPerFlow - len) {
            TX_WARN("Dropping UDP packet while %s tunnel is connecting: per-flow queue limit reached",
                    tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
            return;
        }
        PendingUdpPacket pkt;
        pkt.session_id = sid;
        pkt.target = target;
        pkt.payload.assign(data, data + len);
        tunnel->pending_bytes += pkt.payload.size();
        flow->second.pending_proxy_bytes += pkt.payload.size();
        tunnel->pending.push_back(std::move(pkt));
        return;
    }

    Buffer encoded;
    if (!tunnel->codec.encode_udp_packet(sid, target, data, len, encoded) ||
        !tunnel->tunnel_session || tunnel->tunnel_session->is_closed()) return;
    if (tunnel->tunnel_session->pending_write_bytes() + encoded.readable() >
        kMaxUdpTunnelWriteBacklog) {
        TX_WARN("Dropping UDP packet for %s: tunnel write backlog limit reached",
                tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
        return;
    }
    if (tunnel->tunnel_session->send(encoded)) {
        record_traffic(RouteAction::Proxy, true, len);
    }
}

bool ClientApp::parse_dns_upstream(const std::string& upstream, TargetAddr& target) const {
    std::string host;
    uint16_t port = 53;
    if (upstream.empty()) return false;

    const auto parse_port = [](const std::string& text, uint16_t& value) {
        if (text.empty()) return false;
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(text.c_str(), &end, 10);
        if (!end || *end != '\0' || parsed == 0 || parsed > 65535) return false;
        value = static_cast<uint16_t>(parsed);
        return true;
    };

    if (upstream.front() == '[') {
        const size_t close = upstream.find(']');
        if (close == std::string::npos) return false;
        host = upstream.substr(1, close - 1);
        if (close + 1 < upstream.size() &&
            (upstream[close + 1] != ':' ||
             !parse_port(upstream.substr(close + 2), port))) {
            return false;
        }
    } else if (is_numeric_ip_address(upstream)) {
        host = upstream;
    } else {
        const size_t colon = upstream.rfind(':');
        if (colon == std::string::npos ||
            !parse_port(upstream.substr(colon + 1), port)) {
            return false;
        }
        host = upstream.substr(0, colon);
    }

    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        target.type = AddrType::IPv4;
    } else if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
        target.type = AddrType::IPv6;
    } else {
        return false;
    }
    target.host = host;
    target.port = port;
    return true;
}

void ClientApp::resolve_dns_via_tunnel(std::vector<uint8_t> query,
                                       DnsResolver::ResolveCallback callback) {
    if (!callback) return;
    if (query.size() < 12 || query.size() > 65535 || config_.dns_upstreams.empty()) {
        callback(std::vector<uint8_t>());
        return;
    }

    const OutboundConfig* outbound = find_outbound(config_.dns_outbound_tag);
    if (!outbound || outbound->type != OutboundType::Tx) {
        TX_ERROR("Android DNS outboundTag must reference a TX outbound: %s",
                 config_.dns_outbound_tag.c_str());
        callback(std::vector<uint8_t>());
        return;
    }
    if (udp_flows_.size() >= config_.udp_max_flows) {
        TX_WARN("Dropping Android DNS query: configured UDP flow limit reached");
        callback(std::vector<uint8_t>());
        return;
    }

    UdpTunnelPtr tunnel = get_udp_tunnel(outbound);
    if (!ensure_udp_tunnel(tunnel)) {
        callback(std::vector<uint8_t>());
        return;
    }

    const SessionId session_id = allocate_session_id();
    if (session_id == 0) {
        TX_ERROR("Android DNS session ID space exhausted");
        callback(std::vector<uint8_t>());
        return;
    }

    const std::string flow_key = "internal-dns:" + std::to_string(session_id);
    UdpFlow flow;
    flow.session_id = session_id;
    flow.kind = UdpFlowKind::InternalDns;
    flow.last_activity_ms = uv_now(loop_);
    flow.outbound = outbound;
    flow.proxied = true;
    flow.dns_callback = std::move(callback);
    flow.dns_query = std::move(query);
    flow.dns_upstream_index = 0;
    udp_flows_.emplace(flow_key, std::move(flow));
    udp_session_keys_[session_id] = flow_key;
    start_internal_dns_attempt(flow_key);
}

void ClientApp::discard_pending_udp_packets(const UdpTunnelPtr& tunnel, SessionId sid) {
    if (!tunnel) return;
    for (auto pending = tunnel->pending.begin(); pending != tunnel->pending.end();) {
        if (pending->session_id != sid) {
            ++pending;
            continue;
        }
        tunnel->pending_bytes -= std::min(tunnel->pending_bytes,
                                          pending->payload.size());
        auto key = udp_session_keys_.find(sid);
        if (key != udp_session_keys_.end()) {
            auto flow = udp_flows_.find(key->second);
            if (flow != udp_flows_.end()) {
                flow->second.pending_proxy_bytes -= std::min(
                    flow->second.pending_proxy_bytes, pending->payload.size());
            }
        }
        pending = tunnel->pending.erase(pending);
    }
}

bool ClientApp::send_shared_tunnel_disconnect(const UdpTunnelPtr& tunnel,
                                               SessionId sid) {
    if (!tunnel || !tunnel->connected || !tunnel->tunnel_session ||
        tunnel->tunnel_session->is_closed()) {
        return false;
    }
    Buffer encoded;
    return tunnel->codec.encode_disconnect(sid, encoded) &&
           tunnel->tunnel_session->send(encoded);
}

bool ClientApp::rotate_internal_dns_session(const std::string& flow_key) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns) {
        return false;
    }
    UdpFlow& flow = it->second;
    udp_session_keys_.erase(flow.session_id);
    release_session_id(flow.session_id);
    flow.session_id = allocate_session_id();
    if (flow.session_id == 0) {
        TX_ERROR("Android DNS session ID space exhausted during retry");
        return false;
    }
    udp_session_keys_[flow.session_id] = flow_key;
    return true;
}

void ClientApp::start_internal_dns_attempt(const std::string& flow_key) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns) return;
    UdpFlow& flow = it->second;

    while (flow.dns_upstream_index < config_.dns_upstreams.size() &&
           !parse_dns_upstream(config_.dns_upstreams[flow.dns_upstream_index],
                               flow.dns_upstream)) {
        TX_WARN("Skipping invalid Android DNS upstream: %s",
                config_.dns_upstreams[flow.dns_upstream_index].c_str());
        ++flow.dns_upstream_index;
    }
    if (flow.dns_upstream_index >= config_.dns_upstreams.size()) {
        complete_internal_dns(flow_key, std::vector<uint8_t>(), false);
        return;
    }

    UdpTunnelPtr tunnel = get_udp_tunnel(flow.outbound);
    discard_pending_udp_packets(tunnel, flow.session_id);
    flow.dns_stage = InternalDnsStage::Udp;
    flow.dns_tcp_response.clear();
    flow.dns_deadline_ms = uv_now(loop_) + kInternalDnsStageTimeoutMs;
    flow.last_activity_ms = uv_now(loop_);
    TX_DEBUG("Android DNS query via upstream %s:%u (%zu/%zu)",
             flow.dns_upstream.host.c_str(), flow.dns_upstream.port,
             flow.dns_upstream_index + 1, config_.dns_upstreams.size());
    send_udp_packet(tunnel, flow.session_id, flow.dns_upstream,
                    flow.dns_query.data(), flow.dns_query.size());
    arm_internal_dns_timer();
}

void ClientApp::retry_internal_dns(const std::string& flow_key, const char* reason) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns) return;

    UdpFlow& flow = it->second;
    TX_WARN("Android DNS upstream %s:%u failed (%s)",
            flow.dns_upstream.host.c_str(), flow.dns_upstream.port,
            reason ? reason : "unknown");
    auto tunnel_it = flow.outbound ? udp_tunnels_.find(flow.outbound->tag)
                                   : udp_tunnels_.end();
    UdpTunnelPtr tunnel = tunnel_it != udp_tunnels_.end() ? tunnel_it->second
                                                           : UdpTunnelPtr();
    discard_pending_udp_packets(tunnel, flow.session_id);
    send_shared_tunnel_disconnect(tunnel, flow.session_id);
    flow.dns_deadline_ms = 0;
    flow.dns_tcp_response.clear();
    ++flow.dns_upstream_index;
    if (stopping_ || flow.dns_upstream_index >= config_.dns_upstreams.size()) {
        complete_internal_dns(flow_key, std::vector<uint8_t>(), false);
        return;
    }
    if (!rotate_internal_dns_session(flow_key)) {
        complete_internal_dns(flow_key, std::vector<uint8_t>(), false);
        return;
    }
    start_internal_dns_attempt(flow_key);
}

void ClientApp::start_internal_dns_tcp(const std::string& flow_key,
                                       const UdpTunnelPtr& tunnel) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns ||
        it->second.dns_stage != InternalDnsStage::Udp || !tunnel ||
        !tunnel->connected || !tunnel->tunnel_session ||
        tunnel->tunnel_session->is_closed()) {
        retry_internal_dns(flow_key, "TCP fallback unavailable");
        return;
    }

    UdpFlow& flow = it->second;
    discard_pending_udp_packets(tunnel, flow.session_id);
    send_shared_tunnel_disconnect(tunnel, flow.session_id);
    if (!rotate_internal_dns_session(flow_key)) {
        complete_internal_dns(flow_key, std::vector<uint8_t>(), false);
        return;
    }
    auto current = udp_flows_.find(flow_key);
    if (current == udp_flows_.end()) return;
    UdpFlow& tcp_flow = current->second;
    Buffer encoded;
    if (!tunnel->codec.encode(TunnelCmd::Connect, tcp_flow.session_id,
                              tcp_flow.dns_upstream, nullptr, 0, encoded) ||
        tunnel->tunnel_session->pending_write_bytes() + encoded.readable() >
            kMaxUdpTunnelWriteBacklog ||
        !tunnel->tunnel_session->send(encoded)) {
        retry_internal_dns(flow_key, "TCP fallback start failed");
        return;
    }
    tcp_flow.dns_stage = InternalDnsStage::TcpConnect;
    tcp_flow.dns_tcp_response.clear();
    tcp_flow.dns_deadline_ms = uv_now(loop_) + kInternalDnsStageTimeoutMs;
    TX_DEBUG("Android DNS UDP response was truncated; retrying %s:%u over TCP",
             tcp_flow.dns_upstream.host.c_str(), tcp_flow.dns_upstream.port);
    arm_internal_dns_timer();
}

void ClientApp::send_internal_dns_tcp_query(const std::string& flow_key,
                                            const UdpTunnelPtr& tunnel) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns ||
        it->second.dns_stage != InternalDnsStage::TcpConnect || !tunnel ||
        !tunnel->connected || !tunnel->tunnel_session ||
        tunnel->tunnel_session->is_closed()) {
        retry_internal_dns(flow_key, "TCP connect failed");
        return;
    }

    UdpFlow& flow = it->second;
    std::vector<uint8_t> wire(2 + flow.dns_query.size());
    store_be16(wire.data(), static_cast<uint16_t>(flow.dns_query.size()));
    std::copy(flow.dns_query.begin(), flow.dns_query.end(), wire.begin() + 2);
    Buffer encoded;
    if (!tunnel->codec.encode_data_chunks(flow.session_id, wire.data(), wire.size(), encoded) ||
        tunnel->tunnel_session->pending_write_bytes() + encoded.readable() >
            kMaxUdpTunnelWriteBacklog ||
        !tunnel->tunnel_session->send(encoded)) {
        retry_internal_dns(flow_key, "TCP query send failed");
        return;
    }
    record_traffic(RouteAction::Proxy, true, flow.dns_query.size());
    flow.dns_stage = InternalDnsStage::TcpResponse;
    flow.dns_deadline_ms = uv_now(loop_) + kInternalDnsStageTimeoutMs;
    arm_internal_dns_timer();
}

void ClientApp::handle_internal_dns_udp_response(const std::string& flow_key,
                                                 const UdpTunnelPtr& tunnel,
                                                 const TargetAddr& source,
                                                 const uint8_t* data, size_t len) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns ||
        it->second.dns_stage != InternalDnsStage::Udp || !data) return;
    UdpFlow& flow = it->second;
    if (!same_numeric_target(source, flow.dns_upstream)) {
        TX_DEBUG("Ignoring Android DNS response from stale upstream %s:%u",
                 source.host.c_str(), source.port);
        return;
    }

    std::vector<uint8_t> response(data, data + len);
    if (!DnsResolver::response_matches_query(flow.dns_query, response)) {
        TX_DEBUG("Ignoring Android DNS response that does not match the query");
        return;
    }
    if (DnsResolver::response_is_truncated(response)) {
        start_internal_dns_tcp(flow_key, tunnel);
        return;
    }
    record_traffic(RouteAction::Proxy, false, response.size());
    complete_internal_dns(flow_key, std::move(response), true);
}

void ClientApp::handle_internal_dns_tcp_data(const std::string& flow_key,
                                             const uint8_t* data, size_t len) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns ||
        it->second.dns_stage != InternalDnsStage::TcpResponse || !data || len == 0) return;
    UdpFlow& flow = it->second;
    if (len > kMaxDnsTcpWireSize ||
        flow.dns_tcp_response.readable() > kMaxDnsTcpWireSize - len) {
        retry_internal_dns(flow_key, "oversized TCP response");
        return;
    }
    flow.dns_tcp_response.append(data, len);
    if (flow.dns_tcp_response.readable() < 2) return;

    const uint16_t response_len = load_be16(flow.dns_tcp_response.data());
    if (response_len < 12) {
        retry_internal_dns(flow_key, "invalid TCP response length");
        return;
    }
    const size_t wire_len = 2 + static_cast<size_t>(response_len);
    if (flow.dns_tcp_response.readable() < wire_len) return;
    if (flow.dns_tcp_response.readable() != wire_len) {
        retry_internal_dns(flow_key, "unexpected trailing TCP response data");
        return;
    }

    std::vector<uint8_t> response(flow.dns_tcp_response.data() + 2,
                                  flow.dns_tcp_response.data() + wire_len);
    if (!DnsResolver::response_matches_query(flow.dns_query, response) ||
        DnsResolver::response_is_truncated(response)) {
        retry_internal_dns(flow_key, "invalid TCP response");
        return;
    }
    record_traffic(RouteAction::Proxy, false, response.size());
    complete_internal_dns(flow_key, std::move(response), true);
}

void ClientApp::complete_internal_dns(const std::string& flow_key,
                                      std::vector<uint8_t> response,
                                      bool notify_peer) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns) return;
    auto callback = std::move(it->second.dns_callback);
    it->second.dns_deadline_ms = 0;
    remove_udp_flow(flow_key, notify_peer);
    if (callback) callback(std::move(response));
}

void ClientApp::flush_pending_udp_packets(const UdpTunnelPtr& tunnel) {
    while (tunnel && tunnel->connected && !tunnel->pending.empty()) {
        PendingUdpPacket pkt = std::move(tunnel->pending.front());
        tunnel->pending.pop_front();
        tunnel->pending_bytes -= std::min(tunnel->pending_bytes, pkt.payload.size());
        auto key = udp_session_keys_.find(pkt.session_id);
        if (key != udp_session_keys_.end()) {
            auto flow = udp_flows_.find(key->second);
            if (flow != udp_flows_.end()) {
                flow->second.pending_proxy_bytes -= std::min(
                    flow->second.pending_proxy_bytes, pkt.payload.size());
            }
        }
        send_udp_packet(tunnel, pkt.session_id, pkt.target, pkt.payload.data(), pkt.payload.size());
    }
}

void ClientApp::on_udp_tunnel_handshake_read(const UdpTunnelPtr& tunnel, Buffer& data) {
    if (!tunnel || !tunnel->connecting) {
        data.clear();
        return;
    }
    tunnel->handshake_buf.append(data);
    data.clear();
    if (tunnel->handshake_buf.readable() < TunnelCodec::kHandshakeSize) return;

    TunnelTrafficKeys keys;
    if (!tunnel->outbound ||
        !TunnelCodec::parse_server_hello(tunnel->outbound->psk, tunnel->handshake_state,
                                          tunnel->handshake_buf.data(),
                                          TunnelCodec::kHandshakeSize, keys)) {
        TX_ERROR("UDP tunnel handshake failed");
        close_udp_tunnel(tunnel);
        return;
    }

    tunnel->handshake_buf.consume(TunnelCodec::kHandshakeSize);
    tunnel->codec = TunnelCodec(keys, true);
    TunnelCodec::cleanse_handshake_state(tunnel->handshake_state);
    tunnel->connecting = false;
    tunnel->connected = true;
    TX_INFO("UDP tunnel handshake complete for outbound %s", tunnel->outbound->tag.c_str());

    if (tunnel->tunnel_session && !tunnel->tunnel_session->is_closed()) {
        std::weak_ptr<UdpTunnel> weak_tunnel = tunnel;
        tunnel->tunnel_session->start_read([this, weak_tunnel](SessionPtr, Buffer& more) {
            if (UdpTunnelPtr current = weak_tunnel.lock()) {
                current->recv_buf.append(more);
                more.clear();
                on_udp_tunnel_read(current, current->recv_buf);
            } else {
                more.clear();
            }
        });
    }

    if (!tunnel->handshake_buf.empty()) {
        tunnel->recv_buf.append(tunnel->handshake_buf);
        tunnel->handshake_buf.clear();
        on_udp_tunnel_read(tunnel, tunnel->recv_buf);
    }
    flush_pending_udp_packets(tunnel);
}

void ClientApp::on_udp_tunnel_read(const UdpTunnelPtr& tunnel, Buffer& data) {
    if (!tunnel || !tunnel->connected) {
        data.clear();
        return;
    }
    TunnelCmd cmd;
    SessionId sid;
    TargetAddr target;
    Buffer payload;

    while (tunnel->codec.decode(data, cmd, sid, target, payload)) {
        auto key_it = udp_session_keys_.find(sid);
        auto flow_it = key_it == udp_session_keys_.end() ? udp_flows_.end()
                                                         : udp_flows_.find(key_it->second);
        if (flow_it == udp_flows_.end() || !flow_it->second.proxied ||
            flow_it->second.outbound != tunnel->outbound) {
            payload.clear();
            continue;
        }

        const std::string flow_key = key_it->second;
        if (flow_it->second.kind == UdpFlowKind::InternalDns) {
            switch (cmd) {
                case TunnelCmd::UdpPacket:
                    flow_it->second.last_activity_ms = uv_now(loop_);
                    handle_internal_dns_udp_response(flow_key, tunnel, target,
                                                     payload.data(), payload.readable());
                    break;
                case TunnelCmd::ConnectResult:
                    if (flow_it->second.dns_stage == InternalDnsStage::TcpConnect &&
                        payload.readable() == 1 && payload.data()[0] == 1) {
                        send_internal_dns_tcp_query(flow_key, tunnel);
                    } else {
                        retry_internal_dns(flow_key, "TCP connect rejected");
                    }
                    break;
                case TunnelCmd::Data:
                    handle_internal_dns_tcp_data(flow_key, payload.data(),
                                                 payload.readable());
                    break;
                case TunnelCmd::Disconnect:
                case TunnelCmd::HalfClose:
                    retry_internal_dns(flow_key, "remote TCP flow closed");
                    break;
                case TunnelCmd::Connect:
                    break;
            }
            payload.clear();
            continue;
        }

        if (cmd == TunnelCmd::UdpPacket) {
            flow_it->second.last_activity_ms = uv_now(loop_);
            send_udp_response_to_flow(flow_it->second, target, payload.data(),
                                      payload.readable(), RouteAction::Proxy);
        } else if (cmd == TunnelCmd::Disconnect) {
            remove_udp_flow(key_it->second, false);
        }
        payload.clear();
    }

    if (tunnel->codec.has_protocol_error()) {
        tunnel->codec.clear_protocol_error();
        close_udp_tunnel(tunnel);
    }
}

void ClientApp::close_udp_tunnel(const UdpTunnelPtr& tunnel) {
    if (!tunnel) return;
    auto session = std::move(tunnel->tunnel_session);
    tunnel->connected = false;
    tunnel->connecting = false;
    tunnel->handshake_buf.clear();
    tunnel->recv_buf.clear();
    for (const auto& packet : tunnel->pending) {
        auto key = udp_session_keys_.find(packet.session_id);
        if (key == udp_session_keys_.end()) continue;
        auto flow = udp_flows_.find(key->second);
        if (flow != udp_flows_.end()) {
            flow->second.pending_proxy_bytes -= std::min(
                flow->second.pending_proxy_bytes, packet.payload.size());
        }
    }
    tunnel->pending.clear();
    tunnel->pending_bytes = 0;
    tunnel->codec = TunnelCodec();
    TunnelCodec::cleanse_handshake_state(tunnel->handshake_state);
    std::vector<std::string> failed_dns_flows;
    for (const auto& item : udp_flows_) {
        if (item.second.kind == UdpFlowKind::InternalDns &&
            item.second.outbound == tunnel->outbound) {
            failed_dns_flows.push_back(item.first);
        }
    }
    for (const auto& flow_key : failed_dns_flows) remove_udp_flow(flow_key, false);
    if (session && !session->is_closed()) {
        session->set_close_callback(nullptr);
        session->close();
    }
}

void ClientApp::close_all_udp_tunnels() {
    std::vector<UdpTunnelPtr> tunnels;
    tunnels.reserve(udp_tunnels_.size());
    for (const auto& item : udp_tunnels_) tunnels.push_back(item.second);
    udp_tunnels_.clear();
    for (const auto& tunnel : tunnels) close_udp_tunnel(tunnel);
}

void ClientApp::on_udp_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    auto* data = static_cast<char*>(malloc(suggested_size));
    *buf = uv_buf_init(data, static_cast<unsigned int>(suggested_size));
}

void ClientApp::on_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                            const struct sockaddr* addr, unsigned flags) {
    std::unique_ptr<char, decltype(&free)> storage(buf->base, free);
    if (nread <= 0 || !addr) return;

    auto* app = static_cast<ClientApp*>(handle->data);
    TargetAddr target;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (!parse_socks5_udp_packet(reinterpret_cast<const uint8_t*>(buf->base),
                                  static_cast<size_t>(nread),
                                  target, payload, payload_len)) {
        return;
    }

    const std::string flow_key = sockaddr_key(addr) + ">" + target.host + ":" + std::to_string(target.port);
    auto it = app->udp_flows_.find(flow_key);
    if (it == app->udp_flows_.end()) {
        if (app->udp_flows_.size() >= app->config_.udp_max_flows) {
            TX_WARN("Dropping SOCKS5 UDP flow: configured flow limit reached");
            return;
        }
        UdpFlow flow;
        flow.session_id = app->allocate_session_id();
        if (flow.session_id == 0) {
            TX_ERROR("UDP session ID space exhausted");
            return;
        }
        flow.kind = UdpFlowKind::Socks5;
        flow.last_activity_ms = uv_now(app->loop_);
        memset(&flow.client_addr, 0, sizeof(flow.client_addr));
        if (addr->sa_family == AF_INET) {
            flow.client_addr_len = sizeof(sockaddr_in);
            memcpy(&flow.client_addr, addr, sizeof(sockaddr_in));
        } else {
            flow.client_addr_len = sizeof(sockaddr_in6);
            memcpy(&flow.client_addr, addr, sizeof(sockaddr_in6));
        }
        const SessionId session_id = flow.session_id;
        it = app->udp_flows_.emplace(flow_key, std::move(flow)).first;
        app->udp_session_keys_[session_id] = flow_key;
    }
    it->second.last_activity_ms = uv_now(app->loop_);

    RouteDecision decision = app->router_.decide_target(target);

    const OutboundConfig* outbound = app->find_outbound(decision.outbound_tag);
    if (!outbound) {
        TX_ERROR("UDP route selected unknown outboundTag: %s", decision.outbound_tag.c_str());
        return;
    }
    if (outbound->type == OutboundType::Block) {
        TX_DEBUG("[Block][UDP] %s:%u", target.host.c_str(), target.port);
        return;
    }
    if (outbound->type == OutboundType::Direct) {
        TX_DEBUG("[Direct][UDP] %s:%u", target.host.c_str(), target.port);
        app->send_direct_udp_packet(flow_key, it->second, target, payload, payload_len);
        return;
    }

    it->second.proxied = true;
    it->second.outbound = outbound;
    app->send_udp_packet(app->get_udp_tunnel(outbound), it->second.session_id,
                         target, payload, payload_len);
}

void ClientApp::on_udp_send_done(uv_udp_send_t* req, int status) {
    auto* buf = static_cast<uv_buf_t*>(req->data);
    delete[] buf->base;
    delete buf;
    delete req;
}

void ClientApp::on_direct_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                                   const struct sockaddr* addr, unsigned flags) {
    std::unique_ptr<char, decltype(&free)> storage(buf->base, free);
    if (nread <= 0 || !addr) return;

    auto* relay = static_cast<DirectUdpRelay*>(handle->data);
    if (!relay || !relay->app) return;

    ClientApp* app = relay->app;
    auto flow_it = app->udp_flows_.find(relay->flow_key);
    if (flow_it == app->udp_flows_.end() ||
        flow_it->second.session_id != relay->session_id) {
        return;
    }

    flow_it->second.last_activity_ms = uv_now(app->loop_);
    TargetAddr source = sockaddr_to_target(addr);
    app->send_udp_response_to_flow(flow_it->second, source,
                                   reinterpret_cast<const uint8_t*>(buf->base),
                                   static_cast<size_t>(nread),
                                   RouteAction::Direct);
}

void ClientApp::on_direct_udp_closed(uv_handle_t* handle) {
    auto* relay = static_cast<DirectUdpRelay*>(handle->data);
    delete relay;
}

bool ClientApp::start_tun_listener() {
    if (!config_.tun_enabled) return true;
    if (tun_started_) return true;
    if (config_.tun_fd < 0) {
        TX_INFO("TUN fd not provided; creating platform TUN device");
    }
    if ((config_.tun_tcp_stack != "system" && config_.tun_tcp_stack != "lwip") ||
        config_.tun_udp_stack != "lwip") {
        TX_ERROR("Unsupported TUN stack combination: tcp=%s udp=%s",
                 config_.tun_tcp_stack.c_str(), config_.tun_udp_stack.c_str());
        return false;
    }

    tun_device_ = PlatformTunDevice::create();
    if (!tun_device_) {
        TX_ERROR("TUN is not supported on this platform");
        return false;
    }

    std::string error;
    if (!tun_device_->open(config_, error)) {
        TX_ERROR("Failed to open TUN device: %s", error.c_str());
        tun_device_.reset();
        return false;
    }

    tun_fd_ = tun_device_->fd();
    // PlatformTunDevice now owns the descriptor; clear the config copy so
    // initialization-failure cleanup cannot close a recycled fd later.
    config_.tun_fd = -1;
    tun_read_buf_.resize(static_cast<size_t>(config_.tun_mtu > 0 ? config_.tun_mtu : 1500) + 256);

    if (!lwip_udp_stack_.initialize(
            config_.tun_addresses, config_.tun_mtu,
            [this](uint64_t flow_id, const IpAddr& source,
                   const IpAddr& destination, const uint8_t* data, size_t len) {
                handle_lwip_udp_datagram(flow_id, source, destination, data, len);
            },
            [this](const std::shared_ptr<LwipTcpStream>& stream,
                   const IpAddr& source, const TargetAddr& target) {
                on_lwip_tcp_accept(stream, source, target);
            },
            [this](const uint8_t* packet, size_t len) {
                if (!tun_device_) return false;
                std::string write_error;
                const bool written = tun_device_->write_packet(packet, len, write_error);
                if (!written && !write_error.empty()) {
                    TX_WARN("TUN write failed: %s", write_error.c_str());
                }
                return written;
            }, error)) {
        TX_ERROR("Failed to initialize HEV lwIP UDP stack: %s", error.c_str());
        tun_device_->close();
        tun_device_.reset();
        tun_fd_ = -1;
        return false;
    }

    if (tun_fd_ >= 0) {
        int r = uv_poll_init(loop_, &tun_poll_, tun_fd_);
        if (r != 0) {
            TX_ERROR("uv_poll_init for TUN fd failed: %s", uv_strerror(r));
            lwip_udp_stack_.shutdown();
            tun_device_.reset();
            tun_fd_ = -1;
            return false;
        }
        tun_poll_.data = this;

        r = uv_poll_start(&tun_poll_, UV_READABLE, ClientApp::on_tun_poll);
        if (r != 0) {
            TX_ERROR("uv_poll_start for TUN fd failed: %s", uv_strerror(r));
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_poll_), nullptr);
            lwip_udp_stack_.shutdown();
            tun_device_.reset();
            tun_fd_ = -1;
            return false;
        }
        r = uv_timer_init(loop_, &tun_timer_);
        if (r != 0) {
            TX_ERROR("uv_timer_init for lwIP failed: %s", uv_strerror(r));
            uv_poll_stop(&tun_poll_);
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_poll_), nullptr);
            lwip_udp_stack_.shutdown();
            tun_device_.reset();
            tun_fd_ = -1;
            return false;
        }
        tun_timer_.data = this;
        r = uv_timer_start(&tun_timer_, ClientApp::on_tun_timer, 1, 0);
        if (r != 0) {
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_timer_), nullptr);
            uv_poll_stop(&tun_poll_);
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_poll_), nullptr);
            lwip_udp_stack_.shutdown();
            tun_device_.reset();
            tun_fd_ = -1;
            return false;
        }
        tun_timer_started_ = true;
    } else {
        if (!tun_device_->start_async_reader(loop_, [this]() { drain_tun_packets(); }, error)) {
            TX_ERROR("Failed to start platform TUN reader: %s", error.c_str());
            lwip_udp_stack_.shutdown();
            tun_device_->close();
            tun_device_.reset();
            return false;
        }
        int r = uv_timer_init(loop_, &tun_timer_);
        if (r != 0) {
            TX_ERROR("uv_timer_init for TUN failed: %s", uv_strerror(r));
            lwip_udp_stack_.shutdown();
            tun_device_.reset();
            return false;
        }
        tun_timer_.data = this;
        r = uv_timer_start(&tun_timer_, ClientApp::on_tun_timer, 1, 0);
        if (r != 0) {
            TX_ERROR("uv_timer_start for TUN failed: %s", uv_strerror(r));
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_timer_), nullptr);
            lwip_udp_stack_.shutdown();
            tun_device_.reset();
            return false;
        }
        tun_timer_started_ = true;
    }

    if (!start_tun_tcp_redirect()) {
        if (tun_fd_ >= 0) {
            uv_poll_stop(&tun_poll_);
            if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&tun_poll_))) {
                uv_close(reinterpret_cast<uv_handle_t*>(&tun_poll_), nullptr);
            }
        }
        if (tun_timer_started_) {
            tun_timer_started_ = false;
            uv_timer_stop(&tun_timer_);
            if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&tun_timer_))) {
                uv_close(reinterpret_cast<uv_handle_t*>(&tun_timer_), nullptr);
            }
        }
        tun_device_->close();
        lwip_udp_stack_.shutdown();
        tun_device_.reset();
        tun_fd_ = -1;
        return false;
    }

    tun_started_ = true;
    return true;
}

void ClientApp::stop_tun_listener() {
    if (!tun_started_) return;
    tun_started_ = false;
    stop_tun_tcp_redirect();
    lwip_udp_stack_.shutdown();
    if (tun_fd_ >= 0) {
        uv_poll_stop(&tun_poll_);
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&tun_poll_))) {
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_poll_), nullptr);
        }
    }
    if (tun_timer_started_) {
        tun_timer_started_ = false;
        uv_timer_stop(&tun_timer_);
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&tun_timer_))) {
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_timer_), nullptr);
        }
    }
    if (tun_device_) {
        tun_device_->close();
        tun_device_.reset();
    }
    tun_fd_ = -1;
}

bool ClientApp::start_tun_tcp_redirect() {
    if (config_.tun_tcp_stack == "lwip") {
        TcpSession::set_outbound_mark(config_.tun_bypass_mark);
        return true;
    }
    if (!config_.tun_auto_redirect) {
        TcpSession::set_outbound_mark(0);
        return true;
    }

#if !defined(TX_PLATFORM_LINUX)
    TX_ERROR("tun.auto_redirect is only supported on Linux");
    return false;
#else
    tun_tcp_server_.set_accept_callback([this](SessionPtr s) { on_tun_tcp_accept(s); });
    if (!tun_tcp_server_.listen_transparent("0.0.0.0", config_.tun_redirect_port)) {
        TX_ERROR("Failed to start TUN TCP transparent listener on 0.0.0.0:%u",
                 config_.tun_redirect_port);
        return false;
    }

    TcpSession::set_outbound_mark(config_.tun_redirect_mark);
    if (!install_linux_auto_redirect(config_.tun_redirect_port,
                                     config_.tun_redirect_mark)) {
        TcpSession::set_outbound_mark(0);
        tun_tcp_server_.stop();
        TX_ERROR("Failed to install Linux tun.auto_redirect nft rules");
        return false;
    }

    tun_tcp_redirect_started_ = true;
    TX_INFO("  TUN TCP redirect: 0.0.0.0:%u mark=0x%s",
            config_.tun_redirect_port,
            hex_u32(config_.tun_redirect_mark).c_str());
    return true;
#endif
}

void ClientApp::stop_tun_tcp_redirect() {
    if (config_.tun_tcp_stack == "lwip") {
        TcpSession::set_outbound_mark(0);
        return;
    }
    if (!tun_tcp_redirect_started_) return;
    tun_tcp_redirect_started_ = false;
#if defined(TX_PLATFORM_LINUX)
    uninstall_linux_auto_redirect();
#endif
    TcpSession::set_outbound_mark(0);
    tun_tcp_server_.stop();
}

void ClientApp::on_tun_tcp_accept(SessionPtr session) {
    TargetAddr target;
#if defined(TX_PLATFORM_LINUX)
    if (!original_tcp_destination(session, target)) {
        TX_WARN("[TUN][TCP] failed to get original destination");
        session->close();
        return;
    }
#else
    session->close();
    return;
#endif

    auto conn = std::make_shared<ProxyConn>();
    conn->local_session = session;
    conn->socks5 = nullptr;
    conn->http = nullptr;
    conn->target = target;
    conn->route = RouteAction::Proxy;
    conn->outbound = nullptr;
    conn->connected = false;
    conn->connect_result_sent = false;

    std::string domain;
    if (fake_ip_dns_.reverse_lookup(conn->target.host, domain)) {
        conn->fake_ip_target = true;
        conn->target.type = AddrType::Domain;
        conn->target.host = domain;
    }
    const bool sniff_tls_sni = !conn->fake_ip_target && conn->target.port == 443;
    conn->target_dispatched = !sniff_tls_sni;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    conn->tunnel_timer = nullptr;
    conn->session_id = allocate_session_id();
    if (conn->session_id == 0) {
        TX_ERROR("TCP session ID space exhausted");
        session->close();
        return;
    }
    if (!admit_proxy_connection(conn)) {
        release_session_id(conn->session_id);
        session->close();
        return;
    }

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });
    session->set_eof_callback([this, conn](SessionPtr) { on_local_eof(conn); });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        conn->proto_buf.append(data);
        data.clear();

        if (!conn->target_dispatched) {
            std::string sni;
            const TlsSniResult result = extract_tls_sni(
                conn->proto_buf.data(), conn->proto_buf.readable(), sni);
            if (result == TlsSniResult::NeedMore && conn->proto_buf.readable() <= 65540)
                return;
            conn->target_dispatched = true;
            if (result == TlsSniResult::Found) {
                TX_INFO("[TUN][TLS] recovered domain %s for %s:%u",
                        sni.c_str(), conn->target.host.c_str(), conn->target.port);
                conn->target.type = AddrType::Domain;
                conn->target.host = std::move(sni);
            } else {
                TX_WARN("[TUN][TLS] no SNI for %s:%u; using original IP",
                        conn->target.host.c_str(), conn->target.port);
            }
            on_target_resolved(conn);
        }

        if (!conn->connected) {
            return;
        }
        if (conn->route == RouteAction::Direct && conn->direct_session) {
            size_t bytes = conn->proto_buf.readable();
            if (conn->bridge) conn->bridge->forward_from_left(conn->proto_buf);
            else conn->direct_session->send(conn->proto_buf);
            record_traffic(RouteAction::Direct, true, bytes);
            conn->proto_buf.clear();
        } else if (!conn->proto_buf.empty()) {
            tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
            conn->proto_buf.clear();
        }
    });

    TX_DEBUG("[TUN][TCP] accepted transparent flow to %s:%u",
             conn->target.host.c_str(), conn->target.port);
    if (conn->target_dispatched) {
        on_target_resolved(conn);
    }
}

void ClientApp::on_lwip_tcp_accept(const std::shared_ptr<LwipTcpStream>& stream,
                                   const IpAddr&, const TargetAddr& target) {
    if (!stream || config_.tun_tcp_stack != "lwip") {
        if (stream) stream->reset();
        return;
    }
    if (target.port == 53) {
        auto pending = std::make_shared<Buffer>();
        std::weak_ptr<LwipTcpStream> weak_stream = stream;
        stream->set_data_callback([this, weak_stream, pending](Buffer& data) {
            auto stream = weak_stream.lock();
            if (!stream) return;
            pending->append(data);
            data.clear();
            while (pending->readable() >= 2) {
                const uint16_t query_len = load_be16(pending->data());
                if (query_len > 4096) { stream->reset(); return; }
                if (pending->readable() < static_cast<size_t>(query_len) + 2) return;
                std::vector<uint8_t> query(pending->data() + 2,
                                           pending->data() + 2 + query_len);
                pending->consume(static_cast<size_t>(query_len) + 2);
                std::vector<uint8_t> response;
                const bool generated = fake_ip_dns_.respond(query.data(), query.size(), response);
                if (generated) {
                    static std::atomic<unsigned> tcp_dns_diagnostics{0};
                    Buffer framed(response.size() + 2);
                    uint8_t length[2];
                    store_be16(length, static_cast<uint16_t>(response.size()));
                    framed.append(length, 2);
                    if (!response.empty()) framed.append(response.data(), response.size());
                    const bool written = stream->write(framed);
                    const unsigned diagnostic = tcp_dns_diagnostics.fetch_add(1);
                    if (diagnostic < 12) {
                        TX_WARN("[DNS][TUN][TCP] query=%zu response=%zu written=%d",
                                query.size(), response.size(), written ? 1 : 0);
                    }
                    if (!written) stream->reset();
                }
                if (!generated && dns_resolver_.can_query()) {
                    dns_resolver_.resolve(query.data(), query.size(),
                        [weak_stream](std::vector<uint8_t> upstream) {
                            auto current = weak_stream.lock();
                            if (!current || current->is_closed() || upstream.empty()) return;
                            Buffer framed(upstream.size() + 2);
                            uint8_t length[2];
                            store_be16(length, static_cast<uint16_t>(upstream.size()));
                            framed.append(length, 2);
                            framed.append(upstream.data(), upstream.size());
                            if (!current->write(framed)) current->reset();
                        });
                }
            }
        });
        stream->set_eof_callback([weak_stream]() {
            if (auto stream = weak_stream.lock()) stream->shutdown_write();
        });
        return;
    }

    auto conn = std::make_shared<ProxyConn>();
    conn->local_session = stream;
    conn->target = target;
    std::string domain;
    if (fake_ip_dns_.reverse_lookup(conn->target.host, domain)) {
        conn->fake_ip_target = true;
        conn->target.type = AddrType::Domain;
        conn->target.host = domain;
    }
    const bool sniff_tls_sni = !conn->fake_ip_target && conn->target.port == 443;
    conn->route = RouteAction::Proxy;
    conn->outbound = nullptr;
    conn->connected = false;
    conn->connect_result_sent = false;
    conn->target_dispatched = !sniff_tls_sni;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    conn->tunnel_timer = nullptr;
    conn->session_id = allocate_session_id();
    if (conn->session_id == 0) {
        TX_ERROR("TCP session ID space exhausted");
        stream->reset();
        return;
    }
    if (!admit_proxy_connection(conn)) {
        release_session_id(conn->session_id);
        stream->reset();
        return;
    }

    stream->set_close_callback([this, conn]() { on_proxy_close(conn); });
    stream->set_eof_callback([this, conn]() { on_local_eof(conn); });
    stream->set_error_callback([conn](int) {
        if (conn->local_session && !conn->local_session->is_closed()) {
            conn->local_session->reset();
        }
    });
    stream->set_data_callback([this, conn](Buffer& data) {
        conn->proto_buf.append(data);
        data.clear();
        if (!conn->target_dispatched) {
            std::string sni;
            const TlsSniResult result = extract_tls_sni(
                conn->proto_buf.data(), conn->proto_buf.readable(), sni);
            if (result == TlsSniResult::NeedMore && conn->proto_buf.readable() <= 65540)
                return;
            conn->target_dispatched = true;
            if (result == TlsSniResult::Found) {
                TX_INFO("[TUN][TLS] recovered domain %s for %s:%u",
                        sni.c_str(), conn->target.host.c_str(), conn->target.port);
                conn->target.type = AddrType::Domain;
                conn->target.host = std::move(sni);
            } else {
                TX_WARN("[TUN][TLS] no SNI for %s:%u; using original IP",
                        conn->target.host.c_str(), conn->target.port);
            }
            on_target_resolved(conn);
        }
        if (!conn->connected) return;
        if (conn->route == RouteAction::Direct && conn->direct_session) {
            const size_t bytes = conn->proto_buf.readable();
            bool sent = conn->bridge ? conn->bridge->forward_from_left(conn->proto_buf)
                                     : conn->direct_session->send(conn->proto_buf);
            if (!sent) {
                conn->local_session->reset();
                return;
            }
            record_traffic(RouteAction::Direct, true, bytes);
        } else if (!conn->proto_buf.empty()) {
            tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
            conn->proto_buf.clear();
        }
    });
    TX_DEBUG("[TUN][lwIP][TCP] accepted flow to %s:%u",
             target.host.c_str(), target.port);
    if (conn->target_dispatched) on_target_resolved(conn);
}

void ClientApp::on_tun_poll(uv_poll_t* handle, int status, int events) {
    auto* app = static_cast<ClientApp*>(handle->data);
    if (!app || !app->tun_started_) return;
    if (status < 0) {
        TX_WARN("TUN poll error: %s", uv_strerror(status));
        return;
    }
    if ((events & UV_READABLE) == 0) return;
    app->drain_tun_packets();
}

void ClientApp::on_tun_timer(uv_timer_t* timer) {
    auto* app = static_cast<ClientApp*>(timer->data);
    if (!app || !app->tun_started_) return;
    app->lwip_udp_stack_.poll_timers();
    app->drain_tun_packets();
    if (app->tun_started_) {
        uv_timer_start(timer, ClientApp::on_tun_timer,
                       app->lwip_udp_stack_.next_timeout_ms(), 0);
    }
}

void ClientApp::drain_tun_packets() {
    if (!tun_device_) return;
    for (;;) {
        std::string error;
        std::ptrdiff_t nread = tun_device_->read_packet(tun_read_buf_.data(),
                                                        tun_read_buf_.size(),
                                                        error);
        if (nread > 0) {
            static std::atomic<unsigned> tun_packet_diagnostics{0};
            const unsigned diagnostic = tun_packet_diagnostics.fetch_add(1,
                                                                          std::memory_order_relaxed);
            if (diagnostic < 6) {
                const unsigned version = static_cast<unsigned>(tun_read_buf_[0] >> 4);
                TX_INFO("[TUN] input packet=%zu bytes version=%u", static_cast<size_t>(nread),
                        version);
            }
            handle_tun_packet(tun_read_buf_.data(), static_cast<size_t>(nread));
            continue;
        }
        if (nread < 0 && !error.empty()) {
            TX_WARN("TUN read failed: %s", error.c_str());
        }
        break;
    }
}

void ClientApp::handle_tun_packet(const uint8_t* data, size_t len) {
    lwip_udp_stack_.input(data, len);
}

bool ClientApp::finalize_tun_udp_route(UdpFlow& flow, const TargetAddr& route_target,
                                       const TargetAddr& send_target) {
    const RouteDecision decision = router_.decide_target(route_target);
    const OutboundConfig* outbound = find_outbound(decision.outbound_tag);
    if (!outbound) {
        TX_ERROR("TUN UDP route selected unknown outboundTag: %s",
                 decision.outbound_tag.c_str());
        return false;
    }

    release_tun_quic_sniffer(flow);
    flow.route_target = route_target;
    flow.send_target = send_target;
    flow.outbound = outbound;
    flow.proxied = outbound->type == OutboundType::Tx;
    flow.route_ready = true;
    return true;
}

void ClientApp::dispatch_tun_udp_packet(const std::string& flow_key, UdpFlow& flow,
                                        const uint8_t* data, size_t len) {
    if (!flow.route_ready || !flow.outbound || !data) return;

    const OutboundConfig* outbound = flow.outbound;
    if (outbound->type == OutboundType::Block) {
        TX_DEBUG("[TUN][Block][UDP] route=%s:%u send=%s:%u",
                 flow.route_target.host.c_str(), flow.route_target.port,
                 flow.send_target.host.c_str(), flow.send_target.port);
        return;
    }
    if (outbound->type == OutboundType::Direct) {
        TX_DEBUG("[TUN][Direct][UDP] route=%s:%u send=%s:%u",
                 flow.route_target.host.c_str(), flow.route_target.port,
                 flow.send_target.host.c_str(), flow.send_target.port);
        send_direct_udp_packet(flow_key, flow, flow.send_target, data, len);
        return;
    }

    // Keep domain targets intact for TX.  The server resolves them through
    // its own system resolver; dns.upstreams is only for local DNS handling.
    send_udp_packet(get_udp_tunnel(outbound), flow.session_id, flow.send_target, data, len);
}

void ClientApp::release_tun_quic_sniffer(UdpFlow& flow) {
    if (flow.quic_sniffer) {
        flow.quic_sniffer.reset();
        if (quic_sniff_active_flows_ > 0) --quic_sniff_active_flows_;
    }
    flow.quic_sniff_deadline_ms = 0;
}

void ClientApp::clear_tun_quic_pending(UdpFlow& flow) {
    quic_sniff_pending_bytes_ -= std::min(quic_sniff_pending_bytes_,
                                          flow.quic_pending_bytes);
    flow.quic_pending_packets.clear();
    flow.quic_pending_bytes = 0;
}

void ClientApp::flush_tun_quic_pending(const std::string& flow_key, UdpFlow& flow) {
    release_tun_quic_sniffer(flow);
    std::deque<std::vector<uint8_t>> pending;
    pending.swap(flow.quic_pending_packets);
    quic_sniff_pending_bytes_ -= std::min(quic_sniff_pending_bytes_,
                                          flow.quic_pending_bytes);
    flow.quic_pending_bytes = 0;
    for (const auto& packet : pending) {
        dispatch_tun_udp_packet(flow_key, flow, packet.data(), packet.size());
    }
}

void ClientApp::fallback_tun_quic_to_ip(const std::string& flow_key) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::Tun ||
        it->second.route_ready) {
        return;
    }
    UdpFlow& flow = it->second;
    const TargetAddr target = flow.send_target;
    if ((target.type != AddrType::IPv4 && target.type != AddrType::IPv6) ||
        !finalize_tun_udp_route(flow, target, target)) {
        release_tun_quic_sniffer(flow);
        clear_tun_quic_pending(flow);
        return;
    }
    flush_tun_quic_pending(flow_key, flow);
}

void ClientApp::process_tun_quic_packet(const std::string& flow_key, UdpFlow& flow,
                                        const uint8_t* data, size_t len) {
    if (!data) return;

    const bool exceeds_packet_limit = len > kMaxQuicSniffPendingBytesPerFlow ||
        flow.quic_pending_bytes > kMaxQuicSniffPendingBytesPerFlow - len;
    const bool exceeds_global_limit = len > kMaxQuicSniffPendingBytes ||
        quic_sniff_pending_bytes_ > kMaxQuicSniffPendingBytes - len;
    if (exceeds_packet_limit || exceeds_global_limit) {
        TX_DEBUG("[TUN][QUIC] sniff packet queue limit reached; using original IP");
        fallback_tun_quic_to_ip(flow_key);
        if (flow.route_ready) dispatch_tun_udp_packet(flow_key, flow, data, len);
        return;
    }

    if (!flow.quic_sniffer) {
        if (quic_sniff_active_flows_ >= kMaxQuicSniffActiveFlows) {
            TX_DEBUG("[TUN][QUIC] sniff flow limit reached; using original IP");
            fallback_tun_quic_to_ip(flow_key);
            if (flow.route_ready) dispatch_tun_udp_packet(flow_key, flow, data, len);
            return;
        }
        flow.quic_sniffer.reset(new QuicSniSniffer());
        ++quic_sniff_active_flows_;
        flow.quic_sniff_deadline_ms = uv_now(loop_) + kQuicSniffTimeoutMs;
    }

    flow.quic_pending_packets.emplace_back(data, data + len);
    flow.quic_pending_bytes += len;
    quic_sniff_pending_bytes_ += len;

    std::string host;
    const QuicSniResult result = flow.quic_sniffer->feed(data, len, host);
    if (result == QuicSniResult::Found) {
        TargetAddr route_target = flow.send_target;
        route_target.type = AddrType::Domain;
        route_target.host = std::move(host);
        TX_DEBUG("[TUN][QUIC] recovered domain %s for %s:%u",
                 route_target.host.c_str(), flow.send_target.host.c_str(),
                 flow.send_target.port);
        if (finalize_tun_udp_route(flow, route_target, flow.send_target)) {
            flush_tun_quic_pending(flow_key, flow);
        } else {
            release_tun_quic_sniffer(flow);
            clear_tun_quic_pending(flow);
        }
        return;
    }
    if (result == QuicSniResult::NeedMore) {
        arm_internal_dns_timer();
        return;
    }

    TX_DEBUG("[TUN][QUIC] SNI unavailable (%d); using original IP",
             static_cast<int>(result));
    fallback_tun_quic_to_ip(flow_key);
}

void ClientApp::handle_lwip_udp_datagram(uint64_t lwip_flow_id,
                                         const IpAddr& source,
                                         const IpAddr& destination,
                                         const uint8_t* data, size_t len) {
    TargetAddr target;
    target.type = destination.family == IpAddr::IPv4 ? AddrType::IPv4 : AddrType::IPv6;
    target.host = ipaddr_host_string(destination);
    target.port = destination.port;

    if (destination.port == 53) {
        static std::atomic<unsigned> dns_diagnostics{0};
        std::vector<uint8_t> query(data, data + len);
        std::vector<uint8_t> response;
        const bool generated = fake_ip_dns_.respond(query.data(), query.size(), response);
        const bool sent = generated && lwip_udp_stack_.send_response(
            lwip_flow_id, destination, response.data(), response.size());
        const unsigned diagnostic = dns_diagnostics.fetch_add(1);
        if (diagnostic < 12) {
            TX_WARN("[DNS][TUN] query=%zu response=%zu generated=%d sent=%d dst=%s",
                    query.size(), response.size(), generated ? 1 : 0, sent ? 1 : 0,
                    ipaddr_host_string(destination).c_str());
        }
        if (generated) {
            // DNS is a one-request/one-response flow here. It is intentionally
            // not inserted into udp_flows_, so release its lwIP PCB now.
            lwip_udp_stack_.close_flow(lwip_flow_id);
        } else if (dns_resolver_.can_query()) {
            dns_resolver_.resolve(query.data(), query.size(),
                [this, lwip_flow_id, destination](std::vector<uint8_t> upstream) {
                    if (!upstream.empty())
                        lwip_udp_stack_.send_response(lwip_flow_id, destination,
                                                      upstream.data(), upstream.size());
                    lwip_udp_stack_.close_flow(lwip_flow_id);
                });
        } else {
            lwip_udp_stack_.close_flow(lwip_flow_id);
        }
        return;
    }

    const TargetAddr numeric_target = target;
    std::string domain;
    const bool fake_ip = fake_ip_dns_.reverse_lookup(target.host, domain);
    if (fake_ip) {
        target.type = AddrType::Domain;
        target.host = domain;
    }

    const std::string flow_key = "tun:lwip:" + std::to_string(lwip_flow_id);

    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end()) {
        if (udp_flows_.size() >= config_.udp_max_flows) {
            TX_WARN("Dropping TUN UDP flow: configured flow limit reached");
            lwip_udp_stack_.close_flow(lwip_flow_id);
            return;
        }
        UdpFlow flow;
        flow.session_id = allocate_session_id();
        if (flow.session_id == 0) {
            TX_ERROR("TUN UDP session ID space exhausted");
            lwip_udp_stack_.close_flow(lwip_flow_id);
            return;
        }
        flow.kind = UdpFlowKind::Tun;
        flow.last_activity_ms = uv_now(loop_);
        flow.client_addr_len = 0;
        flow.tun_src_ip = source;
        flow.tun_dst_ip = destination;
        flow.lwip_flow_id = lwip_flow_id;
        const SessionId session_id = flow.session_id;
        it = udp_flows_.emplace(flow_key, std::move(flow)).first;
        udp_session_keys_[session_id] = flow_key;
    }
    UdpFlow& flow = it->second;
    flow.last_activity_ms = uv_now(loop_);
    if (flow.route_ready) {
        dispatch_tun_udp_packet(flow_key, flow, data, len);
        return;
    }

    if (fake_ip) {
        // Preserve the established fake-IP behavior: the domain is both the
        // routing target and the target sent to the existing UDP path.
        if (finalize_tun_udp_route(flow, target, target)) {
            dispatch_tun_udp_packet(flow_key, flow, data, len);
        }
        return;
    }

    flow.route_target = numeric_target;
    flow.send_target = numeric_target;
    if (numeric_target.port == 443 && config_.udp_quic_sniff) {
        process_tun_quic_packet(flow_key, flow, data, len);
        return;
    }

    if (finalize_tun_udp_route(flow, numeric_target, numeric_target)) {
        dispatch_tun_udp_packet(flow_key, flow, data, len);
    }
}

bool ClientApp::write_tun_udp_packet(const UdpFlow& flow, const TargetAddr& source,
                                     const uint8_t* data, size_t len) {
    if (!tun_started_ || !tun_device_) return false;

    IpAddr src = IpAddr::from_string(source.host, source.port);
    if (src.family != flow.tun_src_ip.family) {
        return false;
    }

    return lwip_udp_stack_.send_response(flow.lwip_flow_id, src, data, len);
}

void ClientApp::on_http_accept(SessionPtr session) {
    auto conn = std::make_shared<ProxyConn>();
    conn->local_session = session;
    conn->socks5 = nullptr;
    conn->http = std::make_unique<HttpProxyHandler>();
    conn->route = RouteAction::Proxy;
    conn->outbound = nullptr;
    conn->connected = false;
    conn->connect_result_sent = false;
    conn->target_dispatched = false;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    conn->tunnel_timer = nullptr;
    conn->session_id = allocate_session_id();
    if (conn->session_id == 0) {
        TX_ERROR("HTTP session ID space exhausted");
        session->close();
        return;
    }
    if (!admit_proxy_connection(conn)) {
        release_session_id(conn->session_id);
        session->close();
        return;
    }

    conn->http->set_target_callback([conn](const TargetAddr& target) {
        conn->target = target;
    });

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });
    session->set_eof_callback([this, conn](SessionPtr) { on_local_eof(conn); });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        // Accumulate into persistent buffer
        conn->proto_buf.append(data);
        data.clear();

        if (conn->http->state() == HttpProxyHandler::State::Connected && conn->connected) {
            // Fully connected — forward all buffered data
            if (!conn->proto_buf.empty()) {
                if (conn->route == RouteAction::Direct && conn->direct_session) {
                    size_t bytes = conn->proto_buf.readable();
                    if (conn->bridge) conn->bridge->forward_from_left(conn->proto_buf);
                    else conn->direct_session->send(conn->proto_buf);
                    record_traffic(RouteAction::Direct, true, bytes);
                    conn->proto_buf.clear();
                } else {
                    tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
                    conn->proto_buf.clear();
                }
            }
        } else if (conn->http->state() == HttpProxyHandler::State::Connected) {
            // CONNECT parsed but tunnel not ready yet — buffer data
            // proto_buf already accumulated, will be sent in connect_via_tunnel/connect_direct
        } else {
            // Parse HTTP CONNECT headers
            size_t consumed = conn->http->feed(conn->proto_buf.data(), conn->proto_buf.readable());
            conn->proto_buf.consume(consumed);
            if (conn->http->state() == HttpProxyHandler::State::Connected &&
                conn->http->mode() == HttpProxyHandler::Mode::Plain) {
                conn->proto_buf.clear();
                conn->proto_buf.append(conn->http->initial_payload());
            }
            if (conn->http->state() == HttpProxyHandler::State::Error) {
                Buffer resp;
                conn->http->build_error_response(400, resp);
                conn->local_session->send(resp);
                conn->local_session->close();
                return;
            }
            if (conn->http->state() == HttpProxyHandler::State::Connected &&
                !conn->target_dispatched) {
                conn->target_dispatched = true;
                on_target_resolved(conn);
            }
        }
    });
}

void ClientApp::on_socks5_accept(SessionPtr session) {
    auto conn = std::make_shared<ProxyConn>();
    conn->local_session = session;
    conn->socks5 = std::make_unique<Socks5Handler>();
    conn->http = nullptr;
    conn->route = RouteAction::Proxy;
    conn->outbound = nullptr;
    conn->connected = false;
    conn->connect_result_sent = false;
    conn->target_dispatched = false;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    conn->tunnel_timer = nullptr;
    conn->session_id = allocate_session_id();
    if (conn->session_id == 0) {
        TX_ERROR("SOCKS5 session ID space exhausted");
        session->close();
        return;
    }
    if (!admit_proxy_connection(conn)) {
        release_session_id(conn->session_id);
        session->close();
        return;
    }

    conn->socks5->set_target_callback([conn](const TargetAddr& target) {
        conn->target = target;
    });

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });
    session->set_eof_callback([this, conn](SessionPtr) { on_local_eof(conn); });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        // Accumulate into persistent buffer
        conn->proto_buf.append(data);
        data.clear();

        if (conn->socks5->state() == Socks5State::Connected && conn->connected) {
            // Fully connected — forward all buffered data
            if (!conn->proto_buf.empty()) {
                if (conn->route == RouteAction::Direct && conn->direct_session) {
                    size_t bytes = conn->proto_buf.readable();
                    if (conn->bridge) conn->bridge->forward_from_left(conn->proto_buf);
                    else conn->direct_session->send(conn->proto_buf);
                    record_traffic(RouteAction::Direct, true, bytes);
                    conn->proto_buf.clear();
                } else {
                    tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
                    conn->proto_buf.clear();
                }
            }
        } else if (conn->socks5->state() == Socks5State::Connected) {
            // CONNECT parsed but tunnel not ready yet — buffer data
        } else {
            // Loop to process handshake + CONNECT in one TCP segment
            while (!conn->proto_buf.empty()) {
                size_t consumed = conn->socks5->feed(conn->proto_buf.data(),
                                                      conn->proto_buf.readable());
                if (consumed == 0) break; // need more data
                conn->proto_buf.consume(consumed);

                if (conn->socks5->state() == Socks5State::Error) {
                    Buffer resp;
                    conn->socks5->build_connect_response(false, resp);
                    conn->local_session->send(resp);
                    conn->local_session->close();
                    return;
                }

                // After handshake → send NO AUTH response
                if (conn->socks5->state() == Socks5State::Request) {
                    Buffer resp;
                    uint8_t auth_resp[] = {0x05, 0x00};
                    resp.append(auth_resp, 2);
                    conn->local_session->send(resp);
                }

                if (conn->socks5->state() == Socks5State::Connected &&
                    !conn->target_dispatched) {
                    conn->target_dispatched = true;
                    if (conn->socks5->command() == Socks5Handler::Command::UdpAssociate) {
                        Buffer resp;
                        conn->socks5->build_connect_response(true, resp,
                                                             "127.0.0.1",
                                                             config_.socks5_port);
                        conn->local_session->send(resp);
                        conn->connected = true;
                        return;
                    }
                    on_target_resolved(conn);
                }
            }
        }
    });
}

void ClientApp::on_target_resolved(ProxyConnPtr conn) {
    TX_INFO("Target resolved: %s:%u", conn->target.host.c_str(), conn->target.port);

    // Route decision
    resolve_and_route(conn);
}

void ClientApp::resolve_and_route(ProxyConnPtr conn) {
    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    const RouteDecision decision = router_.decide_target(conn->target);
    // A decision is terminal even when its outbound blocks the connection or
    // is invalid. In particular, never continue to the fallback after a block.
    if (!apply_route_decision(conn, decision)) return;

    if (conn->route == RouteAction::Direct) {
        TX_INFO("[AsIs][Direct] %s:%u (%s -> %s)",
                conn->target.host.c_str(), conn->target.port,
                decision.matched ? "rule" : "fallback",
                conn->outbound ? conn->outbound->tag.c_str() : "");
        connect_direct(conn);
    } else {
        TX_INFO("[AsIs][Proxy] %s:%u (%s -> %s)",
                conn->target.host.c_str(), conn->target.port,
                decision.matched ? "rule" : "fallback",
                conn->outbound ? conn->outbound->tag.c_str() : "");
        connect_via_tunnel(conn);
    }
}

void ClientApp::connect_direct(ProxyConnPtr conn) {
    TX_INFO("[Direct] Connecting to %s:%u", conn->target.host.c_str(), conn->target.port);

    // Track direct flows as well as tunnel flows so Android network changes
    // can retire every socket bound to the previous physical Network.
    connections_[conn->session_id] = conn;

    dns_resolver_.resolve_host(conn->target.host, AF_UNSPEC,
        [this, conn](std::vector<std::string> result) {
            if (!conn || !conn->local_session || conn->local_session->is_closed()) return;
            if (result.empty()) {
                TX_ERROR("Direct DNS failed for %s", conn->target.host.c_str());
                block_connection(conn);
                return;
            }
            connect_direct_candidates(conn,
                std::make_shared<std::vector<std::string>>(std::move(result)), 0);
        });
}

void ClientApp::connect_direct_candidates(
    ProxyConnPtr conn, std::shared_ptr<std::vector<std::string>> addresses, size_t index) {
    if (!conn || !conn->local_session || conn->local_session->is_closed() ||
        connections_.find(conn->session_id) == connections_.end()) {
        return;
    }
    if (!addresses || index >= addresses->size()) {
        block_connection(conn);
        return;
    }

    auto direct = std::make_shared<TcpSession>(loop_, socket_protector_);
    conn->direct_session = direct;

    direct->set_close_callback([conn](SessionPtr) {
        if (conn->local_session && !conn->local_session->is_closed()) {
            // A graceful two-way EOF lets TcpSession close itself only after
            // its queued response writes and shutdown have completed.
            if (!(conn->local_eof && conn->remote_eof &&
                  std::dynamic_pointer_cast<TcpSession>(conn->local_session))) {
                conn->local_session->close();
            }
        }
    });
    direct->set_eof_callback([conn](SessionPtr) {
        conn->remote_eof = true;
        if (conn->local_session && !conn->local_session->is_closed()) {
            conn->local_session->shutdown_write();
        }
    });
    direct->set_error_callback([conn](SessionPtr, int) {
        if (conn->local_session && !conn->local_session->is_closed())
            conn->local_session->reset();
    });

    direct->connect((*addresses)[index], conn->target.port, kTcpConnectTimeoutMs,
        [this, conn, direct, addresses, index](bool success) {
            if (!conn->local_session || conn->local_session->is_closed() ||
                conn->direct_session != direct ||
                connections_.find(conn->session_id) == connections_.end()) {
                direct->set_close_callback(nullptr);
                if (!direct->is_closed()) direct->close();
                return;
            }
            if (!success) {
                direct->set_close_callback(nullptr);
                if (index + 1 < addresses->size()) {
                    connect_direct_candidates(conn, addresses, index + 1);
                    return;
                }
                TX_ERROR("Direct connect failed to %s:%u",
                         conn->target.host.c_str(), conn->target.port);
                if (conn->socks5) {
                    Buffer resp;
                    conn->socks5->build_connect_response(false, resp);
                    conn->local_session->send(resp);
                } else if (conn->http) {
                    Buffer resp;
                    conn->http->build_error_response(502, resp);
                    conn->local_session->send(resp);
                }
                if (!conn->socks5 && !conn->http && conn->local_session &&
                    !conn->local_session->is_closed()) {
                    conn->local_session->reset();
                }
                return;
            }

            conn->connected = true;
            conn->bridge = std::make_shared<TcpFlowBridge>(conn->local_session, direct);
            std::weak_ptr<TcpFlowBridge> weak_bridge = conn->bridge;
            direct->set_write_drain_callback([weak_bridge](SessionPtr) {
                if (auto bridge = weak_bridge.lock()) bridge->on_right_writable();
            });
            if (auto local_tcp = std::dynamic_pointer_cast<TcpSession>(conn->local_session)) {
                local_tcp->set_write_drain_callback([weak_bridge](SessionPtr) {
                    if (auto bridge = weak_bridge.lock()) bridge->on_left_writable();
                });
            } else if (auto local_lwip =
                       std::dynamic_pointer_cast<LwipTcpStream>(conn->local_session)) {
                local_lwip->set_writable_callback([weak_bridge]() {
                    if (auto bridge = weak_bridge.lock()) bridge->on_left_writable();
                });
            }

            // Send success response to local client
            if (conn->socks5) {
                Buffer resp;
                conn->socks5->build_connect_response(true, resp);
                conn->local_session->send(resp);
            } else if (conn->http &&
                       conn->http->mode() == HttpProxyHandler::Mode::Connect) {
                Buffer resp;
                conn->http->build_connect_response(resp);
                conn->local_session->send(resp);
            }

            // Flush any data buffered while waiting for connection
            if (!conn->proto_buf.empty()) {
                size_t bytes = conn->proto_buf.readable();
                conn->bridge->forward_from_left(conn->proto_buf);
                record_traffic(RouteAction::Direct, true, bytes);
                conn->proto_buf.clear();
            }

            // Start reading from direct connection
            direct->start_read([this, conn](SessionPtr, Buffer& data) {
                if (conn->local_session && !conn->local_session->is_closed()) {
                    record_traffic(RouteAction::Direct, false, data.readable());
                    if (conn->bridge) conn->bridge->forward_from_right(data);
                }
            });

            // EOF can arrive while DNS resolution or connect is pending.
            // Queue all buffered request bytes before propagating the FIN.
            if (conn->local_eof && !conn->local_half_close_sent &&
                !direct->is_closed()) {
                conn->local_half_close_sent = true;
                direct->shutdown_write();
            }
        });
}

void ClientApp::connect_via_tunnel(ProxyConnPtr conn) {
    if (!conn || !conn->outbound || conn->outbound->type != OutboundType::Tx) {
        block_connection(conn);
        return;
    }

    TX_INFO("[Proxy] Connecting via tunnel to %s:%u",
            conn->target.host.c_str(), conn->target.port);

    connections_[conn->session_id] = conn;

    if (!start_tunnel(conn)) {
        TX_ERROR("Failed to establish tunnel");
        fail_tunnel_connection(conn);
    }
}

bool ClientApp::start_tunnel(ProxyConnPtr conn) {
    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        return false;
    }
    if (conn->tunnel_session && (conn->tunnel_connected || conn->tunnel_connecting)) {
        return true;
    }

    const std::string server_host = conn->outbound->server_host;
    dns_resolver_.resolve_host(server_host, AF_UNSPEC,
        [this, conn](std::vector<std::string> addresses) {
            if (!conn || !conn->local_session || conn->local_session->is_closed()) return;
            if (addresses.empty()) {
                fail_tunnel_connection(conn);
                return;
            }
            connect_tunnel_candidates(conn,
                std::make_shared<std::vector<std::string>>(std::move(addresses)), 0);
        });
    conn->tunnel_connecting = true;
    return true;
}

void ClientApp::connect_tunnel_candidates(
    ProxyConnPtr conn, std::shared_ptr<std::vector<std::string>> addresses, size_t index) {
    if (!conn || !addresses || index >= addresses->size() || !conn->outbound ||
        !conn->local_session || conn->local_session->is_closed()) {
        if (conn) fail_tunnel_connection(conn);
        return;
    }
    auto tunnel = std::make_shared<TcpSession>(loop_, socket_protector_);
    conn->tunnel_session = tunnel;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = true;
    conn->tunnel_handshake_buf.clear();
    conn->tunnel_recv_buf.clear();
    TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
    tunnel->set_close_callback([this, conn, tunnel](SessionPtr) {
        TX_WARN("Tunnel disconnected for session %u", conn->session_id);
        if (conn->tunnel_session == tunnel) {
            conn->tunnel_connected = false;
            conn->tunnel_connecting = false;
            conn->tunnel_session.reset();
            fail_tunnel_connection(conn);
        }
    });
    tunnel->set_write_drain_callback([conn](SessionPtr tunnel_session) {
        if (conn->local_paused_for_tunnel && conn->local_session &&
            tunnel_session->pending_write_bytes() <= TcpFlowBridge::kLowWatermark) {
            conn->local_paused_for_tunnel = false;
            conn->local_session->resume_read();
        }
    });

    auto on_connected = [this, conn, tunnel, addresses, index](bool success) {
            if (!conn || conn->tunnel_session != tunnel ||
                !conn->local_session || conn->local_session->is_closed()) {
                if (tunnel && !tunnel->is_closed()) {
                    tunnel->close();
                }
                return;
            }

            if (success) {
                conn->tunnel_handshake_buf.clear();
                TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
                TX_INFO("Tunnel connected to %s:%u for session %u",
                        conn->outbound ? conn->outbound->server_host.c_str() : "",
                        conn->outbound ? conn->outbound->server_port : 0,
                        conn->session_id);

                tunnel->start_read([this, conn](SessionPtr, Buffer& data) {
                    on_tunnel_handshake_read(conn, data);
                });

                Buffer hello;
                if (!conn->outbound ||
                    !TunnelCodec::build_client_hello(conn->outbound->psk,
                                                      conn->outbound->cipher, hello,
                                                      conn->tunnel_handshake_state)) {
                    TX_ERROR("Failed to build tunnel handshake for session %u",
                             conn->session_id);
                    fail_tunnel_connection(conn);
                    return;
                }
                if (!tunnel->send(hello)) {
                    TX_ERROR("Failed to send tunnel ClientHello for session %u",
                             conn->session_id);
                    fail_tunnel_connection(conn);
                    return;
                }
                start_tunnel_timer(conn, kTunnelHandshakeTimeoutMs, "handshake");
            } else {
                tunnel->set_close_callback(nullptr);
                if (index + 1 < addresses->size()) {
                    conn->tunnel_session.reset();
                    connect_tunnel_candidates(conn, addresses, index + 1);
                    return;
                }
                conn->tunnel_connecting = false;
                conn->tunnel_connected = false;
                TX_ERROR("Tunnel connect failed to %s:%u for session %u",
                         conn->outbound ? conn->outbound->server_host.c_str() : "",
                         conn->outbound ? conn->outbound->server_port : 0,
                         conn->session_id);
                fail_tunnel_connection(conn);
            }
        };
    const uint16_t server_port = conn->outbound->server_port;
    tunnel->connect((*addresses)[index], server_port, kTcpConnectTimeoutMs,
                    on_connected);
}

void ClientApp::on_tunnel_handshake_read(ProxyConnPtr conn, Buffer& data) {
    if (!conn) {
        data.clear();
        return;
    }

    conn->tunnel_handshake_buf.append(data);
    data.clear();

    if (conn->tunnel_handshake_buf.readable() < TunnelCodec::kHandshakeSize) {
        return;
    }

    TunnelTrafficKeys keys;
    if (!conn->outbound ||
        !TunnelCodec::parse_server_hello(conn->outbound->psk,
                                          conn->tunnel_handshake_state,
                                          conn->tunnel_handshake_buf.data(),
                                          TunnelCodec::kHandshakeSize,
                                          keys)) {
        fail_tunnel_connection(conn);
        return;
    }

    conn->tunnel_handshake_buf.consume(TunnelCodec::kHandshakeSize);
    finish_tunnel_handshake(conn, keys);

    if (!conn->tunnel_handshake_buf.empty()) {
        conn->tunnel_recv_buf.append(conn->tunnel_handshake_buf);
        conn->tunnel_handshake_buf.clear();
        on_tunnel_read(conn, conn->tunnel_recv_buf);
    }
}

void ClientApp::finish_tunnel_handshake(ProxyConnPtr conn,
                                        const TunnelTrafficKeys& keys) {
    if (!conn || !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        return;
    }

    conn->tunnel_codec = TunnelCodec(keys, true);
    TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
    stop_tunnel_timer(conn);

    conn->tunnel_connecting = false;
    conn->tunnel_connected = true;
    TX_INFO("Tunnel handshake complete for session %u", conn->session_id);

    conn->tunnel_session->start_read([this, conn](SessionPtr, Buffer& data) {
        conn->tunnel_recv_buf.append(data);
        data.clear();
        on_tunnel_read(conn, conn->tunnel_recv_buf);
    });

    activate_tunnel_connection(conn);
}

void ClientApp::activate_tunnel_connection(ProxyConnPtr conn) {
    if (!conn || conn->connected ||
        !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    if (connections_.find(conn->session_id) == connections_.end()) {
        return;
    }

    tunnel_send_connect(conn);
    conn->connected = true;
    start_tunnel_timer(conn, kTunnelConnectResultTimeoutMs, "connect-result");
}

void ClientApp::complete_tunnel_connection(ProxyConnPtr conn) {
    if (!conn || conn->connect_result_sent ||
        !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    conn->connect_result_sent = true;
    stop_tunnel_timer(conn);
    TX_INFO("[Proxy] CONNECT established for session %u: %s:%u",
            conn->session_id, conn->target.host.c_str(), conn->target.port);

    std::weak_ptr<ProxyConn> weak_conn = conn;
    auto resume_tunnel = [weak_conn]() {
        auto current = weak_conn.lock();
        if (!current || !current->tunnel_paused_for_local ||
            !current->local_session || !current->tunnel_session) return;
        if (current->local_session->pending_write_bytes() <=
            TcpFlowBridge::kLowWatermark) {
            current->tunnel_paused_for_local = false;
            current->tunnel_session->resume_read();
        }
    };
    if (auto local_tcp = std::dynamic_pointer_cast<TcpSession>(conn->local_session)) {
        local_tcp->set_write_drain_callback([resume_tunnel](SessionPtr) { resume_tunnel(); });
    } else if (auto local_lwip =
               std::dynamic_pointer_cast<LwipTcpStream>(conn->local_session)) {
        local_lwip->set_writable_callback(std::move(resume_tunnel));
    }

    if (conn->socks5) {
        Buffer resp;
        conn->socks5->build_connect_response(true, resp);
        conn->local_session->send(resp);
    } else if (conn->http &&
               conn->http->mode() == HttpProxyHandler::Mode::Connect) {
        Buffer resp;
        conn->http->build_connect_response(resp);
        conn->local_session->send(resp);
    }

    if (!conn->pending_data.empty()) {
        tunnel_send(conn, conn->pending_data.data(), conn->pending_data.readable());
        conn->pending_data.clear();
    }

    if (!conn->proto_buf.empty()) {
        tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
        conn->proto_buf.clear();
    }

    // Preserve a FIN received while the tunnel or remote target was still
    // connecting. It must follow all buffered application data.
    if (conn->local_eof && !conn->local_half_close_sent) {
        tunnel_send_half_close(conn);
    }
}

void ClientApp::fail_tunnel_connection(ProxyConnPtr conn) {
    if (!conn) return;

    connections_.erase(conn->session_id);
    conn->connected = false;
    close_tunnel_session(conn);

    if (!conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    if (!conn->connect_result_sent) {
        if (conn->socks5) {
            Buffer resp;
            conn->socks5->build_connect_response(false, resp);
            conn->local_session->send(resp);
        } else if (conn->http) {
            Buffer resp;
            conn->http->build_error_response(502, resp);
            conn->local_session->send(resp);
        }
        if (!conn->socks5 && !conn->http) {
            conn->local_session->reset();
        }
        return;
    }

    if (std::dynamic_pointer_cast<LwipTcpStream>(conn->local_session))
        conn->local_session->reset();
    else
        conn->local_session->close();
}

void ClientApp::close_tunnel_session(ProxyConnPtr conn) {
    if (!conn) return;

    auto tunnel = conn->tunnel_session;
    conn->tunnel_session.reset();
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
    conn->tunnel_handshake_buf.clear();
    conn->tunnel_recv_buf.clear();
    stop_tunnel_timer(conn);

    if (tunnel && !tunnel->is_closed()) {
        tunnel->set_close_callback(nullptr);
        tunnel->close();
    }
}

void ClientApp::start_tunnel_timer(ProxyConnPtr conn, uint64_t timeout_ms, const char* phase) {
    if (!conn) return;

    stop_tunnel_timer(conn);

    auto* timer = new uv_timer_t;
    auto* ctx = new TunnelTimerCtx{this, conn, phase ? phase : "unknown"};
    timer->data = ctx;

    if (uv_timer_init(loop_, timer) != 0) {
        delete ctx;
        delete timer;
        return;
    }

    conn->tunnel_timer = timer;
    int r = uv_timer_start(timer, ClientApp::on_tunnel_timer, timeout_ms, 0);
    if (r != 0) {
        conn->tunnel_timer = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_tunnel_timer_closed);
    }
}

void ClientApp::stop_tunnel_timer(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_timer) return;

    auto* timer = conn->tunnel_timer;
    conn->tunnel_timer = nullptr;

    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_timer_stop(timer);
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_tunnel_timer_closed);
    }
}

void ClientApp::on_tunnel_timer(uv_timer_t* timer) {
    auto* ctx = static_cast<TunnelTimerCtx*>(timer->data);
    if (!ctx || !ctx->app) return;

    auto conn = ctx->conn;
    std::string phase = ctx->phase;
    if (!conn || conn->tunnel_timer != timer) {
        return;
    }

    conn->tunnel_timer = nullptr;
    TX_ERROR("Tunnel %s timeout for session %u: %s:%u",
             phase.c_str(), conn->session_id,
             conn->target.host.c_str(), conn->target.port);
    ctx->app->fail_tunnel_connection(conn);

    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_tunnel_timer_closed);
    }
}

void ClientApp::on_tunnel_timer_closed(uv_handle_t* handle) {
    auto* ctx = static_cast<TunnelTimerCtx*>(handle->data);
    delete ctx;
    delete reinterpret_cast<uv_timer_t*>(handle);
}

void ClientApp::tunnel_send_connect(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        fail_tunnel_connection(conn);
        return;
    }

    Buffer encoded;
    if (conn->tunnel_codec.encode(TunnelCmd::Connect, conn->session_id,
                                  conn->target, nullptr, 0, encoded)) {
        conn->tunnel_session->send(encoded);
    }
}

void ClientApp::tunnel_send(ProxyConnPtr conn, const uint8_t* data, size_t len) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        fail_tunnel_connection(conn);
        return;
    }

    Buffer encoded;
    if (!conn->tunnel_codec.encode_data_chunks(conn->session_id, data, len, encoded)) {
        return;
    }

    if (conn->tunnel_session->pending_write_bytes() + encoded.readable() >
        TcpFlowBridge::kHardLimit) {
        if (conn->local_session) conn->local_session->reset();
        fail_tunnel_connection(conn);
        return;
    }
    conn->tunnel_session->send(encoded);
    if (!conn->local_paused_for_tunnel && conn->local_session &&
        conn->tunnel_session->pending_write_bytes() >=
            TcpFlowBridge::kHighWatermark) {
        conn->local_paused_for_tunnel = true;
        conn->local_session->pause_read();
    }
    record_traffic(RouteAction::Proxy, true, len);
}

void ClientApp::tunnel_send_disconnect(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        return;
    }

    Buffer encoded;
    if (conn->tunnel_codec.encode_disconnect(conn->session_id, encoded)) {
        conn->tunnel_session->send(encoded);
    }
}

void ClientApp::tunnel_send_half_close(ProxyConnPtr conn) {
    if (!conn || conn->local_half_close_sent || !conn->connect_result_sent ||
        !conn->tunnel_connected || !conn->tunnel_session ||
        conn->tunnel_session->is_closed()) return;
    Buffer encoded;
    if (conn->tunnel_codec.encode_half_close(conn->session_id, encoded)) {
        if (conn->tunnel_session->send(encoded)) {
            conn->local_half_close_sent = true;
        }
    }
}

void ClientApp::on_local_eof(ProxyConnPtr conn) {
    if (!conn || conn->local_eof) return;
    conn->local_eof = true;
    if (conn->route == RouteAction::Direct) {
        if (conn->connected && !conn->local_half_close_sent &&
            conn->direct_session && !conn->direct_session->is_closed()) {
            conn->local_half_close_sent = true;
            conn->direct_session->shutdown_write();
        }
    } else if (conn->route == RouteAction::Proxy) {
        tunnel_send_half_close(conn);
    }
}

void ClientApp::on_tunnel_read(ProxyConnPtr conn, Buffer& data) {
    if (!conn) {
        data.clear();
        return;
    }

    TunnelCmd cmd;
    SessionId session_id;
    TargetAddr target;
    Buffer payload;

    while (conn->tunnel_codec.decode(data, cmd, session_id, target, payload)) {
        if (session_id != conn->session_id) {
            TX_WARN("Tunnel data for unexpected session %u on tunnel for session %u",
                    session_id, conn->session_id);
            continue;
        }

        switch (cmd) {
            case TunnelCmd::Data:
                if (!payload.empty() && conn->local_session &&
                    !conn->local_session->is_closed()) {
                    record_traffic(RouteAction::Proxy, false, payload.readable());
                    if (conn->local_session->pending_write_bytes() + payload.readable() >
                        TcpFlowBridge::kHardLimit || !conn->local_session->send(payload)) {
                        conn->local_session->reset();
                        fail_tunnel_connection(conn);
                        return;
                    }
                    if (!conn->tunnel_paused_for_local && conn->tunnel_session &&
                        conn->local_session->pending_write_bytes() >=
                            TcpFlowBridge::kHighWatermark) {
                        conn->tunnel_paused_for_local = true;
                        conn->tunnel_session->pause_read();
                    }
                }
                break;

            case TunnelCmd::ConnectResult:
                TX_INFO("[Proxy] CONNECT_RESULT session %u: %s",
                        session_id,
                        (!payload.empty() && payload.data()[0] == 1) ? "success" : "failure");
                if (!payload.empty() && payload.data()[0] == 1) {
                    complete_tunnel_connection(conn);
                } else {
                    TX_DEBUG("Tunnel connect failed for session %u", session_id);
                    fail_tunnel_connection(conn);
                }
                break;

            case TunnelCmd::Disconnect:
                TX_DEBUG("Tunnel disconnect for session %u", session_id);
                fail_tunnel_connection(conn);
                break;

            case TunnelCmd::HalfClose:
                conn->remote_eof = true;
                if (conn->local_session && !conn->local_session->is_closed()) {
                    conn->local_session->shutdown_write();
                }
                break;

            default:
                break;
        }
    }

    if (conn->tunnel_codec.has_protocol_error()) {
        TX_ERROR("Closing tunnel because remote data is not valid TX tunnel protocol");
        conn->tunnel_codec.clear_protocol_error();
        fail_tunnel_connection(conn);
    }
}

void ClientApp::on_proxy_close(ProxyConnPtr conn) {
    if (!conn) return;

    TX_DEBUG("Proxy connection closed, session %u", conn->session_id);

    if (conn->direct_session && !conn->direct_session->is_closed()) {
        conn->direct_session->set_close_callback(nullptr);
        conn->direct_session->close();
    }

    connections_.erase(conn->session_id);
    release_session_id(conn->session_id);
    if (conn->admitted) {
        conn->admitted = false;
        if (active_proxy_connections_ > 0) --active_proxy_connections_;
    }

    if (conn->route == RouteAction::Proxy) {
        tunnel_send_disconnect(conn);
        close_tunnel_session(conn);
    }
}

bool ClientApp::admit_proxy_connection(ProxyConnPtr conn) {
    if (!conn) return false;
    if (active_proxy_connections_ >= config_.max_proxy_connections) {
        TX_WARN("Rejecting proxy connection: configured connection limit reached");
        return false;
    }
    ++active_proxy_connections_;
    conn->admitted = true;
    return true;
}

SessionId ClientApp::allocate_session_id() {
    const SessionId first = next_session_id_;
    do {
        const SessionId candidate = next_session_id_++;
        if (candidate != 0 && active_session_ids_.insert(candidate).second) {
            return candidate;
        }
    } while (next_session_id_ != first);
    return 0;
}

void ClientApp::release_session_id(SessionId session_id) {
    if (session_id != 0) active_session_ids_.erase(session_id);
}

} // namespace tx
