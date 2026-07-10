#include "client_app.h"
#include "tx/common/log.h"
#include "tx/common/endian.h"

#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <random>
#include <cstdlib>
#include <sstream>
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

bool is_ip_literal(const std::string& host) {
    struct in_addr v4;
    struct in6_addr v6;
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool sockaddr_to_ipaddr(const sockaddr* addr, uint16_t port, IpAddr& out) {
    if (!addr) return false;

    if (addr->sa_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        out = IpAddr::from_ipv4(
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[0],
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[1],
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[2],
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[3],
            port);
        return true;
    }

    if (addr->sa_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        out = IpAddr::from_ipv6(reinterpret_cast<const uint8_t*>(&a6->sin6_addr), port);
        return true;
    }

    return false;
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

    bool ok = true;
    ok = run_auto_redirect_cmd("nft add table inet tx_auto_redirect") && ok;
    ok = run_auto_redirect_cmd(
        "nft 'add chain inet tx_auto_redirect output { type nat hook output priority dstnat; policy accept; }'") && ok;
    ok = run_auto_redirect_cmd(
        "nft add rule inet tx_auto_redirect output meta mark 0x" +
        hex_u32(mark) + " return") && ok;
    ok = run_auto_redirect_cmd(
        "nft 'add rule inet tx_auto_redirect output ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return'") && ok;
    ok = run_auto_redirect_cmd(
        "nft add rule inet tx_auto_redirect output ip protocol tcp redirect to :" +
        std::to_string(port)) && ok;
    return ok;
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

struct ClientApp::RouteDnsCtx {
    ClientApp* app;
    ProxyConnPtr conn;
};

struct ClientApp::TunnelTimerCtx {
    ClientApp* app;
    ProxyConnPtr conn;
    std::string phase;
};

struct ClientApp::UdpResolveCtx {
    ClientApp* app;
    std::string flow_key;
    TargetAddr target;
    std::vector<uint8_t> payload;
};

struct ClientApp::DirectUdpRelay {
    ClientApp* app;
    std::string flow_key;
    uv_udp_t handle;
    int family = AF_UNSPEC;
    bool recv_started = false;
};

ClientApp::ClientApp(SocketProtectCallback socket_protector)
    : loop_(uv_default_loop()),
      http_server_(loop_),
      socks5_server_(loop_),
      tun_tcp_server_(loop_),
      socks5_udp_started_(false),
      tun_fd_(-1),
      tun_started_(false),
      tun_timer_started_(false),
      tun_tcp_redirect_started_(false),
      next_session_id_(1),
      socket_protector_(std::move(socket_protector)) {}

ClientApp::~ClientApp() {
    stop();
}

bool ClientApp::init(const ClientConfig& config) {
    config_ = config;

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
    TX_INFO("  Outbounds:    %zu", config.outbounds.size());
    return true;
}

int ClientApp::run() {
    return uv_run(loop_, UV_RUN_DEFAULT);
}

void ClientApp::stop() {
    stop_tun_listener();
    stop_udp_listener();
    close_udp_tunnel();
    http_server_.stop();
    socks5_server_.stop();
    for (auto& kv : connections_) {
        auto& conn = kv.second;
        close_tunnel_session(conn);
        if (conn->direct_session && !conn->direct_session->is_closed()) {
            conn->direct_session->set_close_callback(nullptr);
            conn->direct_session->close();
        }
        if (conn->local_session && !conn->local_session->is_closed()) {
            conn->local_session->set_close_callback(nullptr);
            conn->local_session->close();
        }
    }
    connections_.clear();
    uv_stop(loop_);
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
    if (!socks5_udp_started_) return;
    socks5_udp_started_ = false;
    uv_udp_recv_stop(&socks5_udp_);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&socks5_udp_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&socks5_udp_), nullptr);
    }
    for (auto& kv : udp_flows_) {
        close_direct_udp_relay(kv.second);
    }
    udp_flows_.clear();
    udp_session_keys_.clear();
}

bool ClientApp::ensure_direct_udp_relay(const std::string& flow_key, UdpFlow& flow,
                                        int target_family) {
    if (flow.direct_relay) {
        return flow.direct_relay->family == target_family;
    }

    auto* relay = new DirectUdpRelay;
    relay->app = this;
    relay->flow_key = flow_key;
    relay->family = target_family;

    int r = uv_udp_init(loop_, &relay->handle);
    if (r != 0) {
        TX_ERROR("direct UDP init failed: %s", uv_strerror(r));
        delete relay;
        return false;
    }
    relay->handle.data = relay;

    if (socket_protector_) {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
        int socket_fd = ::socket(target_family, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            TX_ERROR("Failed to create direct UDP socket: %s", std::strerror(errno));
            uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                     ClientApp::on_direct_udp_closed);
            return false;
        }
        if (!socket_protector_(socket_fd)) {
            TX_ERROR("Socket protector rejected UDP fd %d", socket_fd);
            ::close(socket_fd);
            uv_close(reinterpret_cast<uv_handle_t*>(&relay->handle),
                     ClientApp::on_direct_udp_closed);
            return false;
        }
        r = uv_udp_open(&relay->handle, static_cast<uv_os_sock_t>(socket_fd));
        if (r != 0) {
            TX_ERROR("uv_udp_open for protected socket failed: %s", uv_strerror(r));
            ::close(socket_fd);
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

    auto* req = new uv_getaddrinfo_t;
    auto* ctx = new UdpResolveCtx;
    ctx->app = this;
    ctx->flow_key = flow_key;
    ctx->target = target;
    ctx->payload.assign(data, data + len);
    req->data = ctx;

    const std::string service = std::to_string(target.port);
    int r = uv_getaddrinfo(loop_, req, ClientApp::on_direct_udp_resolved,
                           target.host.c_str(), service.c_str(), nullptr);
    if (r != 0) {
        TX_WARN("[Direct][UDP] DNS lookup failed to start for %s:%u: %s",
                target.host.c_str(), target.port, uv_strerror(r));
        delete ctx;
        delete req;
    }
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

bool ClientApp::ensure_udp_tunnel() {
    if (udp_tunnel_.connected) return true;
    if (udp_tunnel_.connecting) return true;

    const OutboundConfig* outbound = udp_tunnel_.outbound;
    if (!outbound || outbound->type != OutboundType::Tx) {
        TX_ERROR("UDP proxy tunnel has no TX outbound selected");
        return false;
    }

    auto tunnel = std::make_shared<TcpSession>(loop_, socket_protector_);
    udp_tunnel_.tunnel_session = tunnel;
    udp_tunnel_.connected = false;
    udp_tunnel_.connecting = true;
    udp_tunnel_.handshake_buf.clear();
    udp_tunnel_.recv_buf.clear();
    TunnelCodec::cleanse_handshake_state(udp_tunnel_.handshake_state);

    tunnel->set_close_callback([this, tunnel](SessionPtr) {
        if (udp_tunnel_.tunnel_session == tunnel) {
            TX_WARN("UDP tunnel disconnected");
            close_udp_tunnel();
        }
    });

    tunnel->connect(outbound->server_host, outbound->server_port,
        [this, tunnel](bool success) {
            if (udp_tunnel_.tunnel_session != tunnel) {
                if (tunnel && !tunnel->is_closed()) tunnel->close();
                return;
            }
            if (!success) {
                TX_ERROR("UDP tunnel connect failed to %s:%u",
                         udp_tunnel_.outbound ? udp_tunnel_.outbound->server_host.c_str() : "",
                         udp_tunnel_.outbound ? udp_tunnel_.outbound->server_port : 0);
                close_udp_tunnel();
                return;
            }

            tunnel->start_read([this](SessionPtr, Buffer& data) {
                on_udp_tunnel_handshake_read(data);
            });

            Buffer hello;
            if (!udp_tunnel_.outbound ||
                !TunnelCodec::build_client_hello(udp_tunnel_.outbound->psk,
                                                  udp_tunnel_.outbound->cipher, hello,
                                                  udp_tunnel_.handshake_state)) {
                TX_ERROR("Failed to build UDP tunnel handshake");
                close_udp_tunnel();
                return;
            }
            tunnel->send(hello);
        });

    return true;
}

void ClientApp::send_udp_packet(SessionId sid, const TargetAddr& target,
                                const uint8_t* data, size_t len) {
    if (!ensure_udp_tunnel()) return;

    if (!udp_tunnel_.connected) {
        PendingUdpPacket pkt;
        pkt.session_id = sid;
        pkt.target = target;
        pkt.payload.assign(data, data + len);
        if (udp_tunnel_.pending.size() < 1024) {
            udp_tunnel_.pending.push_back(std::move(pkt));
        }
        return;
    }

    Buffer encoded;
    if (udp_tunnel_.codec.encode_udp_packet(sid, target, data, len, encoded) &&
        udp_tunnel_.tunnel_session && !udp_tunnel_.tunnel_session->is_closed()) {
        udp_tunnel_.tunnel_session->send(encoded);
        record_traffic(RouteAction::Proxy, true, len);
    }
}

void ClientApp::flush_pending_udp_packets() {
    while (udp_tunnel_.connected && !udp_tunnel_.pending.empty()) {
        PendingUdpPacket pkt = std::move(udp_tunnel_.pending.front());
        udp_tunnel_.pending.pop_front();
        send_udp_packet(pkt.session_id, pkt.target, pkt.payload.data(), pkt.payload.size());
    }
}

void ClientApp::on_udp_tunnel_handshake_read(Buffer& data) {
    udp_tunnel_.handshake_buf.append(data);
    data.clear();
    if (udp_tunnel_.handshake_buf.readable() < TunnelCodec::kHandshakeSize) return;

    TunnelTrafficKeys keys;
    if (!udp_tunnel_.outbound ||
        !TunnelCodec::parse_server_hello(udp_tunnel_.outbound->psk,
                                          udp_tunnel_.handshake_state,
                                          udp_tunnel_.handshake_buf.data(),
                                          TunnelCodec::kHandshakeSize,
                                          keys)) {
        TX_ERROR("UDP tunnel handshake failed");
        close_udp_tunnel();
        return;
    }

    udp_tunnel_.handshake_buf.consume(TunnelCodec::kHandshakeSize);
    udp_tunnel_.codec = TunnelCodec(keys, true);
    TunnelCodec::cleanse_handshake_state(udp_tunnel_.handshake_state);
    udp_tunnel_.connecting = false;
    udp_tunnel_.connected = true;
    TX_INFO("UDP tunnel handshake complete");

    if (udp_tunnel_.tunnel_session && !udp_tunnel_.tunnel_session->is_closed()) {
        udp_tunnel_.tunnel_session->start_read([this](SessionPtr, Buffer& more) {
            udp_tunnel_.recv_buf.append(more);
            more.clear();
            on_udp_tunnel_read(udp_tunnel_.recv_buf);
        });
    }

    if (!udp_tunnel_.handshake_buf.empty()) {
        udp_tunnel_.recv_buf.append(udp_tunnel_.handshake_buf);
        udp_tunnel_.handshake_buf.clear();
        on_udp_tunnel_read(udp_tunnel_.recv_buf);
    }
    flush_pending_udp_packets();
}

void ClientApp::on_udp_tunnel_read(Buffer& data) {
    TunnelCmd cmd;
    SessionId sid;
    TargetAddr target;
    Buffer payload;

    while (udp_tunnel_.codec.decode(data, cmd, sid, target, payload)) {
        if (cmd == TunnelCmd::UdpPacket) {
            auto key_it = udp_session_keys_.find(sid);
            if (key_it == udp_session_keys_.end()) {
                payload.clear();
                continue;
            }
            auto flow_it = udp_flows_.find(key_it->second);
            if (flow_it == udp_flows_.end()) {
                payload.clear();
                continue;
            }

            send_udp_response_to_flow(flow_it->second, target,
                                      payload.data(), payload.readable(),
                                      RouteAction::Proxy);
        } else if (cmd == TunnelCmd::Disconnect) {
            udp_session_keys_.erase(sid);
        }
        payload.clear();
    }

    if (udp_tunnel_.codec.has_protocol_error()) {
        udp_tunnel_.codec.clear_protocol_error();
        close_udp_tunnel();
    }
}

void ClientApp::close_udp_tunnel() {
    auto tunnel = udp_tunnel_.tunnel_session;
    udp_tunnel_ = UdpTunnel();
    if (tunnel && !tunnel->is_closed()) {
        tunnel->set_close_callback(nullptr);
        tunnel->close();
    }
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
        UdpFlow flow;
        flow.session_id = app->next_session_id_++;
        flow.kind = UdpFlowKind::Socks5;
        memset(&flow.client_addr, 0, sizeof(flow.client_addr));
        if (addr->sa_family == AF_INET) {
            flow.client_addr_len = sizeof(sockaddr_in);
            memcpy(&flow.client_addr, addr, sizeof(sockaddr_in));
        } else {
            flow.client_addr_len = sizeof(sockaddr_in6);
            memcpy(&flow.client_addr, addr, sizeof(sockaddr_in6));
        }
        it = app->udp_flows_.emplace(flow_key, flow).first;
        app->udp_session_keys_[flow.session_id] = flow_key;
    }

    RouteDecision decision;
    if (target.type == AddrType::Domain) {
        decision = app->router_.decide_by_host(target.host);
        if (!decision.matched) {
            decision = app->router_.fallback_decision();
        }
    } else {
        IpAddr ip = IpAddr::from_string(target.host, target.port);
        decision = app->router_.decide_by_ip(ip);
    }

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

    if (app->udp_tunnel_.outbound && app->udp_tunnel_.outbound != outbound) {
        app->close_udp_tunnel();
    }
    app->udp_tunnel_.outbound = outbound;
    app->send_udp_packet(it->second.session_id, target, payload, payload_len);
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
    if (flow_it == app->udp_flows_.end()) {
        return;
    }

    TargetAddr source = sockaddr_to_target(addr);
    app->send_udp_response_to_flow(flow_it->second, source,
                                   reinterpret_cast<const uint8_t*>(buf->base),
                                   static_cast<size_t>(nread),
                                   RouteAction::Direct);
}

void ClientApp::on_direct_udp_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    auto* ctx = static_cast<UdpResolveCtx*>(req->data);
    ClientApp* app = ctx->app;

    if (status < 0 || !res) {
        TX_WARN("[Direct][UDP] DNS lookup failed for %s:%u: %s",
                ctx->target.host.c_str(), ctx->target.port,
                status < 0 ? uv_strerror(status) : "no results");
        if (res) uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    auto flow_it = app->udp_flows_.find(ctx->flow_key);
    if (flow_it == app->udp_flows_.end()) {
        uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    const sockaddr* target_addr = nullptr;
    for (auto* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
            target_addr = ai->ai_addr;
            break;
        }
    }

    if (!target_addr ||
        !app->ensure_direct_udp_relay(ctx->flow_key, flow_it->second, target_addr->sa_family)) {
        uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    auto* send_req = new uv_udp_send_t;
    auto* data_copy = new char[ctx->payload.size()];
    memcpy(data_copy, ctx->payload.data(), ctx->payload.size());
    auto* send_buf = new uv_buf_t;
    *send_buf = uv_buf_init(data_copy, static_cast<unsigned int>(ctx->payload.size()));
    send_req->data = send_buf;

    int r = uv_udp_send(send_req, &flow_it->second.direct_relay->handle, send_buf, 1,
                        target_addr, ClientApp::on_udp_send_done);
    if (r != 0) {
        TX_WARN("[Direct][UDP] send failed to %s:%u: %s",
                ctx->target.host.c_str(), ctx->target.port, uv_strerror(r));
        delete[] send_buf->base;
        delete send_buf;
        delete send_req;
    } else {
        app->record_traffic(RouteAction::Direct, true, ctx->payload.size());
    }

    uv_freeaddrinfo(res);
    delete ctx;
    delete req;
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
    if (config_.tun_mode != "mixed") {
        TX_ERROR("Unsupported TUN mode: %s", config_.tun_mode.c_str());
        return false;
    }
    if (config_.tun_tcp_stack != "system" || config_.tun_udp_stack != "gvisor") {
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
    tun_read_buf_.resize(static_cast<size_t>(config_.tun_mtu > 0 ? config_.tun_mtu : 1500) + 256);

    if (tun_fd_ >= 0) {
        int r = uv_poll_init(loop_, &tun_poll_, tun_fd_);
        if (r != 0) {
            TX_ERROR("uv_poll_init for TUN fd failed: %s", uv_strerror(r));
            tun_device_.reset();
            tun_fd_ = -1;
            return false;
        }
        tun_poll_.data = this;

        r = uv_poll_start(&tun_poll_, UV_READABLE, ClientApp::on_tun_poll);
        if (r != 0) {
            TX_ERROR("uv_poll_start for TUN fd failed: %s", uv_strerror(r));
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_poll_), nullptr);
            tun_device_.reset();
            tun_fd_ = -1;
            return false;
        }
    } else {
        int r = uv_timer_init(loop_, &tun_timer_);
        if (r != 0) {
            TX_ERROR("uv_timer_init for TUN failed: %s", uv_strerror(r));
            tun_device_.reset();
            return false;
        }
        tun_timer_.data = this;
        r = uv_timer_start(&tun_timer_, ClientApp::on_tun_timer, 1, 1);
        if (r != 0) {
            TX_ERROR("uv_timer_start for TUN failed: %s", uv_strerror(r));
            uv_close(reinterpret_cast<uv_handle_t*>(&tun_timer_), nullptr);
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
    conn->target_dispatched = true;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    conn->tunnel_timer = nullptr;
    conn->session_id = next_session_id_++;

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        conn->proto_buf.append(data);
        data.clear();

        if (!conn->connected) {
            return;
        }
        if (conn->route == RouteAction::Direct && conn->direct_session) {
            size_t bytes = conn->proto_buf.readable();
            conn->direct_session->send(conn->proto_buf);
            record_traffic(RouteAction::Direct, true, bytes);
            conn->proto_buf.clear();
        } else if (!conn->proto_buf.empty()) {
            tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
            conn->proto_buf.clear();
        }
    });

    TX_DEBUG("[TUN][TCP] accepted transparent flow to %s:%u",
             conn->target.host.c_str(), conn->target.port);
    on_target_resolved(conn);
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
    app->drain_tun_packets();
}

void ClientApp::drain_tun_packets() {
    if (!tun_device_) return;
    for (;;) {
        std::string error;
        std::ptrdiff_t nread = tun_device_->read_packet(tun_read_buf_.data(),
                                                        tun_read_buf_.size(),
                                                        error);
        if (nread > 0) {
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
    TunPacketView packet;
    if (!parse_tun_packet(data, len, packet)) {
        return;
    }

    if (packet.protocol == TunL4Protocol::Tcp) {
        TX_DEBUG("[TUN][TCP] system stack packet %s:%u -> %s:%u ignored by UDP path",
                 packet.src_ip.to_string().c_str(), packet.src_port,
                 packet.dst_ip.to_string().c_str(), packet.dst_port);
        return;
    }

    TargetAddr target;
    target.type = packet.dst_ip.family == IpAddr::IPv4 ? AddrType::IPv4 : AddrType::IPv6;
    target.host = ipaddr_host_string(packet.dst_ip);
    target.port = packet.dst_port;

    const std::string flow_key =
        std::string("tun:") + packet.src_ip.to_string() + ">" +
        packet.dst_ip.to_string() + "/" + std::to_string(static_cast<int>(packet.protocol));

    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end()) {
        UdpFlow flow;
        flow.session_id = next_session_id_++;
        flow.kind = UdpFlowKind::Tun;
        flow.client_addr_len = 0;
        flow.tun_src_ip = packet.src_ip;
        flow.tun_dst_ip = packet.dst_ip;
        it = udp_flows_.emplace(flow_key, flow).first;
        udp_session_keys_[flow.session_id] = flow_key;
    }

    RouteDecision decision = router_.decide_by_ip(packet.dst_ip);
    const OutboundConfig* outbound = find_outbound(decision.outbound_tag);
    if (!outbound) {
        TX_ERROR("TUN UDP route selected unknown outboundTag: %s",
                 decision.outbound_tag.c_str());
        return;
    }
    if (outbound->type == OutboundType::Block) {
        TX_DEBUG("[TUN][Block][UDP] %s:%u", target.host.c_str(), target.port);
        return;
    }
    if (outbound->type == OutboundType::Direct) {
        TX_DEBUG("[TUN][Direct][UDP] %s:%u", target.host.c_str(), target.port);
        send_direct_udp_packet(flow_key, it->second, target,
                               packet.payload, packet.payload_len);
        return;
    }

    if (udp_tunnel_.outbound && udp_tunnel_.outbound != outbound) {
        close_udp_tunnel();
    }
    udp_tunnel_.outbound = outbound;
    send_udp_packet(it->second.session_id, target, packet.payload, packet.payload_len);
}

bool ClientApp::write_tun_udp_packet(const UdpFlow& flow, const TargetAddr& source,
                                     const uint8_t* data, size_t len) {
    if (!tun_started_ || !tun_device_) return false;

    IpAddr src = IpAddr::from_string(source.host);
    if (src.family != flow.tun_src_ip.family) {
        return false;
    }

    Buffer packet;
    if (!build_udp_tun_packet(src, source.port,
                              flow.tun_src_ip, flow.tun_src_ip.port,
                              data, len, packet)) {
        return false;
    }

    std::string error;
    if (!tun_device_->write_packet(packet.data(), packet.readable(), error)) {
        if (!error.empty()) {
            TX_WARN("TUN write failed: %s", error.c_str());
        }
        return false;
    }
    return true;
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
    conn->session_id = next_session_id_++;

    conn->http->set_target_callback([this, conn](const TargetAddr& target) {
        conn->target = target;
    });

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        // Accumulate into persistent buffer
        conn->proto_buf.append(data);
        data.clear();

        if (conn->http->state() == HttpProxyHandler::State::Connected && conn->connected) {
            // Fully connected — forward all buffered data
            if (!conn->proto_buf.empty()) {
                if (conn->route == RouteAction::Direct && conn->direct_session) {
                    size_t bytes = conn->proto_buf.readable();
                    conn->direct_session->send(conn->proto_buf);
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
    conn->session_id = next_session_id_++;

    conn->socks5->set_target_callback([this, conn](const TargetAddr& target) {
        conn->target = target;
    });

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        // Accumulate into persistent buffer
        conn->proto_buf.append(data);
        data.clear();

        if (conn->socks5->state() == Socks5State::Connected && conn->connected) {
            // Fully connected — forward all buffered data
            if (!conn->proto_buf.empty()) {
                if (conn->route == RouteAction::Direct && conn->direct_session) {
                    size_t bytes = conn->proto_buf.readable();
                    conn->direct_session->send(conn->proto_buf);
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

    RouteDecision host_decision = router_.decide_by_host(conn->target.host);
    bool host_rule_matched = host_decision.matched;

    if (host_rule_matched && apply_route_decision(conn, host_decision)) {
        if (conn->route == RouteAction::Direct) {
            TX_INFO("[Direct] %s:%u (domain rule -> %s)",
                    conn->target.host.c_str(), conn->target.port,
                    conn->outbound ? conn->outbound->tag.c_str() : "");
            connect_direct(conn);
        } else if (conn->route == RouteAction::Proxy) {
            TX_INFO("[Proxy] %s:%u (domain rule -> %s)",
                    conn->target.host.c_str(), conn->target.port,
                    conn->outbound ? conn->outbound->tag.c_str() : "");
            connect_via_tunnel(conn);
        }
        return;
    }

    if (conn->target.type == AddrType::Domain) {
        resolve_domain_and_route(conn);
        return;
    }

    IpAddr ip = IpAddr::from_string(conn->target.host, conn->target.port);
    if (conn->target.type == AddrType::Domain && ip.is_lan() && !is_ip_literal(conn->target.host)) {
        TX_WARN("[Proxy] %s:%u resolved to private/local address %s, forcing proxy",
                conn->target.host.c_str(), conn->target.port, ip.to_string().c_str());
        RouteDecision decision = router_.decide_by_ip(ip);
        if (apply_route_decision(conn, decision)) {
            if (conn->route == RouteAction::Direct) {
                connect_direct(conn);
            } else if (conn->route == RouteAction::Proxy) {
                connect_via_tunnel(conn);
            }
        }
        return;
    }

    RouteDecision ip_decision = router_.decide_by_ip(ip);
    if (!apply_route_decision(conn, ip_decision)) {
        return;
    }

    if (conn->route == RouteAction::Direct) {
        TX_INFO("[Direct] %s:%u (ip rule -> %s)",
                conn->target.host.c_str(), conn->target.port,
                conn->outbound ? conn->outbound->tag.c_str() : "");
        connect_direct(conn);
    } else {
        TX_INFO("[Proxy] %s:%u (ip/default rule -> %s)",
                conn->target.host.c_str(), conn->target.port,
                conn->outbound ? conn->outbound->tag.c_str() : "");
        connect_via_tunnel(conn);
    }
}

void ClientApp::resolve_domain_and_route(ProxyConnPtr conn) {
    auto* req = new uv_getaddrinfo_t;
    auto* ctx = new RouteDnsCtx{this, conn};
    req->data = ctx;

    int r = uv_getaddrinfo(loop_, req, ClientApp::on_route_dns_resolved,
                           conn->target.host.c_str(), nullptr, nullptr);
    if (r != 0) {
        TX_WARN("[Proxy] %s:%u DNS route lookup failed: %s",
                conn->target.host.c_str(), conn->target.port, uv_strerror(r));
        conn->route = RouteAction::Proxy;
        connect_via_tunnel(conn);
        delete ctx;
        delete req;
    }
}

void ClientApp::on_route_dns_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    auto* ctx = static_cast<RouteDnsCtx*>(req->data);
    auto conn = ctx->conn;
    ClientApp* app = ctx->app;

    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        if (res) uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    IpAddr selected;
    bool have_ip = false;

    if (status == 0 && res) {
        for (auto* ai = res; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                have_ip = sockaddr_to_ipaddr(ai->ai_addr, conn->target.port, selected);
                break;
            }
            if (!have_ip && ai->ai_family == AF_INET6) {
                have_ip = sockaddr_to_ipaddr(ai->ai_addr, conn->target.port, selected);
            }
        }
    }

    bool private_domain_result = have_ip && selected.is_lan() && conn->target.type == AddrType::Domain;

    if (private_domain_result) {
        TX_WARN("%s:%u resolved to private/local address %s; applying route rules",
                conn->target.host.c_str(), conn->target.port,
                selected.to_string().c_str());
    }

    RouteDecision decision;
    if (have_ip) {
        decision = app->router_.decide(conn->target.host, selected);
    } else {
        decision = app->router_.fallback_decision();
    }

    if (!app->apply_route_decision(conn, decision)) {
        // block_connection already handled failure response when needed.
    } else if (conn->route == RouteAction::Direct) {
        TX_INFO("[Direct] %s:%u resolved to %s (rule -> %s)",
                conn->target.host.c_str(), conn->target.port,
                have_ip ? selected.to_string().c_str() : "none",
                conn->outbound ? conn->outbound->tag.c_str() : "");
        app->connect_direct(conn);
    } else {
        if (status < 0 || !res) {
            TX_WARN("[Proxy] %s:%u DNS route lookup failed: %s",
                    conn->target.host.c_str(), conn->target.port,
                    status < 0 ? uv_strerror(status) : "no results");
        } else {
            TX_INFO("[Proxy] %s:%u resolved to %s (rule -> %s)",
                    conn->target.host.c_str(), conn->target.port,
                    selected.to_string().c_str(),
                    conn->outbound ? conn->outbound->tag.c_str() : "");
        }
        app->connect_via_tunnel(conn);
    }

    if (res) uv_freeaddrinfo(res);
    delete ctx;
    delete req;
}

void ClientApp::connect_direct(ProxyConnPtr conn) {
    TX_INFO("[Direct] Connecting to %s:%u", conn->target.host.c_str(), conn->target.port);

    auto direct = std::make_shared<TcpSession>(loop_, socket_protector_);
    conn->direct_session = direct;

    direct->set_close_callback([this, conn](SessionPtr) {
        if (conn->local_session && !conn->local_session->is_closed()) {
            conn->local_session->close();
        }
    });

    direct->connect(conn->target.host, conn->target.port,
        [this, conn, direct](bool success) {
            if (!success) {
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
                return;
            }

            conn->connected = true;

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
                direct->send(conn->proto_buf);
                record_traffic(RouteAction::Direct, true, bytes);
                conn->proto_buf.clear();
            }

            // Start reading from direct connection
            direct->start_read([this, conn](SessionPtr, Buffer& data) {
                if (conn->local_session && !conn->local_session->is_closed()) {
                    record_traffic(RouteAction::Direct, false, data.readable());
                    conn->local_session->send(data);
                }
            });
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

    auto tunnel = std::make_shared<TcpSession>(loop_, socket_protector_);
    conn->tunnel_session = tunnel;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = true;
    conn->tunnel_handshake_buf.clear();
    conn->tunnel_recv_buf.clear();
    TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
    start_tunnel_timer(conn, kTunnelHandshakeTimeoutMs, "handshake");

    tunnel->set_close_callback([this, conn, tunnel](SessionPtr) {
        TX_WARN("Tunnel disconnected for session %u", conn->session_id);
        if (conn->tunnel_session == tunnel) {
            conn->tunnel_connected = false;
            conn->tunnel_connecting = false;
            conn->tunnel_session.reset();
            fail_tunnel_connection(conn);
        }
    });

    tunnel->connect(conn->outbound->server_host, conn->outbound->server_port,
        [this, conn, tunnel](bool success) {
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
                tunnel->send(hello);
            } else {
                conn->tunnel_connecting = false;
                conn->tunnel_connected = false;
                TX_ERROR("Tunnel connect failed to %s:%u for session %u",
                         conn->outbound ? conn->outbound->server_host.c_str() : "",
                         conn->outbound ? conn->outbound->server_port : 0,
                         conn->session_id);
                fail_tunnel_connection(conn);
            }
        });

    return true;
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
            conn->local_session->close();
        }
        return;
    }

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

    conn->tunnel_session->send(encoded);
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
                    conn->local_session->send(payload);
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

    if (conn->route == RouteAction::Proxy) {
        tunnel_send_disconnect(conn);
        connections_.erase(conn->session_id);
        close_tunnel_session(conn);
    }
}

} // namespace tx
