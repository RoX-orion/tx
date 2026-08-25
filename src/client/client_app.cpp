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
#include <new>
#include <cstdlib>
#include <array>
#include <climits>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

#if defined(TX_PLATFORM_POSIX)
#include <unistd.h>
#endif

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <cerrno>
#include <sys/socket.h>
#endif

#if defined(TX_PLATFORM_WINDOWS)
#include <io.h>
#endif

#if defined(TX_PLATFORM_LINUX)
#include <linux/netfilter_ipv4.h>
#endif

namespace tx {

namespace {

void close_owned_tun_fd(int fd) {
    if (fd < 0) return;
#if defined(TX_PLATFORM_WINDOWS)
    _close(fd);
#else
    ::close(fd);
#endif
}

constexpr uint64_t kTunnelHandshakeTimeoutMs = 8000;
constexpr uint64_t kTunnelConnectResultTimeoutMs = 15000;
constexpr uint64_t kTcpConnectTimeoutMs = 5000;
// DNS tunnel establishment and the server-side resolver are separate
// stages.  The response budget covers the resolver's UDP wait, TCP fallback,
// and trying the remaining system nameservers after a timeout/TC response.
constexpr uint64_t kInternalDnsConnectTimeoutMs = 15000;
constexpr uint64_t kInternalDnsResponseTimeoutMs = 30000;
constexpr uint64_t kTunDnsIdleTimeoutMs = 30000;
constexpr uint64_t kUdpTunnelHandshakeTimeoutMs = 8000;
// Keep one-shot TUN DNS sockets well below lwIP's 1024-UDP-PCB pool so a
// burst of distinct source ports cannot starve ordinary UDP flows.
constexpr size_t kMaxTunDnsFlows = 256;
constexpr size_t kMaxTunDnsPendingQueries = 64;
constexpr size_t kMaxUdpPendingPackets = 1024;
constexpr size_t kMaxUdpPendingBytes = 4 * 1024 * 1024;
// MUX increases the number of independent pending queues. Keep their total
// budget equal to the old data-plus-DNS two-tunnel maximum.
constexpr size_t kMaxAllUdpPendingBytes = 2 * kMaxUdpPendingBytes;
constexpr size_t kMaxUdpPendingBytesPerFlow = 512 * 1024;
constexpr size_t kMaxUdpTunnelWriteBacklog = 8 * 1024 * 1024;
constexpr uint32_t kUdpTunnelRetryInitialMs = 250;
constexpr uint32_t kUdpTunnelRetryMaxMs = 5000;
constexpr uint64_t kQuicSniffTimeoutMs = 300;
constexpr size_t kMaxQuicSniffPendingBytesPerFlow = 16 * 1024;
constexpr size_t kMaxQuicSniffActiveFlows = 256;
constexpr size_t kMaxQuicSniffPendingBytes = 4 * 1024 * 1024;
constexpr size_t kMaxQuicRouteCacheEntries = 1024;
constexpr size_t kMaxHttpHandshakeBytes = 64 * 1024;
constexpr size_t kMaxSocks5HandshakeBytes = 512;
constexpr uint64_t kProxyHandshakeTimeoutMs = 30000;
constexpr size_t kTunDrainPacketBudget = 64;
constexpr size_t kTunDrainByteBudget = 256 * 1024;
constexpr uint64_t kTunDrainTimeBudgetNs = 1000 * 1000;
constexpr size_t kTunWritePacketBudget = 64;
constexpr size_t kTunWriteByteBudget = 256 * 1024;
constexpr uint64_t kTunWriteTimeBudgetNs = 1000 * 1000;

struct UdpSendRequest {
    uv_udp_send_t request;
    uv_buf_t buffer;
};

UdpSendRequest* allocate_udp_send_request(const uint8_t* data, size_t len) {
    if ((!data && len != 0) || len > static_cast<size_t>(UINT_MAX) ||
        len > std::numeric_limits<size_t>::max() - sizeof(UdpSendRequest)) {
        return nullptr;
    }
    void* storage = ::operator new(sizeof(UdpSendRequest) + len, std::nothrow);
    if (!storage) return nullptr;
    auto* request = new (storage) UdpSendRequest{};
    char* payload = reinterpret_cast<char*>(request + 1);
    if (len != 0) std::memcpy(payload, data, len);
    request->buffer = uv_buf_init(payload, static_cast<unsigned int>(len));
    request->request.data = request;
    return request;
}

void free_udp_send_request(UdpSendRequest* request) {
    if (!request) return;
    request->~UdpSendRequest();
    ::operator delete(request);
}

bool append_tunnel_input(Buffer& destination, const Buffer& source) {
    const size_t incoming = source.readable();
    if (incoming > TunnelCodec::kMaxReceiveBufferSize ||
        destination.readable() > TunnelCodec::kMaxReceiveBufferSize - incoming) {
        return false;
    }
    destination.append(source);
    return true;
}

bool same_target(const TargetAddr& left, const TargetAddr& right) {
    return left.type == right.type && left.port == right.port && left.host == right.host;
}

bool build_dns_error_response(const std::vector<uint8_t>& query,
                              std::vector<uint8_t>& response, uint8_t rcode) {
    if (query.size() < 12 || load_be16(query.data() + 4) != 1) return false;
    size_t pos = 12;
    while (pos < query.size()) {
        const uint8_t length = query[pos++];
        if (length == 0) break;
        if ((length & 0xc0u) != 0 || length > 63 || pos + length > query.size()) return false;
        pos += length;
    }
    if (pos + 4 > query.size()) return false;
    pos += 4;
    response.assign(query.begin(), query.begin() + pos);
    const uint16_t flags = static_cast<uint16_t>(0x8080u | (rcode & 0x0fu) |
        (load_be16(query.data() + 2) & 0x0100u));
    store_be16(response.data() + 2, flags);
    store_be16(response.data() + 6, 0);
    store_be16(response.data() + 8, 0);
    store_be16(response.data() + 10, 0);
    return true;
}

bool build_dns_servfail(const std::vector<uint8_t>& query, std::vector<uint8_t>& response) {
    return build_dns_error_response(query, response, 2);
}

bool build_dns_refused(const std::vector<uint8_t>& query, std::vector<uint8_t>& response) {
    return build_dns_error_response(query, response, 5);
}

bool extract_quic_long_connection_ids(const uint8_t* data, size_t len,
                                      std::string& dcid, std::string& scid) {
    dcid.clear();
    scid.clear();
    // Header form and fixed bit must both be set.  CID bytes themselves are
    // not header-protected, so this can also inspect encrypted responses.
    if (!data || len < 7 || (data[0] & 0xc0) != 0xc0) return false;
    size_t pos = 5; // first byte and version
    const size_t dcid_len = data[pos++];
    if (dcid_len > 20 || dcid_len > len - pos) return false;
    dcid.assign(reinterpret_cast<const char*>(data + pos), dcid_len);
    pos += dcid_len;
    if (pos >= len) return false;
    const size_t scid_len = data[pos++];
    if (scid_len > 20 || scid_len > len - pos) return false;
    scid.assign(reinterpret_cast<const char*>(data + pos), scid_len);
    return true;
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

int numeric_address_family(const std::string& host) {
    in_addr v4{};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) return AF_INET;
    in6_addr v6{};
    if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) return AF_INET6;
    return AF_UNSPEC;
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
        IpAddr ip;
        if (!IpAddr::parse(target.host, 0, ip) || ip.family != IpAddr::IPv4) return false;
        out.append(ip.data.v4, 4);
    } else if (target.type == AddrType::IPv6) {
        IpAddr ip;
        if (!IpAddr::parse(target.host, 0, ip) || ip.family != IpAddr::IPv6) return false;
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

struct ClientApp::UdpTunnelRetryCtx {
    ClientApp* app = nullptr;
    std::weak_ptr<UdpTunnel> tunnel;
};

struct ClientApp::UdpTunnelHandshakeCtx {
    ClientApp* app = nullptr;
    std::weak_ptr<UdpTunnel> tunnel;
};

ClientApp::ClientApp(SocketProtectCallback socket_protector,
                     DnsResolver::HostResolveHook host_resolver,
                     DnsResolver::QueryHook dns_query,
                     uint32_t android_address_family_mask)
    : owned_loop_(create_app_loop("client")),
      loop_(owned_loop_.get()),
      loop_closed_(false),
      stop_async_initialized_(false),
      network_async_initialized_(false),
      ready_to_run_(false),
      stop_requested_(false),
      stopping_(false),
      dns_resolver_(loop_),
      direct_dns_resolver_(loop_),
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
      android_address_family_mask_(android_address_family_mask),
      socket_protector_(std::move(socket_protector)),
      host_resolver_(std::move(host_resolver)),
      dns_query_(std::move(dns_query)) {}

ClientApp::~ClientApp() {
    stop();
    if (!loop_closed_) {
        drain_and_close_loop(loop_, "client");
        loop_closed_ = true;
    }
    if (config_.tun_fd >= 0) {
        close_owned_tun_fd(config_.tun_fd);
        config_.tun_fd = -1;
    }
}

bool ClientApp::init(const ClientConfig& config) {
    // Claim an externally supplied TUN fd before any initialization step that
    // may fail or throw.  start_client keeps a temporary guard only until
    // this call returns; ClientApp is then responsible for closing the fd on
    // every success and failure path.
    const int supplied_tun_fd = config.tun_fd;
    config_.tun_fd = supplied_tun_fd;
    try {
        config_ = config;
    } catch (...) {
        config_.tun_fd = supplied_tun_fd;
        throw;
    }

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

#if defined(TX_PLATFORM_ANDROID)
    // A TX endpoint is the bootstrap for the tunnel itself.  Resolving it
    // through the physical Network would leak the server hostname and make
    // tunnel startup depend on physical DNS, so Android requires a numeric
    // IPv4/IPv6 literal here.  Physical resolver hooks remain available only
    // for destinations that routing explicitly sends to direct.
    for (const auto& outbound : config_.outbounds) {
        if (outbound.type == OutboundType::Tx &&
            numeric_address_family(outbound.server_host) == AF_UNSPEC) {
            TX_ERROR("Android TX outbound %s must use a numeric server host: %s",
                     outbound.tag.c_str(), outbound.server_host.c_str());
            return false;
        }
    }
#endif

    std::string dns_error;
    if (!fake_ip_dns_.configure(config_.dns_fake_ipv4_range,
                                config_.dns_fake_ipv6_range,
                                config_.dns_cache_ttl, dns_error,
                                config_.dns_cache_capacity,
                                config_.dns_mapping_ttl)) {
        TX_ERROR("Failed to configure fake-IP DNS: %s", dns_error.c_str());
        return false;
    }
    uint32_t dns_bypass_mark = 0;
    bool dns_requires_physical_network = false;
#if defined(TX_PLATFORM_LINUX)
    // SO_MARK is needed only for the lwIP TUN policy-routing path.  Applying
    // it to ordinary HTTP/SOCKS DNS sockets makes unprivileged clients fail
    // with EPERM before they can issue a query.
    if (config_.tun_enabled &&
        (config_.tun_auto_route || !config_.tun_routes.empty())) {
        dns_bypass_mark = config_.tun_tcp_stack == "lwip"
            ? config_.tun_bypass_mark : config_.tun_redirect_mark;
        dns_requires_physical_network = true;
    }
#endif
    const auto direct_address_filter = [this](const std::string& address) {
        return fake_ip_dns_.contains_address(address);
    };
    std::shared_ptr<DnsNetworkProvider> physical_dns_provider;
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_WINDOWS)
    physical_dns_provider = create_platform_dns_network_provider(
        dns_bypass_mark, dns_requires_physical_network);
#else
    (void)dns_requires_physical_network;
#endif
#if defined(TX_PLATFORM_ANDROID)
    // The client has no configured DNS upstream. dns_resolver_ is only a
    // routing facade; direct_dns_resolver_ is the physical-Network resolver.
    dns_resolver_.configure({}, socket_protector_, dns_bypass_mark,
                            DnsResolver::HostResolveHook(),
                            DnsResolver::QueryHook(),
                            [this](std::vector<uint8_t> query,
                                   DnsResolver::ResolveCallback callback) {
                                resolve_dns_via_tunnel(std::move(query),
                                                       std::move(callback));
                            });
    direct_dns_resolver_.configure({}, socket_protector_, 0,
                                   host_resolver_, dns_query_,
                                   DnsResolver::AsyncQueryHook(),
                                   physical_dns_provider,
                                   direct_address_filter);
#else
    dns_resolver_.configure({}, socket_protector_, dns_bypass_mark,
                            DnsResolver::HostResolveHook(),
                            DnsResolver::QueryHook(),
                            [this](std::vector<uint8_t> query,
                                   DnsResolver::ResolveCallback callback) {
                                resolve_dns_via_tunnel(std::move(query),
                                                       std::move(callback));
                            });
    direct_dns_resolver_.configure({}, socket_protector_, dns_bypass_mark,
                                   host_resolver_, dns_query_,
                                   DnsResolver::AsyncQueryHook(),
                                   physical_dns_provider,
                                   direct_address_filter);
#endif

    // Load router
    if (!router_.load(config.router)) {
        TX_ERROR("Router load failed");
        return false;
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

void ClientApp::update_android_address_family_mask(uint32_t mask) {
    android_address_family_mask_.store(mask, std::memory_order_release);
}

bool ClientApp::android_address_family_available(int family) const {
    const uint32_t mask = android_address_family_mask_.load(std::memory_order_acquire);
    if ((mask & kAndroidNetworkAddressFamilyKnown) == 0) return true;
    if (family == AF_INET) return (mask & kAndroidNetworkAddressFamilyIPv4) != 0;
    if (family == AF_INET6) return (mask & kAndroidNetworkAddressFamilyIPv6) != 0;
    return true;
}

void ClientApp::on_network_async(uv_async_t* handle) {
    auto* app = static_cast<ClientApp*>(handle->data);
    if (app) app->network_changed_on_loop();
}

void ClientApp::network_changed_on_loop() {
    dns_resolver_.cancel_pending();
    direct_dns_resolver_.cancel_pending();
    const uint64_t now = uv_now(loop_);
    for (auto it = quic_route_cache_.begin(); it != quic_route_cache_.end();) {
        if (!it->second.outbound || it->second.expires_at_ms <= now) {
            if (!it->first.empty()) {
                quic_route_cids_by_first_byte_[
                    static_cast<uint8_t>(it->first[0])].erase(it->first);
            }
            it = quic_route_cache_.erase(it);
        } else {
            ++it;
        }
    }
    close_all_udp_tunnels();
    close_all_tun_dns_flows();
    std::vector<std::string> flows;
    for (const auto& item : udp_flows_) flows.push_back(item.first);
    for (const auto& key : flows) remove_udp_flow(key, false);
    std::vector<ProxyConnPtr> connections;
    connections.reserve(connections_.size());
    for (const auto& item : connections_) connections.push_back(item.second);
    connections_.clear();
    for (auto& conn : connections) {
        auto local = conn->local_session;
        release_proxy_resources(conn);
        if (local && !local->is_closed()) local->reset();
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
    // TcpServer owns an initialized libuv handle even when the transparent
    // listener was never started (for example after an early TUN failure or
    // when the lwIP stack is selected). Always close that handle explicitly.
    tun_tcp_server_.stop();
    stop_udp_listener();
    close_all_udp_tunnels();
    close_all_tun_dns_flows();
    http_server_.stop();
    socks5_server_.stop();
    std::vector<ProxyConnPtr> active_connections;
    active_connections.reserve(connections_.size());
    for (const auto& kv : connections_) active_connections.push_back(kv.second);
    connections_.clear();
    for (auto& conn : active_connections) {
        auto local = conn->local_session;
        release_proxy_resources(conn);
        if (local && !local->is_closed()) local->close();
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
    fail_proxy_connection(conn, 403);
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
    while (!udp_deadlines_.empty()) {
        std::string flow_key;
        UdpFlow* flow = nullptr;
        if (resolve_udp_deadline(udp_deadlines_.top(), flow_key, flow)) {
            earliest = udp_deadlines_.top().deadline_ms;
            break;
        }
        udp_deadlines_.pop();
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

void ClientApp::schedule_udp_deadline(UdpFlow& flow, UdpDeadlineKind kind,
                                      uint64_t deadline_ms) {
    ++flow.deadline_generation;
    if (flow.deadline_generation == 0) ++flow.deadline_generation;
    if (kind == UdpDeadlineKind::InternalDns) flow.dns_deadline_ms = deadline_ms;
    else flow.quic_sniff_deadline_ms = deadline_ms;
    udp_deadlines_.push(UdpDeadline{
        deadline_ms, flow.session_id, flow.deadline_generation, kind});
    arm_internal_dns_timer();
}

bool ClientApp::resolve_udp_deadline(const UdpDeadline& deadline,
                                     std::string& flow_key, UdpFlow*& flow) {
    auto key = udp_session_keys_.find(deadline.session_id);
    if (key == udp_session_keys_.end()) return false;
    auto item = udp_flows_.find(key->second);
    if (item == udp_flows_.end() ||
        item->second.session_id != deadline.session_id ||
        item->second.deadline_generation != deadline.generation) {
        return false;
    }
    const uint64_t current = deadline.kind == UdpDeadlineKind::InternalDns
        ? item->second.dns_deadline_ms : item->second.quic_sniff_deadline_ms;
    if (current == 0 || current != deadline.deadline_ms) return false;
    if (deadline.kind == UdpDeadlineKind::InternalDns &&
        item->second.kind != UdpFlowKind::InternalDns) return false;
    if (deadline.kind == UdpDeadlineKind::QuicSniff &&
        (item->second.kind != UdpFlowKind::Tun || !item->second.quic_sniffer)) {
        return false;
    }
    flow_key = key->second;
    flow = &item->second;
    return true;
}

void ClientApp::stop_internal_dns_timer() {
    if (!internal_dns_timer_initialized_) return;
    internal_dns_timer_initialized_ = false;
    uv_timer_stop(&internal_dns_timer_);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&internal_dns_timer_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&internal_dns_timer_), nullptr);
    }
    while (!udp_deadlines_.empty()) udp_deadlines_.pop();
}

void ClientApp::on_internal_dns_timer(uv_timer_t* timer) {
    auto* app = static_cast<ClientApp*>(timer->data);
    if (!app || app->stopping_) return;

    const uint64_t now = uv_now(app->loop_);
    while (!app->udp_deadlines_.empty() &&
           app->udp_deadlines_.top().deadline_ms <= now) {
        const UdpDeadline deadline = app->udp_deadlines_.top();
        app->udp_deadlines_.pop();
        std::string flow_key;
        UdpFlow* flow = nullptr;
        if (!app->resolve_udp_deadline(deadline, flow_key, flow)) continue;
        if (deadline.kind == UdpDeadlineKind::InternalDns) {
            app->retry_internal_dns(flow_key, "timeout");
        } else {
            app->fallback_tun_quic_to_ip(flow_key);
        }
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
    if (!flow.udp_tunnel_key.empty()) {
        auto tunnel_it = udp_tunnels_.find(flow.udp_tunnel_key);
        if (tunnel_it != udp_tunnels_.end() &&
            tunnel_it->second->outbound == flow.outbound) {
            tunnel = tunnel_it->second;
        }
    }
    const bool close_dedicated_tunnel = tunnel && tunnel->dedicated &&
        tunnel->owner_session_id == sid;
    if (notify_peer && flow.proxied && tunnel && tunnel->connected &&
        tunnel->tunnel_session && !tunnel->tunnel_session->is_closed()) {
        Buffer encoded(64);
        if (tunnel->codec.encode_disconnect(sid, encoded)) {
            tunnel->tunnel_session->send(std::move(encoded));
        }
    }

    close_direct_udp_relay(flow);
    release_tun_quic_sniffer(flow);
    clear_tun_quic_pending(flow);
    if (flow.kind == UdpFlowKind::Tun && flow.lwip_flow_id != 0) {
        tun_udp_flow_sessions_.erase(flow.lwip_flow_id);
        lwip_udp_stack_.close_flow(flow.lwip_flow_id);
    }
    udp_session_keys_.erase(sid);
    release_session_id(sid);
    if (tunnel) {
        for (auto pending = tunnel->pending.begin(); pending != tunnel->pending.end();) {
            if (pending->session_id == sid) {
                tunnel->pending_bytes -= std::min(tunnel->pending_bytes,
                                                  pending->payload.size());
                udp_tunnel_pending_bytes_ -= std::min(udp_tunnel_pending_bytes_,
                                                       pending->payload.size());
                pending = tunnel->pending.erase(pending);
            } else {
                ++pending;
            }
        }
    }
    udp_flows_.erase(it);
    if (close_dedicated_tunnel) {
        const auto current = udp_tunnels_.find(tunnel->key);
        if (current != udp_tunnels_.end() && current->second == tunnel) {
            udp_tunnels_.erase(current);
        }
        close_udp_tunnel(tunnel);
    }
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
    for (auto it = quic_route_cache_.begin(); it != quic_route_cache_.end();) {
        if (it->second.expires_at_ms <= now_ms) {
            if (!it->first.empty()) {
                quic_route_cids_by_first_byte_[
                    static_cast<uint8_t>(it->first[0])].erase(it->first);
            }
            it = quic_route_cache_.erase(it);
        } else ++it;
    }
    if (!expired.empty()) {
        TX_DEBUG("Cleaned up %zu idle UDP flows", expired.size());
    }
    cleanup_idle_tun_dns_flows(now_ms);
}

void ClientApp::cleanup_idle_tun_dns_flows(uint64_t now_ms) {
    std::vector<uint64_t> expired;
    expired.reserve(tun_dns_flows_.size());
    for (const auto& item : tun_dns_flows_) {
        if (udp_flow_is_idle(now_ms, item.second.last_activity_ms, kTunDnsIdleTimeoutMs)) {
            expired.push_back(item.first);
        }
    }
    for (uint64_t flow_id : expired) {
        TX_DEBUG("Closing idle TUN DNS flow=%llu", static_cast<unsigned long long>(flow_id));
        lwip_udp_stack_.close_flow(flow_id);
        tun_dns_flows_.erase(flow_id);
    }
}

void ClientApp::close_all_tun_dns_flows() {
    for (const auto& item : tun_dns_flows_) {
        lwip_udp_stack_.close_flow(item.first);
    }
    tun_dns_flows_.clear();
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
    if (!android_address_family_available(target_family)) {
        TX_WARN("[Direct][UDP] physical network has no IPv%d default route; dropping flow %s",
                target_family == AF_INET6 ? 6 : 4, flow_key.c_str());
        return false;
    }
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
            outbound_socket_policy_.mark != 0)
#elif defined(TX_PLATFORM_WINDOWS)
        || (target_family == AF_INET6 ? outbound_socket_policy_.ipv6_interface
                                      : outbound_socket_policy_.ipv4_interface) != 0
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
            outbound_socket_policy_.mark != 0) {
            uint32_t mark = outbound_socket_policy_.mark;
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
        const uint32_t interface_index = target_family == AF_INET6
            ? outbound_socket_policy_.ipv6_interface
            : outbound_socket_policy_.ipv4_interface;
        DWORD index = htonl(interface_index);
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
    TargetAddr effective_target = target;
    if (!normalize_fake_ip_target(effective_target, "[Direct][UDP]")) return;
    if (!same_target(effective_target, target)) {
        send_direct_udp_packet(flow_key, flow, effective_target, data, len);
        return;
    }

    sockaddr_storage target_addr;
    bool have_target_address = false;
    if (flow.direct_cached_address_valid &&
        same_target(flow.direct_cached_target, effective_target)) {
        target_addr = flow.direct_cached_address;
        have_target_address = true;
    } else if (target_to_sockaddr(effective_target, target_addr)) {
        flow.direct_cached_target = effective_target;
        flow.direct_cached_address = target_addr;
        flow.direct_cached_address_valid = true;
        have_target_address = true;
    }
    if (have_target_address) {
        if (!ensure_direct_udp_relay(flow_key, flow, target_addr.ss_family)) {
            return;
        }

        uv_buf_t immediate = uv_buf_init(
            reinterpret_cast<char*>(const_cast<uint8_t*>(data)),
            static_cast<unsigned int>(len));
        const int immediate_result = uv_udp_try_send(
            &flow.direct_relay->handle, &immediate, 1,
            reinterpret_cast<const sockaddr*>(&target_addr));
        if (immediate_result == static_cast<int>(len)) {
            record_traffic(RouteAction::Direct, true, len);
            return;
        }
        if (immediate_result >= 0) {
            TX_WARN("[Direct][UDP] partial datagram send to %s:%u",
                    effective_target.host.c_str(), effective_target.port);
            return;
        }
        if (immediate_result != UV_EAGAIN && immediate_result != UV_ENOSYS) {
            TX_WARN("[Direct][UDP] send failed to %s:%u: %s",
                    effective_target.host.c_str(), effective_target.port,
                    uv_strerror(immediate_result));
            return;
        }

        UdpSendRequest* request = allocate_udp_send_request(data, len);
        if (!request) {
            TX_WARN("[Direct][UDP] send allocation failed for %zu bytes", len);
            return;
        }
        int r = uv_udp_send(&request->request, &flow.direct_relay->handle,
                            &request->buffer, 1,
                            reinterpret_cast<const sockaddr*>(&target_addr),
                            ClientApp::on_udp_send_done);
        if (r != 0) {
            TX_WARN("[Direct][UDP] send failed to %s:%u: %s",
                    effective_target.host.c_str(), effective_target.port, uv_strerror(r));
            free_udp_send_request(request);
            return;
        }
        record_traffic(RouteAction::Direct, true, len);
        return;
    }

    // Domain UDP is resolved once per flow.  Re-resolving successive QUIC
    // datagrams can select different CDN peers and can also reorder packets
    // while several DNS operations complete.
    if (flow.direct_send_target.host.size() != 0 &&
        same_target(flow.direct_resolution_target, effective_target)) {
        send_direct_udp_packet(flow_key, flow, flow.direct_send_target, data, len);
        return;
    }

    const auto queue_packet = [&flow, data, len]() {
        if (flow.direct_resolution_packets.size() >= kMaxUdpPendingPackets ||
            len > kMaxUdpPendingBytesPerFlow ||
            flow.direct_resolution_bytes > kMaxUdpPendingBytesPerFlow - len) {
            TX_WARN("Dropping direct UDP packet while resolving %s: queue limit reached",
                    flow.direct_resolution_target.host.c_str());
            return false;
        }
        flow.direct_resolution_packets.emplace_back(data, data + len);
        flow.direct_resolution_bytes += len;
        return true;
    };

    if (flow.direct_target_resolving) {
        if (!same_target(flow.direct_resolution_target, effective_target)) {
            TX_WARN("Dropping direct UDP packet for changed target %s:%u while resolving %s:%u",
                    effective_target.host.c_str(), effective_target.port,
                    flow.direct_resolution_target.host.c_str(),
                    flow.direct_resolution_target.port);
            return;
        }
        queue_packet();
        return;
    }

    flow.direct_resolution_target = effective_target;
    flow.direct_target_resolving = true;
    if (!queue_packet()) {
        flow.direct_target_resolving = false;
        return;
    }

    const SessionId session_id = flow.session_id;
    direct_dns_resolver_.resolve_host(effective_target.host, AF_UNSPEC,
        [this, flow_key, session_id, effective_target](std::vector<std::string> addresses) {
            auto flow_it = udp_flows_.find(flow_key);
            if (flow_it == udp_flows_.end() || flow_it->second.session_id != session_id ||
                !flow_it->second.direct_target_resolving ||
                !same_target(flow_it->second.direct_resolution_target, effective_target)) {
                return;
            }
            UdpFlow& current = flow_it->second;
            current.direct_target_resolving = false;
            if (addresses.empty()) {
                TX_WARN("[Direct][UDP] DNS lookup failed for %s", effective_target.host.c_str());
                current.direct_resolution_packets.clear();
                current.direct_resolution_bytes = 0;
                return;
            }
            const auto candidate = std::find_if(addresses.begin(), addresses.end(),
                [this](const std::string& address) {
                    return android_address_family_available(numeric_address_family(address));
                });
            if (candidate == addresses.end()) {
                TX_WARN("[Direct][UDP] physical network has no usable address family for %s",
                        effective_target.host.c_str());
                current.direct_resolution_packets.clear();
                current.direct_resolution_bytes = 0;
                return;
            }
            TargetAddr resolved = effective_target;
            resolved.host = *candidate;
            resolved.type = resolved.host.find(':') == std::string::npos
                ? AddrType::IPv4 : AddrType::IPv6;
            current.direct_send_target = resolved;
            if (current.kind == UdpFlowKind::Tun) current.send_target = resolved;

            std::deque<std::vector<uint8_t>> pending;
            pending.swap(current.direct_resolution_packets);
            current.direct_resolution_bytes = 0;
            for (const auto& packet : pending) {
                send_direct_udp_packet(flow_key, current, resolved,
                                       packet.data(), packet.size());
            }
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
        remember_tun_quic_response_route(flow, data, len);
        if (write_tun_udp_packet(flow, source, data, len)) {
            record_traffic(route, false, len);
        }
        return;
    }

    Buffer packet;
    if (!build_socks5_udp_packet(source, data, len, packet)) {
        return;
    }

    UdpSendRequest* request = allocate_udp_send_request(
        packet.data(), packet.readable());
    if (!request) return;

    int r = uv_udp_send(&request->request, &socks5_udp_, &request->buffer, 1,
                        reinterpret_cast<const sockaddr*>(&flow.client_addr),
                        ClientApp::on_udp_send_done);
    if (r != 0) {
        TX_WARN("[%s][UDP] failed to send response to SOCKS5 client: %s",
                route == RouteAction::Direct ? "Direct" : "Proxy", uv_strerror(r));
        free_udp_send_request(request);
        return;
    }
    record_traffic(route, false, len);
}

ClientApp::UdpTunnelPtr ClientApp::get_udp_tunnel(const OutboundConfig* outbound,
                                                  UdpTunnelKind kind,
                                                  const std::string& requested_key) {
    if (!outbound || outbound->type != OutboundType::Tx || !outbound->udp_over_tcp) {
        return UdpTunnelPtr();
    }
    const std::string key = requested_key.empty()
        ? outbound->tag + (kind == UdpTunnelKind::Dns ? ":dns" : ":udp")
        : requested_key;
    auto it = udp_tunnels_.find(key);
    if (it != udp_tunnels_.end() && it->second->outbound == outbound &&
        it->second->kind == kind) {
        return it->second;
    }

    UdpTunnelPtr tunnel = std::make_shared<UdpTunnel>();
    tunnel->outbound = outbound;
    tunnel->kind = kind;
    tunnel->key = key;
    udp_tunnels_[key] = tunnel;
    return tunnel;
}

ClientApp::UdpTunnelPtr ClientApp::select_udp_tunnel(UdpFlow& flow) {
    const OutboundConfig* outbound = flow.outbound;
    if (!outbound || outbound->type != OutboundType::Tx || !outbound->udp_over_tcp) {
        return UdpTunnelPtr();
    }

    if (!flow.udp_tunnel_key.empty()) {
        const auto existing = udp_tunnels_.find(flow.udp_tunnel_key);
        if (existing != udp_tunnels_.end() && existing->second->outbound == outbound &&
            existing->second->kind == UdpTunnelKind::Data) {
            return existing->second;
        }
    }

    const bool dedicated = outbound->udp_mux_connections == -1;
    if (!dedicated && outbound->udp_mux_connections < 1) {
        TX_ERROR("TX outbound %s has invalid udp-mux.connections", outbound->tag.c_str());
        return UdpTunnelPtr();
    }
    std::string key;
    if (dedicated) {
        key = outbound->tag + ":udp:flow:" + std::to_string(flow.session_id);
    } else {
        uint32_t& next_slot = udp_mux_next_slot_[outbound->tag];
        const uint32_t slot = next_slot %
            static_cast<uint32_t>(outbound->udp_mux_connections);
        ++next_slot;
        key = outbound->tag + ":udp:" + std::to_string(slot);
    }

    UdpTunnelPtr tunnel = get_udp_tunnel(outbound, UdpTunnelKind::Data, key);
    if (!tunnel) return UdpTunnelPtr();
    tunnel->dedicated = dedicated;
    tunnel->owner_session_id = dedicated ? flow.session_id : 0;
    flow.udp_tunnel_key = tunnel->key;
    return tunnel;
}

bool ClientApp::ensure_udp_tunnel(const UdpTunnelPtr& tunnel) {
    if (!tunnel || !tunnel->outbound || tunnel->outbound->type != OutboundType::Tx) {
        TX_ERROR("UDP proxy tunnel has no TX outbound selected");
        return false;
    }
    if (tunnel->connected || tunnel->connecting) return true;
    // A retry timer owns the next connection attempt. New datagrams are kept
    // in the bounded pending queue until it fires.
    if (tunnel->retry_timer) return true;

    tunnel->connecting = true;
    tunnel->handshake_buf.clear();
    tunnel->recv_buf.clear();
    TunnelCodec::cleanse_handshake_state(tunnel->handshake_state);
    std::weak_ptr<UdpTunnel> weak_tunnel = tunnel;
    direct_dns_resolver_.resolve_host(tunnel->outbound->server_host, AF_UNSPEC,
        [this, weak_tunnel](std::vector<std::string> addresses) {
            UdpTunnelPtr current = weak_tunnel.lock();
            if (!current || !current->connecting) return;
            if (addresses.empty()) {
                TX_ERROR("UDP tunnel DNS resolution failed");
                close_udp_tunnel(current, true);
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
    while (addresses && index < addresses->size() &&
           (fake_ip_dns_.contains_address((*addresses)[index]) ||
            !android_address_family_available(numeric_address_family((*addresses)[index])))) {
        if (fake_ip_dns_.contains_address((*addresses)[index])) {
            TX_WARN("Rejecting protected Fake-IP TX server candidate %s",
                    (*addresses)[index].c_str());
            ++index;
            continue;
        }
        TX_INFO("Skipping TX server IPv%d address %s: physical network has no default route",
                numeric_address_family((*addresses)[index]) == AF_INET6 ? 6 : 4,
                (*addresses)[index].c_str());
        ++index;
    }
    if (!tunnel || !tunnel->connecting || !tunnel->outbound || !addresses ||
        index >= addresses->size()) {
        TX_ERROR("UDP tunnel exhausted all resolved server addresses");
        close_udp_tunnel(tunnel, true);
        return;
    }

    auto session = std::make_shared<TcpSession>(loop_, socket_protector_,
                                                outbound_socket_policy_);
    tunnel->tunnel_session = session;
    std::weak_ptr<UdpTunnel> weak_tunnel = tunnel;
    TcpSession* const session_identity = session.get();
    session->set_close_callback([this, weak_tunnel, session_identity](SessionPtr) {
        UdpTunnelPtr current = weak_tunnel.lock();
        if (current && current->tunnel_session.get() == session_identity) {
            TX_WARN("UDP tunnel disconnected");
            close_udp_tunnel(current, true);
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
                    close_udp_tunnel(tunnel, true);
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
                close_udp_tunnel(tunnel, true);
                return;
            }
            if (!start_udp_tunnel_handshake_timer(tunnel)) {
                TX_ERROR("Failed to start UDP tunnel handshake timer");
                close_udp_tunnel(tunnel, true);
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
        if (flow == udp_flows_.end() || flow->second.outbound != tunnel->outbound ||
            flow->second.udp_tunnel_key != tunnel->key) {
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
        if (len > kMaxAllUdpPendingBytes ||
            udp_tunnel_pending_bytes_ > kMaxAllUdpPendingBytes - len) {
            TX_WARN("Dropping UDP packet while %s tunnel is connecting: global queue limit reached",
                    tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
            return;
        }
        PendingUdpPacket pkt;
        pkt.session_id = sid;
        pkt.target = target;
        pkt.payload.assign(data, data + len);
        tunnel->pending_bytes += pkt.payload.size();
        udp_tunnel_pending_bytes_ += pkt.payload.size();
        flow->second.pending_proxy_bytes += pkt.payload.size();
        tunnel->pending.push_back(std::move(pkt));
        return;
    }

    if (!tunnel->tunnel_session || tunnel->tunnel_session->is_closed()) return;
    size_t frame_size = 0;
    if (!TunnelCodec::encoded_frame_size(TunnelCmd::UdpPacket, target, len, frame_size)) {
        TX_WARN("Dropping UDP packet for %s: frame is too large",
                tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
        return;
    }
    const size_t pending = tunnel->tunnel_session->pending_write_bytes();
    if (frame_size > kMaxUdpTunnelWriteBacklog ||
        pending > kMaxUdpTunnelWriteBacklog - frame_size) {
        TX_WARN("Dropping UDP packet for %s: tunnel write backlog limit reached",
                tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
        return;
    }
    Buffer encoded(frame_size);
    if (!tunnel->codec.encode_udp_packet(sid, target, data, len, encoded)) return;
    if (tunnel->tunnel_session->send(std::move(encoded))) {
        TX_DEBUG("[UDP-TUNNEL-SEND] sid=%u target=%s:%u bytes=%zu outbound=%s",
                 sid, target.host.c_str(), target.port, len,
                 tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
        record_traffic(RouteAction::Proxy, true, len);
    } else {
        TX_WARN("Failed to send UDP packet on %s tunnel; reconnecting",
                tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
        close_udp_tunnel(tunnel, true);
    }
}

void ClientApp::send_dns_query(const UdpTunnelPtr& tunnel, SessionId sid,
                               const uint8_t* data, size_t len) {
    if (!tunnel || !data || len < 12 || len > TunnelCodec::kMaxDataPayloadSize ||
        !ensure_udp_tunnel(tunnel)) return;

    auto key = udp_session_keys_.find(sid);
    auto flow = key == udp_session_keys_.end() ? udp_flows_.end()
                                                : udp_flows_.find(key->second);
    if (flow == udp_flows_.end() || flow->second.kind != UdpFlowKind::InternalDns ||
        flow->second.outbound != tunnel->outbound ||
        flow->second.udp_tunnel_key != tunnel->key) {
        return;
    }

    if (!tunnel->connected) {
        if (tunnel->pending.size() >= kMaxUdpPendingPackets ||
            len > kMaxUdpPendingBytes || tunnel->pending_bytes > kMaxUdpPendingBytes - len ||
            len > kMaxUdpPendingBytesPerFlow ||
            flow->second.pending_proxy_bytes > kMaxUdpPendingBytesPerFlow - len ||
            len > kMaxAllUdpPendingBytes ||
            udp_tunnel_pending_bytes_ > kMaxAllUdpPendingBytes - len) {
            TX_WARN("Dropping DNS query while TX tunnel is connecting: queue limit reached");
            return;
        }
        PendingUdpPacket packet;
        packet.session_id = sid;
        packet.payload.assign(data, data + len);
        packet.dns_query = true;
        tunnel->pending_bytes += len;
        udp_tunnel_pending_bytes_ += len;
        flow->second.pending_proxy_bytes += len;
        tunnel->pending.push_back(std::move(packet));
        return;
    }

    if (!tunnel->tunnel_session || tunnel->tunnel_session->is_closed()) return;
    TargetAddr dummy;
    size_t frame_size = 0;
    if (!TunnelCodec::encoded_frame_size(TunnelCmd::DnsQuery, dummy, len, frame_size)) {
        TX_WARN("Dropping DNS query: frame is too large");
        return;
    }
    const size_t pending = tunnel->tunnel_session->pending_write_bytes();
    if (frame_size > kMaxUdpTunnelWriteBacklog ||
        pending > kMaxUdpTunnelWriteBacklog - frame_size) {
        TX_WARN("Dropping DNS query: tunnel write backlog limit reached");
        return;
    }
    Buffer encoded(frame_size);
    if (!tunnel->codec.encode_dns_query(sid, data, len, encoded)) return;
    if (tunnel->tunnel_session->send(std::move(encoded))) {
        // Do not start the resolver response deadline until the encrypted
        // query has actually been handed to an established tunnel.  A DNS
        // query can otherwise expire during tunnel handshake/retry and hide
        // a valid response that arrives after the server's failover.
        auto current = udp_session_keys_.find(sid);
        if (current != udp_session_keys_.end()) {
            auto current_flow = udp_flows_.find(current->second);
            if (current_flow != udp_flows_.end() &&
                current_flow->second.kind == UdpFlowKind::InternalDns) {
                schedule_udp_deadline(
                    current_flow->second, UdpDeadlineKind::InternalDns,
                    uv_now(loop_) + kInternalDnsResponseTimeoutMs);
            }
        }
        TX_DEBUG("[DNS-TUNNEL-SEND] sid=%u bytes=%zu outbound=%s", sid, len,
                 tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown");
        record_traffic(RouteAction::Proxy, true, len);
    } else {
        TX_WARN("Failed to send DNS query on tunnel; reconnecting");
        close_udp_tunnel(tunnel, true);
    }
}

void ClientApp::resolve_dns_via_tunnel(std::vector<uint8_t> query,
                                       DnsResolver::ResolveCallback callback) {
    if (!callback) return;
    if (query.size() < 12 || query.size() > 65535) {
        std::vector<uint8_t> response;
        if (build_dns_servfail(query, response)) callback(std::move(response));
        else callback(std::vector<uint8_t>());
        return;
    }

    FakeIpDns::Question question;
    if (!FakeIpDns::parse_question(query.data(), query.size(), question)) {
        std::vector<uint8_t> response;
        if (build_dns_servfail(query, response)) callback(std::move(response));
        else callback(std::vector<uint8_t>());
        return;
    }

    TargetAddr dns_target;
    dns_target.type = AddrType::Domain;
    dns_target.host = question.domain;
    dns_target.port = 53;
    const RouteDecision decision = router_.decide_target(dns_target);
    const OutboundConfig* outbound = find_outbound(decision.outbound_tag);
    if (!outbound) {
        TX_WARN("DNS route selected unknown outboundTag: %s",
                decision.outbound_tag.c_str());
        std::vector<uint8_t> response;
        if (build_dns_servfail(query, response)) callback(std::move(response));
        else callback(std::vector<uint8_t>());
        return;
    }

    if (outbound->type == OutboundType::Direct) {
        // This resolver is bound/protected to the physical Network on
        // Android. It is used only after the routing rule selected direct.
        direct_dns_resolver_.resolve(query.data(), query.size(), std::move(callback));
        return;
    }
    if (outbound->type == OutboundType::Block) {
        std::vector<uint8_t> response;
        if (build_dns_refused(query, response)) callback(std::move(response));
        else callback(std::vector<uint8_t>());
        return;
    }
    if (outbound->type != OutboundType::Tx) {
        callback(std::vector<uint8_t>());
        return;
    }

    start_dns_tunnel_query(std::move(query), std::move(callback), outbound);
}

void ClientApp::start_dns_tunnel_query(std::vector<uint8_t> query,
                                       DnsResolver::ResolveCallback callback,
                                       const OutboundConfig* outbound) {
    if (!callback || !outbound || outbound->type != OutboundType::Tx ||
        query.size() < 12 || query.size() > TunnelCodec::kMaxDataPayloadSize) {
        if (callback) callback(std::vector<uint8_t>());
        return;
    }
    if (udp_flows_.size() >= config_.udp_max_flows) {
        TX_WARN("Dropping DNS query: configured UDP flow limit reached");
        callback(std::vector<uint8_t>());
        return;
    }

    UdpTunnelPtr tunnel = get_udp_tunnel(outbound, UdpTunnelKind::Dns);
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
    flow.udp_tunnel_key = tunnel->key;
    flow.proxied = true;
    flow.dns_callback = std::move(callback);
    flow.dns_query = std::move(query);
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
        udp_tunnel_pending_bytes_ -= std::min(udp_tunnel_pending_bytes_,
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

void ClientApp::start_internal_dns_attempt(const std::string& flow_key) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns) return;
    UdpFlow& flow = it->second;

    UdpTunnelPtr tunnel = get_udp_tunnel(flow.outbound, UdpTunnelKind::Dns);
    if (!tunnel) {
        complete_internal_dns(flow_key, std::vector<uint8_t>(), false);
        return;
    }
    flow.udp_tunnel_key = tunnel->key;
    discard_pending_udp_packets(tunnel, flow.session_id);
    // This is only the connection/queueing budget.  send_dns_query() resets
    // the deadline once the encrypted query is actually sent.
    schedule_udp_deadline(flow, UdpDeadlineKind::InternalDns,
                          uv_now(loop_) + kInternalDnsConnectTimeoutMs);
    flow.last_activity_ms = uv_now(loop_);
    TX_DEBUG("DNS query via TX system resolver outbound=%s bytes=%zu",
             flow.outbound ? flow.outbound->tag.c_str() : "unknown",
             flow.dns_query.size());
    send_dns_query(tunnel, flow.session_id,
                   flow.dns_query.data(), flow.dns_query.size());
}

void ClientApp::retry_internal_dns(const std::string& flow_key, const char* reason) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns) return;
    TX_WARN("TX system DNS query failed (%s)", reason ? reason : "unknown");
    complete_internal_dns(flow_key, std::vector<uint8_t>(), false);
}

void ClientApp::complete_internal_dns(const std::string& flow_key,
                                      std::vector<uint8_t> response,
                                      bool notify_peer) {
    auto it = udp_flows_.find(flow_key);
    if (it == udp_flows_.end() || it->second.kind != UdpFlowKind::InternalDns) return;
    auto callback = std::move(it->second.dns_callback);
    it->second.dns_deadline_ms = 0;
    ++it->second.deadline_generation;
    remove_udp_flow(flow_key, notify_peer);
    if (callback) callback(std::move(response));
}

void ClientApp::flush_pending_udp_packets(const UdpTunnelPtr& tunnel) {
    while (tunnel && tunnel->connected && !tunnel->pending.empty()) {
        PendingUdpPacket pkt = std::move(tunnel->pending.front());
        tunnel->pending.pop_front();
        tunnel->pending_bytes -= std::min(tunnel->pending_bytes, pkt.payload.size());
        udp_tunnel_pending_bytes_ -= std::min(udp_tunnel_pending_bytes_,
                                               pkt.payload.size());
        auto key = udp_session_keys_.find(pkt.session_id);
        if (key != udp_session_keys_.end()) {
            auto flow = udp_flows_.find(key->second);
            if (flow != udp_flows_.end()) {
                flow->second.pending_proxy_bytes -= std::min(
                    flow->second.pending_proxy_bytes, pkt.payload.size());
            }
        }
        if (pkt.dns_query) {
            send_dns_query(tunnel, pkt.session_id, pkt.payload.data(), pkt.payload.size());
        } else {
            send_udp_packet(tunnel, pkt.session_id, pkt.target,
                            pkt.payload.data(), pkt.payload.size());
        }
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
    cancel_udp_tunnel_handshake_timer(tunnel);
    tunnel->connecting = false;
    tunnel->connected = true;
    tunnel->retry_delay_ms = 0;
    cancel_udp_tunnel_retry(tunnel);
    TX_INFO("UDP tunnel handshake complete for outbound %s", tunnel->outbound->tag.c_str());

    if (tunnel->tunnel_session && !tunnel->tunnel_session->is_closed()) {
        std::weak_ptr<UdpTunnel> weak_tunnel = tunnel;
        tunnel->tunnel_session->start_read([this, weak_tunnel](SessionPtr, Buffer& more) {
            if (UdpTunnelPtr current = weak_tunnel.lock()) {
                if (!append_tunnel_input(current->recv_buf, more)) {
                    TX_ERROR("UDP tunnel receive buffer limit exceeded");
                    more.clear();
                    close_udp_tunnel(current);
                    return;
                }
                more.clear();
                on_udp_tunnel_read(current, current->recv_buf);
            } else {
                more.clear();
            }
        });
    }

    if (!tunnel->handshake_buf.empty()) {
        if (!append_tunnel_input(tunnel->recv_buf, tunnel->handshake_buf)) {
            TX_ERROR("UDP tunnel receive buffer limit exceeded after handshake");
            close_udp_tunnel(tunnel);
            return;
        }
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
            flow_it->second.outbound != tunnel->outbound ||
            flow_it->second.udp_tunnel_key != tunnel->key) {
            payload.clear();
            continue;
        }

        const std::string flow_key = key_it->second;
        if (flow_it->second.kind == UdpFlowKind::InternalDns) {
            if (cmd == TunnelCmd::DnsResponse) {
                flow_it->second.last_activity_ms = uv_now(loop_);
                std::vector<uint8_t> response(payload.data(),
                                              payload.data() + payload.readable());
                if (!response.empty() &&
                    !DnsResolver::response_matches_query(flow_it->second.dns_query,
                                                         response)) {
                    retry_internal_dns(flow_key, "mismatched DNS response");
                } else {
                    record_traffic(RouteAction::Proxy, false, response.size());
                    complete_internal_dns(flow_key, std::move(response), true);
                }
            } else if (cmd == TunnelCmd::Disconnect) {
                retry_internal_dns(flow_key, "remote DNS session closed");
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

void ClientApp::close_udp_tunnel(const UdpTunnelPtr& tunnel, bool retry_pending) {
    if (!tunnel) return;
    if (!retry_pending) cancel_udp_tunnel_retry(tunnel);
    cancel_udp_tunnel_handshake_timer(tunnel);
    auto session = std::move(tunnel->tunnel_session);
    tunnel->connected = false;
    tunnel->connecting = false;
    tunnel->handshake_buf.clear();
    tunnel->recv_buf.clear();
    if (!retry_pending) {
        for (const auto& packet : tunnel->pending) {
            auto key = udp_session_keys_.find(packet.session_id);
            if (key == udp_session_keys_.end()) continue;
            auto flow = udp_flows_.find(key->second);
            if (flow != udp_flows_.end()) {
                flow->second.pending_proxy_bytes -= std::min(
                    flow->second.pending_proxy_bytes, packet.payload.size());
            }
        }
        udp_tunnel_pending_bytes_ -= std::min(udp_tunnel_pending_bytes_,
                                               tunnel->pending_bytes);
        tunnel->pending.clear();
        tunnel->pending_bytes = 0;
    }
    tunnel->codec = TunnelCodec();
    TunnelCodec::cleanse_handshake_state(tunnel->handshake_state);
    if (!retry_pending) {
        std::vector<std::string> failed_dns_flows;
        for (const auto& item : udp_flows_) {
            if (item.second.kind == UdpFlowKind::InternalDns &&
                item.second.udp_tunnel_key == tunnel->key) {
                failed_dns_flows.push_back(item.first);
            }
        }
        for (const auto& flow_key : failed_dns_flows) remove_udp_flow(flow_key, false);
    }
    if (session && !session->is_closed()) {
        session->set_close_callback(nullptr);
        session->close();
    }
    if (retry_pending && !tunnel->pending.empty()) {
        schedule_udp_tunnel_retry(tunnel);
    }
}

void ClientApp::close_all_udp_tunnels() {
    std::vector<UdpTunnelPtr> tunnels;
    tunnels.reserve(udp_tunnels_.size());
    for (const auto& item : udp_tunnels_) tunnels.push_back(item.second);
    udp_tunnels_.clear();
    udp_mux_next_slot_.clear();
    for (const auto& tunnel : tunnels) close_udp_tunnel(tunnel);
    udp_tunnel_pending_bytes_ = 0;
}

void ClientApp::schedule_udp_tunnel_retry(const UdpTunnelPtr& tunnel) {
    if (!tunnel || stopping_ || tunnel->connected || tunnel->connecting ||
        tunnel->retry_timer || tunnel->pending.empty()) {
        return;
    }
    const uint32_t delay = tunnel->retry_delay_ms == 0 ? kUdpTunnelRetryInitialMs :
        std::min<uint32_t>(tunnel->retry_delay_ms, kUdpTunnelRetryMaxMs);
    tunnel->retry_delay_ms = std::min<uint32_t>(delay * 2, kUdpTunnelRetryMaxMs);
    auto* timer = new uv_timer_t;
    auto* ctx = new UdpTunnelRetryCtx;
    ctx->app = this;
    ctx->tunnel = tunnel;
    timer->data = ctx;
    if (uv_timer_init(loop_, timer) != 0) {
        delete ctx;
        delete timer;
        return;
    }
    if (uv_timer_start(timer, ClientApp::on_udp_tunnel_retry, delay, 0) != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_udp_tunnel_retry_closed);
        return;
    }
    tunnel->retry_timer = timer;
    TX_WARN("Retrying UDP tunnel %s in %u ms (%zu pending packets)",
            tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown", delay,
            tunnel->pending.size());
}

void ClientApp::cancel_udp_tunnel_retry(const UdpTunnelPtr& tunnel) {
    if (!tunnel || !tunnel->retry_timer) return;
    uv_timer_t* timer = tunnel->retry_timer;
    tunnel->retry_timer = nullptr;
    uv_timer_stop(timer);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_udp_tunnel_retry_closed);
    }
}

bool ClientApp::start_udp_tunnel_handshake_timer(const UdpTunnelPtr& tunnel) {
    if (!tunnel || !tunnel->connecting || tunnel->handshake_timer) return true;

    auto* timer = new uv_timer_t;
    auto* ctx = new UdpTunnelHandshakeCtx;
    ctx->app = this;
    ctx->tunnel = tunnel;
    timer->data = ctx;
    if (uv_timer_init(loop_, timer) != 0) {
        delete ctx;
        delete timer;
        return false;
    }
    if (uv_timer_start(timer, ClientApp::on_udp_tunnel_handshake_timeout,
                       kUdpTunnelHandshakeTimeoutMs, 0) != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer),
                 ClientApp::on_udp_tunnel_handshake_timer_closed);
        return false;
    }
    tunnel->handshake_timer = timer;
    TX_DEBUG("Started UDP tunnel handshake timer for %s (%llu ms)",
             tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown",
             static_cast<unsigned long long>(kUdpTunnelHandshakeTimeoutMs));
    return true;
}

void ClientApp::cancel_udp_tunnel_handshake_timer(const UdpTunnelPtr& tunnel) {
    if (!tunnel || !tunnel->handshake_timer) return;
    uv_timer_t* timer = tunnel->handshake_timer;
    tunnel->handshake_timer = nullptr;
    uv_timer_stop(timer);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer),
                 ClientApp::on_udp_tunnel_handshake_timer_closed);
    }
}

void ClientApp::on_udp_tunnel_handshake_timeout(uv_timer_t* timer) {
    auto* ctx = static_cast<UdpTunnelHandshakeCtx*>(timer ? timer->data : nullptr);
    ClientApp* app = ctx ? ctx->app : nullptr;
    UdpTunnelPtr tunnel = ctx ? ctx->tunnel.lock() : UdpTunnelPtr();
    if (tunnel && tunnel->handshake_timer == timer) tunnel->handshake_timer = nullptr;
    if (timer && !uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer),
                 ClientApp::on_udp_tunnel_handshake_timer_closed);
    }
    if (app && tunnel && !app->stopping_ && tunnel->connecting) {
        TX_WARN("UDP tunnel handshake timed out for %s; retrying with %zu pending packets",
                tunnel->outbound ? tunnel->outbound->tag.c_str() : "unknown",
                tunnel->pending.size());
        app->close_udp_tunnel(tunnel, true);
    }
}

void ClientApp::on_udp_tunnel_handshake_timer_closed(uv_handle_t* handle) {
    if (!handle) return;
    delete static_cast<UdpTunnelHandshakeCtx*>(handle->data);
    delete reinterpret_cast<uv_timer_t*>(handle);
}

void ClientApp::on_udp_tunnel_retry(uv_timer_t* timer) {
    auto* ctx = static_cast<UdpTunnelRetryCtx*>(timer ? timer->data : nullptr);
    UdpTunnelPtr tunnel = ctx ? ctx->tunnel.lock() : UdpTunnelPtr();
    ClientApp* app = ctx ? ctx->app : nullptr;
    if (tunnel && tunnel->retry_timer == timer) tunnel->retry_timer = nullptr;
    if (timer && !uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_udp_tunnel_retry_closed);
    }
    if (app && tunnel && !app->stopping_ && !tunnel->pending.empty()) {
        app->ensure_udp_tunnel(tunnel);
    }
}

void ClientApp::on_udp_tunnel_retry_closed(uv_handle_t* handle) {
    if (!handle) return;
    delete static_cast<UdpTunnelRetryCtx*>(handle->data);
    delete reinterpret_cast<uv_timer_t*>(handle);
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
    if (!app->normalize_fake_ip_target(target, "[SOCKS5][UDP]")) return;

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
    UdpTunnelPtr tunnel = app->select_udp_tunnel(it->second);
    app->send_udp_packet(tunnel, it->second.session_id,
                         target, payload, payload_len);
}

void ClientApp::on_udp_send_done(uv_udp_send_t* req, int status) {
    auto* request = static_cast<UdpSendRequest*>(req->data);
    free_udp_send_request(request);
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
    const bool supplied_tun_fd = config_.tun_fd >= 0;
    if (!tun_device_->open(config_, error)) {
        TX_ERROR("Failed to open TUN device: %s", error.c_str());
        if (supplied_tun_fd) config_.tun_fd = -1;
        tun_device_.reset();
        return false;
    }
    outbound_socket_policy_ = tun_device_->outbound_socket_policy();

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
                return write_tun_packet(packet, len);
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
    tun_write_queue_.clear();
    tun_poll_writable_ = false;
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
    outbound_socket_policy_ = OutboundSocketPolicy();
    tun_fd_ = -1;
}

bool ClientApp::start_tun_tcp_redirect() {
    if (config_.tun_tcp_stack == "lwip") {
        outbound_socket_policy_.mark = config_.tun_bypass_mark;
        return true;
    }
    if (!config_.tun_auto_redirect) {
        outbound_socket_policy_.mark = 0;
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

    outbound_socket_policy_.mark = config_.tun_redirect_mark;
    if (!install_linux_auto_redirect(config_.tun_redirect_port,
                                     config_.tun_redirect_mark)) {
        outbound_socket_policy_.mark = 0;
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
        outbound_socket_policy_.mark = 0;
        return;
    }
    if (!tun_tcp_redirect_started_) return;
    tun_tcp_redirect_started_ = false;
#if defined(TX_PLATFORM_LINUX)
    uninstall_linux_auto_redirect();
#endif
    outbound_socket_policy_.mark = 0;
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
    } else if (fake_ip_dns_.contains_address(conn->target.host)) {
        TX_WARN("[TUN][TCP] rejecting stale Fake-IP target %s:%u without reverse mapping",
                conn->target.host.c_str(), conn->target.port);
        session->close();
        return;
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
    connections_[conn->session_id] = conn;

    std::weak_ptr<ProxyConn> weak_conn = conn;
    session->set_close_callback([this, weak_conn](SessionPtr) {
        if (auto current = weak_conn.lock()) on_proxy_close(current);
    });
    session->set_eof_callback([this, weak_conn](SessionPtr) {
        if (auto current = weak_conn.lock()) on_local_eof(current);
    });

    session->start_read([this, weak_conn](SessionPtr, Buffer& data) {
        auto conn = weak_conn.lock();
        if (!conn) { data.clear(); return; }
        const size_t limit = conn->target_dispatched ? TcpFlowBridge::kHardLimit : 65540;
        if (!append_proxy_input(conn, data, limit, "transparent TCP pre-connect")) return;

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

bool ClientApp::append_proxy_input(ProxyConnPtr conn, Buffer& data,
                                   size_t hard_limit, const char* phase) {
    if (!conn || conn->closing) {
        data.clear();
        return false;
    }
    const size_t incoming = data.readable();
    if (incoming > hard_limit || conn->proto_buf.readable() > hard_limit - incoming) {
        TX_WARN("%s buffer limit reached for %s:%u",
                phase ? phase : "proxy pre-connect",
                conn->target.host.c_str(), conn->target.port);
        data.clear();
        fail_proxy_connection(conn, 413);
        return false;
    }
    conn->proto_buf.append(data);
    data.clear();
    if (!conn->connected && !conn->local_paused_for_connect &&
        conn->proto_buf.readable() >= TcpFlowBridge::kHighWatermark &&
        conn->local_session && !conn->local_session->is_closed()) {
        conn->local_paused_for_connect = true;
        conn->local_session->pause_read();
    }
    return true;
}

bool ClientApp::append_lwip_tcp_data(ProxyConnPtr conn, Buffer& data) {
    if (conn && !conn->closing && conn->connected && conn->target_dispatched &&
        conn->proto_buf.empty()) {
        const size_t bytes = data.readable();
        if (conn->route == RouteAction::Direct && conn->direct_session) {
            const bool sent = conn->bridge ? conn->bridge->forward_from_left(data)
                                           : conn->direct_session->send(data);
            if (!sent) {
                if (conn->local_session && !conn->local_session->is_closed()) {
                    conn->local_session->reset();
                }
                return false;
            }
            record_traffic(RouteAction::Direct, true, bytes);
        } else {
            tunnel_send(conn, data.data(), bytes);
            data.clear();
        }
        return true;
    }
    return append_proxy_input(conn, data, TcpFlowBridge::kHardLimit,
                              "lwIP TCP pre-connect");
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
                if (!generated) {
                    resolve_dns_via_tunnel(std::move(query),
                        [weak_stream](std::vector<uint8_t> upstream) {
                            auto current = weak_stream.lock();
                            if (!current || current->is_closed()) return;
                            if (upstream.empty()) return;
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
    } else if (fake_ip_dns_.contains_address(conn->target.host)) {
        TX_WARN("[TUN][TCP] rejecting stale Fake-IP target %s:%u without reverse mapping",
                conn->target.host.c_str(), conn->target.port);
        stream->reset();
        return;
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
    connections_[conn->session_id] = conn;

    std::weak_ptr<ProxyConn> weak_conn = conn;
    stream->set_close_callback([this, weak_conn]() {
        if (auto current = weak_conn.lock()) on_proxy_close(current);
    });
    stream->set_eof_callback([this, weak_conn]() {
        if (auto current = weak_conn.lock()) on_local_eof(current);
    });
    stream->set_error_callback([weak_conn](int) {
        if (auto conn = weak_conn.lock()) {
            if (conn->local_session && !conn->local_session->is_closed())
                conn->local_session->reset();
        }
    });
    stream->set_data_callback([this, weak_conn](Buffer& data) {
        auto conn = weak_conn.lock();
        if (!conn) { data.clear(); return; }
        if (!append_lwip_tcp_data(conn, data)) return;
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
    if ((events & UV_WRITABLE) != 0) app->flush_tun_write_queue();
    if ((events & UV_READABLE) != 0) app->drain_tun_packets();
}

void ClientApp::on_tun_timer(uv_timer_t* timer) {
    auto* app = static_cast<ClientApp*>(timer->data);
    if (!app || !app->tun_started_) return;
    app->lwip_udp_stack_.poll_timers();
    app->flush_tun_write_queue();
    const TunDrainResult drain_result = app->drain_tun_packets();
    if (app->tun_started_) {
        uint64_t timeout = app->lwip_udp_stack_.next_timeout_ms();
        if (!app->tun_write_queue_.empty() ||
            drain_result == TunDrainResult::BudgetExhausted) {
            timeout = std::min<uint64_t>(timeout, 1);
        }
        uv_timer_start(timer, ClientApp::on_tun_timer,
                       timeout, 0);
    }
}

ClientApp::TunDrainResult ClientApp::drain_tun_packets() {
    if (!tun_device_) return TunDrainResult::Empty;
    const uint64_t started_at = uv_hrtime();
    size_t packets = 0;
    size_t bytes = 0;
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
            const size_t packet_size = static_cast<size_t>(nread);
            handle_tun_packet(tun_read_buf_.data(), packet_size);
            ++packets;
            bytes += packet_size;
            ++tun_perf_stats_.rx_packets;
            tun_perf_stats_.rx_bytes += packet_size;
            if (packets >= kTunDrainPacketBudget || bytes >= kTunDrainByteBudget ||
                ((packets & 7u) == 0 &&
                 uv_hrtime() - started_at >= kTunDrainTimeBudgetNs)) {
                ++tun_perf_stats_.rx_budget_yields;
                schedule_tun_retry();
                return TunDrainResult::BudgetExhausted;
            }
            continue;
        }
        if (nread < 0 && !error.empty()) {
            TX_WARN("TUN read failed: %s", error.c_str());
            return TunDrainResult::Error;
        }
        return TunDrainResult::Empty;
    }
}

void ClientApp::schedule_tun_retry() {
    if (!tun_timer_started_ || stopping_) return;
    uv_timer_start(&tun_timer_, ClientApp::on_tun_timer, 1, 0);
}

void ClientApp::set_tun_poll_writable(bool enabled) {
    if (tun_fd_ < 0 || tun_poll_writable_ == enabled || !tun_started_) return;
    const int events = UV_READABLE | (enabled ? UV_WRITABLE : 0);
    const int status = uv_poll_start(&tun_poll_, events, ClientApp::on_tun_poll);
    if (status == 0) {
        tun_poll_writable_ = enabled;
        return;
    }
    TX_WARN("Failed to update TUN poll events: %s", uv_strerror(status));
    schedule_tun_retry();
}

bool ClientApp::write_tun_packet(const uint8_t* data, size_t len) {
    if (!tun_device_ || (!data && len != 0)) return false;
    const auto queue_packet = [this, data, len]() {
        if (!tun_write_queue_.push(data, len)) {
            ++tun_perf_stats_.tx_dropped;
            const uint64_t now = uv_now(loop_);
            if (tun_last_write_warning_ms_ == 0 ||
                now - tun_last_write_warning_ms_ >= 1000) {
                tun_last_write_warning_ms_ = now;
                TX_WARN("TUN output queue full: packets=%zu bytes=%zu dropped=%llu",
                        tun_write_queue_.packet_count(), tun_write_queue_.byte_count(),
                        static_cast<unsigned long long>(tun_perf_stats_.tx_dropped));
            }
            return false;
        }
        ++tun_perf_stats_.tx_queued;
        tun_perf_stats_.tx_max_queued_bytes = std::max(
            tun_perf_stats_.tx_max_queued_bytes, tun_write_queue_.byte_count());
        set_tun_poll_writable(true);
        if (tun_fd_ < 0) schedule_tun_retry();
        return true;
    };

    if (!tun_write_queue_.empty()) return queue_packet();

    std::string error;
    const PlatformTunDevice::WriteResult result =
        tun_device_->write_packet(data, len, error);
    if (result == PlatformTunDevice::WriteResult::Written) {
        ++tun_perf_stats_.tx_immediate;
        return true;
    }
    if (result == PlatformTunDevice::WriteResult::WouldBlock) {
        ++tun_perf_stats_.tx_would_block;
        return queue_packet();
    }

    ++tun_perf_stats_.tx_errors;
    const uint64_t now = uv_now(loop_);
    if (tun_last_write_warning_ms_ == 0 || now - tun_last_write_warning_ms_ >= 1000) {
        tun_last_write_warning_ms_ = now;
        TX_WARN("TUN write failed: %s (errors=%llu)", error.c_str(),
                static_cast<unsigned long long>(tun_perf_stats_.tx_errors));
    }
    return false;
}

void ClientApp::flush_tun_write_queue() {
    if (!tun_device_ || tun_write_queue_.empty()) {
        set_tun_poll_writable(false);
        return;
    }

    const uint64_t started_at = uv_hrtime();
    size_t packets = 0;
    size_t bytes = 0;
    while (!tun_write_queue_.empty()) {
        const Buffer& packet = tun_write_queue_.front();
        std::string error;
        const PlatformTunDevice::WriteResult result =
            tun_device_->write_packet(packet.data(), packet.readable(), error);
        if (result == PlatformTunDevice::WriteResult::WouldBlock) {
            ++tun_perf_stats_.tx_would_block;
            set_tun_poll_writable(true);
            if (tun_fd_ < 0) schedule_tun_retry();
            return;
        }

        const size_t packet_size = packet.readable();
        tun_write_queue_.pop();
        ++packets;
        bytes += packet_size;
        if (result == PlatformTunDevice::WriteResult::Written) {
            ++tun_perf_stats_.tx_immediate;
        } else {
            ++tun_perf_stats_.tx_errors;
            const uint64_t now = uv_now(loop_);
            if (tun_last_write_warning_ms_ == 0 ||
                now - tun_last_write_warning_ms_ >= 1000) {
                tun_last_write_warning_ms_ = now;
                TX_WARN("Queued TUN write failed: %s (errors=%llu)", error.c_str(),
                        static_cast<unsigned long long>(tun_perf_stats_.tx_errors));
            }
        }
        if (packets >= kTunWritePacketBudget || bytes >= kTunWriteByteBudget ||
            ((packets & 7u) == 0 &&
             uv_hrtime() - started_at >= kTunWriteTimeBudgetNs)) {
            if (!tun_write_queue_.empty()) {
                set_tun_poll_writable(true);
                schedule_tun_retry();
            }
            return;
        }
    }
    set_tun_poll_writable(false);
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
    TX_DEBUG("[TUN][UDP][ROUTE] sid=%u route=%s:%u send=%s:%u outbound=%s",
             flow.session_id, route_target.host.c_str(), route_target.port,
             send_target.host.c_str(), send_target.port, outbound->tag.c_str());
    return true;
}

bool ClientApp::inherit_tun_quic_route(UdpFlow& flow, const uint8_t* data, size_t len) {
    if (!data || len < 2) return false;
    const uint64_t now = uv_now(loop_);
    std::string cid;
    std::string ignored;
    if ((data[0] & 0x80) != 0) {
        if (!extract_quic_long_connection_ids(data, len, cid, ignored) || cid.empty()) {
            return false;
        }
    } else {
        // A short header contains the destination CID immediately after its
        // first byte.  Its length is implicit, so compare it to bounded CIDs
        // learned from the server's long-header responses.
        if ((data[0] & 0x40) == 0) return false;
        if (len < 2) return false;
        std::vector<std::string> matches;
        auto& candidates = quic_route_cids_by_first_byte_[data[1]];
        // Tests and embedders may seed the private cache directly. Rebuild
        // this one bucket lazily if it predates the auxiliary index.
        if (candidates.empty() && !quic_route_cache_.empty()) {
            for (const auto& item : quic_route_cache_) {
                if (!item.first.empty() &&
                    static_cast<uint8_t>(item.first[0]) == data[1]) {
                    candidates.insert(item.first);
                }
            }
        }
        for (const auto& known : candidates) {
            auto it = quic_route_cache_.find(known);
            if (it == quic_route_cache_.end()) continue;
            if (it->second.expires_at_ms <= now || !it->second.outbound) {
                continue;
            }
            if (!known.empty() && known.size() <= len - 1 &&
                std::memcmp(data + 1, known.data(), known.size()) == 0) {
                matches.push_back(known);
            }
        }
        // Short headers carry no CID length.  Choosing one of several prefix
        // matches would make routing depend on unordered_map iteration order,
        // so ambiguity deliberately falls back to the original IP route.
        if (matches.size() != 1) return false;
        cid = matches.front();
    }

    const auto it = quic_route_cache_.find(cid);
    if (it == quic_route_cache_.end() || it->second.expires_at_ms <= now ||
        !it->second.outbound) {
        if (it != quic_route_cache_.end()) {
            if (!it->first.empty()) {
                quic_route_cids_by_first_byte_[
                    static_cast<uint8_t>(it->first[0])].erase(it->first);
            }
            quic_route_cache_.erase(it);
        }
        return false;
    }

    release_tun_quic_sniffer(flow);
    flow.route_target = it->second.route_target;
    flow.outbound = it->second.outbound;
    flow.proxied = flow.outbound->type == OutboundType::Tx;
    flow.route_ready = true;
    it->second.last_used_at_ms = now;
    it->second.expires_at_ms = now + config_.udp_idle_timeout_ms;
    TX_DEBUG("[TUN][QUIC] inherited route %s from CID cache",
             flow.route_target.host.c_str());
    return true;
}

void ClientApp::remember_tun_quic_route(const UdpFlow& flow, const std::string& cid) {
    if (cid.empty() || !flow.route_ready || !flow.outbound ||
        flow.route_target.type != AddrType::Domain) {
        return;
    }
    if (quic_route_cache_.find(cid) == quic_route_cache_.end() &&
        quic_route_cache_.size() >= kMaxQuicRouteCacheEntries) {
        auto victim = quic_route_cache_.end();
        for (auto it = quic_route_cache_.begin(); it != quic_route_cache_.end(); ++it) {
            if (victim == quic_route_cache_.end() ||
                it->second.last_used_at_ms < victim->second.last_used_at_ms ||
                (it->second.last_used_at_ms == victim->second.last_used_at_ms &&
                 it->first < victim->first)) {
                victim = it;
            }
        }
        if (victim != quic_route_cache_.end()) {
            if (!victim->first.empty()) {
                quic_route_cids_by_first_byte_[
                    static_cast<uint8_t>(victim->first[0])].erase(victim->first);
            }
            quic_route_cache_.erase(victim);
        }
    }
    QuicRouteCacheEntry entry;
    entry.route_target = flow.route_target;
    entry.outbound = flow.outbound;
    entry.last_used_at_ms = uv_now(loop_);
    entry.expires_at_ms = entry.last_used_at_ms + config_.udp_idle_timeout_ms;
    quic_route_cache_[cid] = std::move(entry);
    quic_route_cids_by_first_byte_[static_cast<uint8_t>(cid[0])].insert(cid);
}

void ClientApp::remember_tun_quic_response_route(const UdpFlow& flow,
                                                  const uint8_t* data, size_t len) {
    if (flow.kind != UdpFlowKind::Tun || flow.send_target.port != 443) return;
    std::string dcid;
    std::string scid;
    if (!extract_quic_long_connection_ids(data, len, dcid, scid)) return;
    // The server's SCID becomes the client's destination CID for subsequent
    // short-header packets, including after QUIC connection migration.
    remember_tun_quic_route(flow, scid);
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

    // A QUIC Initial can reveal a domain after the application has already
    // chosen a numeric address. The recovered SNI is only a routing hint;
    // keep sending to the original address so Retry tokens, connection
    // migration, and CDN affinity stay tied to the endpoint the application
    // selected.
    UdpTunnelPtr tunnel = select_udp_tunnel(flow);
    send_udp_packet(tunnel, flow.session_id, flow.send_target, data, len);
}

void ClientApp::release_tun_quic_sniffer(UdpFlow& flow) {
    if (flow.quic_sniffer) {
        flow.quic_sniffer.reset();
        if (quic_sniff_active_flows_ > 0) --quic_sniff_active_flows_;
    }
    flow.quic_sniff_deadline_ms = 0;
    ++flow.deadline_generation;
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

    if (flow.quic_initial_dcid.empty()) {
        std::string ignored;
        extract_quic_long_connection_ids(data, len, flow.quic_initial_dcid, ignored);
    }

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
        schedule_udp_deadline(flow, UdpDeadlineKind::QuicSniff,
                              uv_now(loop_) + kQuicSniffTimeoutMs);
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
            remember_tun_quic_route(flow, flow.quic_initial_dcid);
            flush_tun_quic_pending(flow_key, flow);
        } else {
            release_tun_quic_sniffer(flow);
            clear_tun_quic_pending(flow);
        }
        return;
    }
    if (result == QuicSniResult::NeedMore) {
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
    if (destination.port == 53) {
        static std::atomic<unsigned> dns_diagnostics{0};
        std::vector<uint8_t> query(data, data + len);
        std::vector<uint8_t> response;
        const uint64_t now = uv_now(loop_);
        auto dns_flow = tun_dns_flows_.find(lwip_flow_id);
        if (dns_flow == tun_dns_flows_.end()) {
            const size_t configured_limit = static_cast<size_t>(config_.udp_max_flows);
            const size_t dns_flow_limit = std::min(configured_limit, kMaxTunDnsFlows);
            if (dns_flow_limit == 0 || tun_dns_flows_.size() >= dns_flow_limit) {
                if (build_dns_servfail(query, response)) {
                    lwip_udp_stack_.send_response(lwip_flow_id, destination,
                                                  response.data(), response.size());
                }
                TX_WARN("[DNS][TUN] rejecting new flow=%llu: flow limit reached (%zu)",
                        static_cast<unsigned long long>(lwip_flow_id), dns_flow_limit);
                lwip_udp_stack_.close_flow(lwip_flow_id);
                return;
            }
            TunDnsFlow flow;
            flow.generation = next_tun_dns_generation_++;
            if (flow.generation == 0) flow.generation = next_tun_dns_generation_++;
            flow.destination = destination;
            flow.last_activity_ms = now;
            dns_flow = tun_dns_flows_.emplace(lwip_flow_id, std::move(flow)).first;
        } else {
            dns_flow->second.destination = destination;
            dns_flow->second.last_activity_ms = now;
        }
        const uint64_t dns_generation = dns_flow->second.generation;
        const bool generated = fake_ip_dns_.respond(query.data(), query.size(), response);
        const bool sent = generated && lwip_udp_stack_.send_response(
            lwip_flow_id, destination, response.data(), response.size());
        const unsigned diagnostic = dns_diagnostics.fetch_add(1);
        if (diagnostic < 12) {
            TX_WARN("[DNS][TUN] flow=%llu generation=%llu query=%zu response=%zu "
                    "generated=%d sent=%d pending=%zu dst=%s",
                    static_cast<unsigned long long>(lwip_flow_id),
                    static_cast<unsigned long long>(dns_generation), query.size(), response.size(),
                    generated ? 1 : 0, sent ? 1 : 0, dns_flow->second.pending_queries,
                    ipaddr_host_string(destination).c_str());
        }
        if (generated) {
            if (!sent) {
                TX_WARN("[DNS][TUN] local response write failed for flow=%llu",
                        static_cast<unsigned long long>(lwip_flow_id));
                lwip_udp_stack_.close_flow(lwip_flow_id);
                tun_dns_flows_.erase(lwip_flow_id);
            }
            return;
        }

        if (dns_flow->second.pending_queries >= kMaxTunDnsPendingQueries) {
            if (build_dns_servfail(query, response)) {
                lwip_udp_stack_.send_response(lwip_flow_id, destination,
                                              response.data(), response.size());
            }
            TX_WARN("[DNS][TUN] rejecting unresolved query flow=%llu pending=%zu",
                    static_cast<unsigned long long>(lwip_flow_id),
                    dns_flow->second.pending_queries);
            return;
        }

        ++dns_flow->second.pending_queries;
        const std::vector<uint8_t> query_for_error = query;
        resolve_dns_via_tunnel(std::move(query),
            [this, lwip_flow_id, dns_generation, destination,
             query = query_for_error](std::vector<uint8_t> upstream) mutable {
                auto current = tun_dns_flows_.find(lwip_flow_id);
                if (current == tun_dns_flows_.end() ||
                    current->second.generation != dns_generation) {
                    return;
                }
                if (current->second.pending_queries > 0) {
                    --current->second.pending_queries;
                }
                current->second.last_activity_ms = uv_now(loop_);
                if (upstream.empty()) {
                    build_dns_servfail(query, upstream);
                }
                const bool written = !upstream.empty() && lwip_udp_stack_.send_response(
                    lwip_flow_id, destination, upstream.data(), upstream.size());
                TX_DEBUG("[DNS][TUN] async response flow=%llu generation=%llu bytes=%zu "
                         "written=%d pending=%zu",
                         static_cast<unsigned long long>(lwip_flow_id),
                         static_cast<unsigned long long>(dns_generation), upstream.size(),
                         written ? 1 : 0, current->second.pending_queries);
            });
        return;
    }

    // Existing TUN flows have already completed Fake-IP recovery, QUIC
    // sniffing, and routing. Resolve them by the stable lwIP flow id before
    // allocating strings or touching the Fake-IP cache.
    auto indexed = tun_udp_flow_sessions_.find(lwip_flow_id);
    if (indexed != tun_udp_flow_sessions_.end()) {
        auto key = udp_session_keys_.find(indexed->second);
        if (key != udp_session_keys_.end()) {
            auto existing = udp_flows_.find(key->second);
            if (existing != udp_flows_.end() &&
                existing->second.kind == UdpFlowKind::Tun &&
                existing->second.lwip_flow_id == lwip_flow_id) {
                UdpFlow& flow = existing->second;
                flow.last_activity_ms = uv_now(loop_);
                if (flow.route_ready) {
                    ++tun_perf_stats_.udp_flow_fast_hits;
                    dispatch_tun_udp_packet(key->second, flow, data, len);
                    return;
                }
                if (!flow.fake_ip_target && flow.send_target.port == 443 &&
                    config_.udp_quic_sniff) {
                    ++tun_perf_stats_.udp_flow_fast_hits;
                    if (inherit_tun_quic_route(flow, data, len)) {
                        dispatch_tun_udp_packet(key->second, flow, data, len);
                    } else {
                        process_tun_quic_packet(key->second, flow, data, len);
                    }
                    return;
                }
            } else {
                tun_udp_flow_sessions_.erase(indexed);
            }
        } else {
            tun_udp_flow_sessions_.erase(indexed);
        }
    }
    ++tun_perf_stats_.udp_flow_fast_misses;

    TargetAddr target;
    target.type = destination.family == IpAddr::IPv4 ? AddrType::IPv4 : AddrType::IPv6;
    target.host = ipaddr_host_string(destination);
    target.port = destination.port;

    const TargetAddr numeric_target = target;
    std::string domain;
    const bool fake_ip = fake_ip_dns_.reverse_lookup(target.host, domain);
    if (!fake_ip && fake_ip_dns_.contains_address(target.host)) {
        TX_WARN("[TUN][UDP] dropping stale Fake-IP target %s:%u without reverse mapping",
                target.host.c_str(), target.port);
        lwip_udp_stack_.close_flow(lwip_flow_id);
        return;
    }
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
        flow.fake_ip_target = fake_ip;
        flow.lwip_flow_id = lwip_flow_id;
        const SessionId session_id = flow.session_id;
        it = udp_flows_.emplace(flow_key, std::move(flow)).first;
        udp_session_keys_[session_id] = flow_key;
        tun_udp_flow_sessions_[lwip_flow_id] = session_id;
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
        if (inherit_tun_quic_route(flow, data, len)) {
            dispatch_tun_udp_packet(flow_key, flow, data, len);
            return;
        }
        process_tun_quic_packet(flow_key, flow, data, len);
        return;
    }

    if (finalize_tun_udp_route(flow, numeric_target, numeric_target)) {
        dispatch_tun_udp_packet(flow_key, flow, data, len);
    }
}

bool ClientApp::tun_udp_response_source(const UdpFlow& flow,
                                        const TargetAddr& source,
                                        IpAddr& output) const {
    if (flow.fake_ip_target) {
        output = flow.tun_dst_ip;
        return true;
    }
    return IpAddr::parse(source.host, source.port, output);
}

bool ClientApp::write_tun_udp_packet(const UdpFlow& flow, const TargetAddr& source,
                                     const uint8_t* data, size_t len) {
    if (!tun_started_ || !tun_device_) return false;

    IpAddr src;
    if (!tun_udp_response_source(flow, source, src)) return false;
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
    connections_[conn->session_id] = conn;

    bind_proxy_target_callback(conn);
    start_tunnel_timer(conn, kProxyHandshakeTimeoutMs, "HTTP negotiation");

    std::weak_ptr<ProxyConn> weak_conn = conn;
    session->set_close_callback([this, weak_conn](SessionPtr) {
        if (auto current = weak_conn.lock()) on_proxy_close(current);
    });
    session->set_eof_callback([this, weak_conn](SessionPtr) {
        if (auto current = weak_conn.lock()) on_local_eof(current);
    });

    session->start_read([this, weak_conn](SessionPtr, Buffer& data) {
        auto conn = weak_conn.lock();
        if (!conn) { data.clear(); return; }
        const size_t limit = conn->http->state() == HttpProxyHandler::State::Request
            ? kMaxHttpHandshakeBytes : TcpFlowBridge::kHardLimit;
        if (!append_proxy_input(conn, data, limit, "HTTP negotiation/pre-connect")) return;

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
                fail_proxy_connection(conn, 400);
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
    connections_[conn->session_id] = conn;

    bind_proxy_target_callback(conn);
    start_tunnel_timer(conn, kProxyHandshakeTimeoutMs, "SOCKS5 negotiation");

    std::weak_ptr<ProxyConn> weak_conn = conn;
    session->set_close_callback([this, weak_conn](SessionPtr) {
        if (auto current = weak_conn.lock()) on_proxy_close(current);
    });
    session->set_eof_callback([this, weak_conn](SessionPtr) {
        if (auto current = weak_conn.lock()) on_local_eof(current);
    });

    session->start_read([this, weak_conn](SessionPtr, Buffer& data) {
        auto conn = weak_conn.lock();
        if (!conn) { data.clear(); return; }
        const size_t limit = conn->socks5->state() == Socks5State::Connected
            ? TcpFlowBridge::kHardLimit : kMaxSocks5HandshakeBytes;
        if (!append_proxy_input(conn, data, limit, "SOCKS5 negotiation/pre-connect")) return;

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
                    fail_proxy_connection(conn);
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
                        stop_tunnel_timer(conn);
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
    if (!conn || conn->closing) return;
    stop_tunnel_timer(conn);
    TX_INFO("Target resolved: %s:%u", conn->target.host.c_str(), conn->target.port);

    // Route decision
    resolve_and_route(conn);
}

bool ClientApp::normalize_fake_ip_target(TargetAddr& target, const char* context) {
    std::string domain;
    if (fake_ip_dns_.reverse_lookup(target.host, domain)) {
        TX_DEBUG("%s: restored Fake-IP %s to %s", context ? context : "Target",
                 target.host.c_str(), domain.c_str());
        target.type = AddrType::Domain;
        target.host = std::move(domain);
        return true;
    }
    if (fake_ip_dns_.contains_address(target.host)) {
        TX_WARN("%s: rejecting stale Fake-IP target %s:%u without reverse mapping",
                context ? context : "Target", target.host.c_str(), target.port);
        return false;
    }
    return true;
}

void ClientApp::resolve_and_route(ProxyConnPtr conn) {
    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    // This is deliberately checked again at the common proxy entry point.
    // TUN already performs the same conversion, but HTTP/SOCKS5 callers and
    // transparent Linux flows can reach this function through another path.
    if (!normalize_fake_ip_target(conn->target, "[Target]")) {
        block_connection(conn);
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

    direct_dns_resolver_.resolve_host(conn->target.host, AF_UNSPEC,
        [this, conn](std::vector<std::string> result) {
            if (!conn || !conn->local_session || conn->local_session->is_closed()) return;
            if (result.empty()) {
                TX_ERROR("Direct DNS failed for %s", conn->target.host.c_str());
                fail_proxy_connection(conn);
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
    while (addresses && index < addresses->size() &&
           (fake_ip_dns_.contains_address((*addresses)[index]) ||
            !android_address_family_available(numeric_address_family((*addresses)[index])))) {
        if (fake_ip_dns_.contains_address((*addresses)[index])) {
            TX_WARN("[Direct] rejecting protected Fake-IP candidate %s for %s:%u",
                    (*addresses)[index].c_str(), conn->target.host.c_str(), conn->target.port);
            ++index;
            continue;
        }
        TX_INFO("Skipping direct IPv%d address %s: physical network has no default route",
                numeric_address_family((*addresses)[index]) == AF_INET6 ? 6 : 4,
                (*addresses)[index].c_str());
        ++index;
    }
    if (!addresses || index >= addresses->size()) {
        TX_WARN("[Direct] physical network has no usable address family for %s:%u",
                conn->target.host.c_str(), conn->target.port);
        fail_proxy_connection(conn);
        return;
    }

    auto direct = std::make_shared<TcpSession>(loop_, socket_protector_,
                                               outbound_socket_policy_);
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
                fail_proxy_connection(conn);
                return;
            }

            conn->connected = true;
            conn->bridge = std::make_shared<TcpFlowBridge>(conn->local_session, direct);
            std::weak_ptr<TcpFlowBridge> weak_bridge = conn->bridge;
            direct->set_write_drain_callback([weak_bridge, conn](SessionPtr) {
                // TcpFlowBridge owns the actual local read pause once the
                // direct socket becomes writable. Clear the pre-connect
                // reason before it resumes the local stream so the two state
                // machines cannot leave a stale pause bit behind.
                conn->local_paused_for_connect = false;
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
            release_local_read(conn);

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
    direct_dns_resolver_.resolve_host(server_host, AF_UNSPEC,
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
    while (addresses && index < addresses->size() &&
           (fake_ip_dns_.contains_address((*addresses)[index]) ||
            !android_address_family_available(numeric_address_family((*addresses)[index])))) {
        if (fake_ip_dns_.contains_address((*addresses)[index])) {
            TX_WARN("Rejecting protected Fake-IP TX server candidate %s",
                    (*addresses)[index].c_str());
            ++index;
            continue;
        }
        TX_INFO("Skipping TX server IPv%d address %s: physical network has no default route",
                numeric_address_family((*addresses)[index]) == AF_INET6 ? 6 : 4,
                (*addresses)[index].c_str());
        ++index;
    }
    if (!conn || !addresses || index >= addresses->size() || !conn->outbound ||
        !conn->local_session || conn->local_session->is_closed()) {
        if (conn) fail_tunnel_connection(conn);
        return;
    }
    auto tunnel = std::make_shared<TcpSession>(loop_, socket_protector_,
                                               outbound_socket_policy_);
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
    tunnel->set_write_drain_callback([this, conn](SessionPtr tunnel_session) {
        if (conn->local_paused_for_tunnel && conn->local_session &&
            tunnel_session->pending_write_bytes() <= TcpFlowBridge::kLowWatermark) {
            conn->local_paused_for_tunnel = false;
            if (conn->local_paused_for_connect) {
                // The local stream may still be paused because the target
                // connection was not ready when its input was buffered.
                // release_local_read() will resume it only after both pause
                // reasons have cleared.
                release_local_read(conn);
            } else {
                conn->local_session->resume_read();
            }
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
        if (!append_tunnel_input(conn->tunnel_recv_buf, conn->tunnel_handshake_buf)) {
            TX_ERROR("Tunnel receive buffer limit exceeded after handshake for session %u",
                     conn->session_id);
            fail_tunnel_connection(conn);
            return;
        }
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
        if (!append_tunnel_input(conn->tunnel_recv_buf, data)) {
            TX_ERROR("Tunnel receive buffer limit exceeded for session %u",
                     conn->session_id);
            data.clear();
            fail_tunnel_connection(conn);
            return;
        }
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

    if (!tunnel_send_connect(conn)) return;
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
    release_local_read(conn);
}

void ClientApp::release_local_read(ProxyConnPtr conn) {
    if (!conn || !conn->local_paused_for_connect || !conn->local_session ||
        conn->local_session->is_closed()) {
        return;
    }
    if (conn->local_paused_for_tunnel) return;
    if (conn->route == RouteAction::Direct && conn->bridge && conn->direct_session &&
        conn->direct_session->pending_write_bytes() >= TcpFlowBridge::kHighWatermark) {
        return;
    }

    conn->local_paused_for_connect = false;
    conn->local_session->resume_read();
}

void ClientApp::fail_tunnel_connection(ProxyConnPtr conn) {
    fail_proxy_connection(conn);
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
    ctx->app->fail_proxy_connection(conn);

    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_tunnel_timer_closed);
    }
}

void ClientApp::on_tunnel_timer_closed(uv_handle_t* handle) {
    auto* ctx = static_cast<TunnelTimerCtx*>(handle->data);
    delete ctx;
    delete reinterpret_cast<uv_timer_t*>(handle);
}

bool ClientApp::tunnel_send_connect(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        fail_tunnel_connection(conn);
        return false;
    }

    Buffer encoded(512);
    if (!conn->tunnel_codec.encode(TunnelCmd::Connect, conn->session_id,
                                   conn->target, nullptr, 0, encoded) ||
        !conn->tunnel_session->send(std::move(encoded))) {
        TX_ERROR("Failed to queue CONNECT frame for session %u", conn->session_id);
        fail_tunnel_connection(conn);
        return false;
    }
    return true;
}

void ClientApp::tunnel_send(ProxyConnPtr conn, const uint8_t* data, size_t len) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        fail_tunnel_connection(conn);
        return;
    }

    size_t offset = 0;
    TargetAddr dummy;
    while (offset < len) {
        const size_t chunk = std::min(TunnelCodec::kMaxDataPayloadSize, len - offset);
        size_t frame_size = 0;
        if (!TunnelCodec::encoded_frame_size(TunnelCmd::Data, dummy, chunk, frame_size) ||
            frame_size > TcpFlowBridge::kHardLimit ||
            conn->tunnel_session->pending_write_bytes() >
                TcpFlowBridge::kHardLimit - frame_size) {
            fail_proxy_connection(conn);
            return;
        }
        Buffer encoded(frame_size);
        if (!conn->tunnel_codec.encode_data(conn->session_id, data + offset,
                                             chunk, encoded) ||
            !conn->tunnel_session->send(std::move(encoded))) {
            fail_proxy_connection(conn);
            return;
        }
        offset += chunk;
        record_traffic(RouteAction::Proxy, true, chunk);
        if (!conn->local_paused_for_tunnel && conn->local_session &&
            conn->tunnel_session->pending_write_bytes() >=
                TcpFlowBridge::kHighWatermark) {
            conn->local_paused_for_tunnel = true;
            conn->local_session->pause_read();
        }
    }
}

void ClientApp::tunnel_send_disconnect(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        return;
    }

    Buffer encoded(64);
    if (conn->tunnel_codec.encode_disconnect(conn->session_id, encoded)) {
        conn->tunnel_session->send(std::move(encoded));
    }
}

void ClientApp::tunnel_send_half_close(ProxyConnPtr conn) {
    if (!conn || conn->local_half_close_sent || !conn->connect_result_sent ||
        !conn->tunnel_connected || !conn->tunnel_session ||
        conn->tunnel_session->is_closed()) return;
    Buffer encoded(64);
    if (conn->tunnel_codec.encode_half_close(conn->session_id, encoded)) {
        if (conn->tunnel_session->send(std::move(encoded))) {
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

void ClientApp::bind_proxy_target_callback(ProxyConnPtr conn) {
    if (!conn) return;

    std::weak_ptr<ProxyConn> weak_conn = conn;
    if (conn->http) {
        conn->http->set_target_callback([weak_conn](const TargetAddr& target) {
            if (auto current = weak_conn.lock()) {
                current->target = target;
            }
        });
    } else if (conn->socks5) {
        conn->socks5->set_target_callback([weak_conn](const TargetAddr& target) {
            if (auto current = weak_conn.lock()) {
                current->target = target;
            }
        });
    }
}

void ClientApp::release_proxy_resources(ProxyConnPtr conn) {
    if (!conn || conn->resources_released) return;
    conn->resources_released = true;
    conn->closing = true;
    conn->connected = false;

    stop_tunnel_timer(conn);
    if (conn->http) conn->http->set_target_callback(nullptr);
    if (conn->socks5) conn->socks5->set_target_callback(nullptr);

    if (conn->direct_session && !conn->direct_session->is_closed()) {
        conn->direct_session->set_close_callback(nullptr);
        conn->direct_session->close();
    }
    conn->direct_session.reset();
    conn->bridge.reset();
    close_tunnel_session(conn);
    conn->proto_buf.clear();
    conn->pending_data.clear();

    auto found = connections_.find(conn->session_id);
    if (found != connections_.end() && found->second == conn) connections_.erase(found);
    release_session_id(conn->session_id);
    if (conn->admitted) {
        conn->admitted = false;
        if (active_proxy_connections_ > 0) --active_proxy_connections_;
    }
}

void ClientApp::fail_proxy_connection(ProxyConnPtr conn, int http_status) {
    if (!conn || conn->closing) return;
    conn->closing = true;

    auto local = conn->local_session;
    bool response_queued = false;
    if (local && !local->is_closed() && !conn->connect_result_sent) {
        Buffer response;
        if (conn->socks5) {
            conn->socks5->build_connect_response(false, response);
        } else if (conn->http) {
            conn->http->build_error_response(http_status, response);
        }
        if (!response.empty()) response_queued = local->write(response);
    }

    if (conn->route == RouteAction::Proxy && conn->tunnel_connected)
        tunnel_send_disconnect(conn);
    release_proxy_resources(conn);

    if (!local || local->is_closed()) return;
    if (auto tcp = std::dynamic_pointer_cast<TcpSession>(local)) {
        if (response_queued) tcp->close_after_flush();
        else tcp->close();
    } else {
        local->reset();
    }
}

void ClientApp::on_proxy_close(ProxyConnPtr conn) {
    if (!conn) return;
    TX_DEBUG("Proxy connection closed, session %u", conn->session_id);
    if (!conn->closing && conn->route == RouteAction::Proxy)
        tunnel_send_disconnect(conn);
    release_proxy_resources(conn);
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
