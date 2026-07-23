#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include "tx/crypto/aead.h"
#include "tx/router/router.h"

namespace tx {

enum class OutboundType {
    Direct,
    Tx,
    Block,
};

struct OutboundConfig {
    std::string tag;
    OutboundType type = OutboundType::Tx;
    std::string server_host;
    uint16_t    server_port = 443;
    std::string secret;
    std::vector<uint8_t> psk;
    AeadCipherKind cipher = AeadCipherKind::Aes256Gcm;
};

struct ClientConfig {
    // HTTP proxy listen
    std::string http_host = "127.0.0.1";
    uint16_t    http_port = 8080;

    // SOCKS5 proxy listen
    std::string socks5_host = "127.0.0.1";
    uint16_t    socks5_port = 1080;

    // Native TUN input. Android should pass the fd through the C API.
    bool        tun_enabled = false;
    int         tun_fd = -1;
    int         tun_mtu = 1500;
    std::string tun_name = "tx0";
    // Interface address in IPv4 CIDR notation.
    std::string tun_address = "198.18.0.1/30";
    std::vector<std::string> tun_addresses = {"198.18.0.1/30", "fd00:198:18::1/126"};
    bool        tun_auto_config = true;
    bool        tun_auto_route = false;
    bool        tun_auto_redirect = false;
    uint16_t    tun_redirect_port = 12345;
    uint32_t    tun_redirect_mark = 0x2024;
    uint32_t    tun_bypass_mark = 0x2024;
    uint32_t    tun_route_table = 20220;
    uint32_t    tun_rule_priority = 10000;
    std::vector<std::string> tun_routes;
    std::string tun_mode = "mixed";
    std::string tun_tcp_stack = "lwip";
    std::string tun_udp_stack = "lwip";

    std::string dns_mode = "fake-ip";
    std::string dns_fake_ipv4_range = "198.18.0.0/16";
    std::string dns_fake_ipv6_range = "fd00:198:18::/96";
    std::vector<std::string> dns_upstreams;
    uint32_t dns_cache_ttl = 60;

    // UDP flows are removed after this much inactivity.
    uint64_t    udp_idle_timeout_ms = 300000;

    // Outbound connections
    std::vector<OutboundConfig> outbounds;
    std::unordered_map<std::string, size_t> outbound_index;

    // Geo routing
    RouterConfig router;

    // Logging
    std::string log_level = "info";

    // Validate configuration
    bool validate() const;
};

// Load config from JSON file
bool load_client_config(const std::string& path, ClientConfig& config);

} // namespace tx
