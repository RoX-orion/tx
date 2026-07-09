#pragma once

#include <string>
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
    std::string tun_address = "10.10.0.1";
    int         tun_prefix = 24;
    bool        tun_auto_config = true;
    std::vector<std::string> tun_routes;
    std::string tun_mode = "mixed";
    std::string tun_tcp_stack = "system";
    std::string tun_udp_stack = "gvisor";

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
