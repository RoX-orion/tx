#pragma once

#include <string>
#include "tx/router/router.h"

namespace tx {

struct ClientConfig {
    // HTTP proxy listen
    std::string http_host = "127.0.0.1";
    uint16_t    http_port = 8080;

    // SOCKS5 proxy listen
    std::string socks5_host = "127.0.0.1";
    uint16_t    socks5_port = 1080;

    // Server connection
    std::string server_host;
    uint16_t    server_port = 443;
    std::string password;

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
