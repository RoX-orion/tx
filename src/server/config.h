#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include "tx/crypto/aead.h"

namespace tx {

struct ServerConfig {
    // Listen
    std::string listen_host = "0.0.0.0";
    uint16_t    listen_port = 443;

    // Authentication
    std::string secret;
    std::vector<uint8_t> psk;
    AeadCipherKind cipher = AeadCipherKind::Aes256Gcm;

    // UDP outbounds are removed after this much inactivity.
    uint64_t    udp_idle_timeout_ms = 300000;

    // Logging
    std::string log_level = "info";

    bool validate() const;
};

bool load_server_config(const std::string& path, ServerConfig& config);

} // namespace tx
