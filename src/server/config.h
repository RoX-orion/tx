#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace tx {

struct ServerConfig {
    // Listen
    std::string listen_host = "0.0.0.0";
    uint16_t    listen_port = 443;

    // Authentication
    std::vector<uint8_t> psk;

    // UDP outbounds are removed after this much inactivity.
    uint64_t    udp_idle_timeout_ms = 300000;

    // Per-process/per-tunnel resource limits. They are deliberately finite by
    // default so an authenticated peer cannot grow state without bound.
    uint32_t    max_clients = 1024;
    uint32_t    max_unauthenticated_per_ip = 32;
    uint32_t    max_new_clients_per_second = 128;
    uint32_t    max_tcp_outbounds_per_client = 1024;
    uint32_t    max_udp_flows_per_client = 4096;
    uint64_t    handshake_timeout_ms = 8000;
    uint64_t    connect_timeout_ms = 10000;
    uint64_t    max_client_rate_bytes_per_sec = 64ULL * 1024 * 1024;

    // Logging
    std::string log_level = "info";

    bool validate() const;
};

bool load_server_config(const std::string& path, ServerConfig& config);

} // namespace tx
