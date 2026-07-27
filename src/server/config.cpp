#include "config.h"
#include "tx/common/log.h"
#include "tx/crypto/secret.h"
#include "tx/net/udp_flow_timeout.h"

#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

namespace tx {

bool ServerConfig::validate() const {
    if (udp_idle_timeout_ms < 1000 || udp_idle_timeout_ms > 24 * 60 * 60 * 1000ULL) {
        TX_ERROR("udp.idle_timeout must be between 1 and 86400 seconds");
        return false;
    }
    if (max_clients == 0 || max_unauthenticated_per_ip == 0 ||
        max_new_clients_per_second == 0 || max_tcp_outbounds_per_client == 0 ||
        max_udp_flows_per_client == 0 || max_clients > 1000000 ||
        max_unauthenticated_per_ip > 1000000 || max_new_clients_per_second > 1000000 ||
        max_tcp_outbounds_per_client > 1000000 || max_udp_flows_per_client > 1000000) {
        TX_ERROR("server limits must be between 1 and 1000000");
        return false;
    }
    if (handshake_timeout_ms < 1000 || handshake_timeout_ms > 60000 ||
        connect_timeout_ms < 1000 || connect_timeout_ms > 120000) {
        TX_ERROR("server handshake/connect timeouts are out of range");
        return false;
    }
    if (max_client_rate_bytes_per_sec == 0 ||
        max_client_rate_bytes_per_sec > 1024ULL * 1024 * 1024) {
        TX_ERROR("server max client rate must be between 1 and 1073741824 bytes/s");
        return false;
    }

    if (psk.size() != Secret::kPskLen) {
        TX_ERROR("High-entropy secret not configured; use secret with base64:, hex:, or uuid-v4:");
        return false;
    }
    if (listen_port == 0) {
        TX_ERROR("Listen port not configured");
        return false;
    }
    return true;
}

bool load_server_config(const std::string& path, ServerConfig& config) {
    std::ifstream file(path);
    if (!file.is_open()) {
        TX_ERROR("Failed to open config file: %s", path.c_str());
        return false;
    }

    try {
        json j;
        file >> j;

        if (j.contains("listen")) {
            auto& listen = j["listen"];
            if (listen.contains("host")) config.listen_host = listen["host"].get<std::string>();
            if (listen.contains("port")) config.listen_port = listen["port"].get<uint16_t>();
        }

        if (j.contains("cipher")) {
            TX_ERROR("Server cipher is no longer configured; remove the cipher field");
            return false;
        }

        if (j.contains("udp")) {
            const auto& udp = j["udp"];
            int64_t idle_timeout = udp.value("idle_timeout",
                                             static_cast<int64_t>(
                                                 kDefaultUdpFlowIdleTimeoutMs / 1000));
            if (idle_timeout < 1 || idle_timeout > 86400) {
                TX_ERROR("udp.idle_timeout must be between 1 and 86400 seconds");
                return false;
            }
            config.udp_idle_timeout_ms = static_cast<uint64_t>(idle_timeout) * 1000;
        }

        if (j.contains("limits")) {
            const auto& limits = j["limits"];
            config.max_clients = limits.value("max_clients", config.max_clients);
            config.max_unauthenticated_per_ip = limits.value(
                "max_unauthenticated_per_ip", config.max_unauthenticated_per_ip);
            config.max_new_clients_per_second = limits.value(
                "max_new_clients_per_second", config.max_new_clients_per_second);
            config.max_tcp_outbounds_per_client = limits.value(
                "max_tcp_outbounds_per_client", config.max_tcp_outbounds_per_client);
            config.max_udp_flows_per_client = limits.value(
                "max_udp_flows_per_client", config.max_udp_flows_per_client);
            int64_t handshake_timeout = limits.value(
                "handshake_timeout", static_cast<int64_t>(config.handshake_timeout_ms / 1000));
            int64_t connect_timeout = limits.value(
                "connect_timeout", static_cast<int64_t>(config.connect_timeout_ms / 1000));
            int64_t rate_mbps = limits.value("max_client_rate_mbps",
                static_cast<int64_t>(config.max_client_rate_bytes_per_sec / (1024 * 1024)));
            if (handshake_timeout < 1 || connect_timeout < 1 || rate_mbps < 1 ||
                handshake_timeout > 60 || connect_timeout > 120 || rate_mbps > 1024) {
                TX_ERROR("Invalid server limits");
                return false;
            }
            config.handshake_timeout_ms = static_cast<uint64_t>(handshake_timeout) * 1000;
            config.connect_timeout_ms = static_cast<uint64_t>(connect_timeout) * 1000;
            config.max_client_rate_bytes_per_sec = static_cast<uint64_t>(rate_mbps) * 1024 * 1024;
        }

        if (j.contains("secret")) {
            const std::string secret = j["secret"].get<std::string>();
            if (!Secret::parse_psk(secret, config.psk)) {
                return false;
            }
        } else if (j.contains("password")) {
            TX_ERROR("password is no longer accepted; use secret with a high-entropy PSK");
            return false;
        }

        if (j.contains("log_level")) {
            config.log_level = j["log_level"].get<std::string>();
        }

    } catch (const json::exception& e) {
        TX_ERROR("Failed to parse config: %s", e.what());
        return false;
    }

    return config.validate();
}

} // namespace tx
