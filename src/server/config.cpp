#include "config.h"
#include "tx/common/log.h"
#include "tx/crypto/secret.h"
#include "tx/net/udp_flow_timeout.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <limits>
#include <algorithm>
#include <cctype>

using json = nlohmann::json;

namespace tx {

namespace {

bool config_error(const std::string& path, const char* message) {
    TX_ERROR("Invalid config field %s: %s", path.c_str(), message);
    return false;
}

bool json_integer(const json& value, int64_t& output) {
    if (value.is_number_unsigned()) {
        const uint64_t raw = value.get<uint64_t>();
        if (raw > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) return false;
        output = static_cast<int64_t>(raw);
        return true;
    }
    if (!value.is_number_integer()) return false;
    output = value.get<int64_t>();
    return true;
}

template <typename T>
bool read_integer(const json& object, const char* key, const std::string& path,
                  int64_t minimum, uint64_t maximum, T& output) {
    auto it = object.find(key);
    if (it == object.end()) return true;
    int64_t value = 0;
    if (!json_integer(*it, value)) return config_error(path, "expected JSON integer");
    if (value < minimum || (value >= 0 && static_cast<uint64_t>(value) > maximum))
        return config_error(path, "integer is out of range");
    output = static_cast<T>(value);
    return true;
}

bool read_string(const json& object, const char* key, const std::string& path,
                 std::string& output) {
    auto it = object.find(key);
    if (it == object.end()) return true;
    if (!it->is_string()) return config_error(path, "expected string");
    output = it->get<std::string>();
    return true;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

} // namespace

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
        if (!j.is_object()) return config_error("$", "expected object");
        ServerConfig parsed;

        if (j.contains("listen")) {
            const auto& listen = j["listen"];
            if (!listen.is_object()) return config_error("listen", "expected object");
            if (!read_string(listen, "host", "listen.host", parsed.listen_host) ||
                !read_integer(listen, "port", "listen.port", 1, 65535,
                              parsed.listen_port)) return false;
        }

        if (j.contains("cipher")) {
            TX_ERROR("Server cipher is no longer configured; remove the cipher field");
            return false;
        }

        if (j.contains("udp")) {
            const auto& udp = j["udp"];
            if (!udp.is_object()) return config_error("udp", "expected object");
            uint64_t idle_timeout = kDefaultUdpFlowIdleTimeoutMs / 1000;
            if (!read_integer(udp, "idle_timeout", "udp.idle_timeout", 1, 86400,
                              idle_timeout)) return false;
            parsed.udp_idle_timeout_ms = idle_timeout * 1000;
        }

        if (j.contains("limits")) {
            const auto& limits = j["limits"];
            if (!limits.is_object()) return config_error("limits", "expected object");
            uint64_t handshake = parsed.handshake_timeout_ms / 1000;
            uint64_t connect = parsed.connect_timeout_ms / 1000;
            uint64_t rate = parsed.max_client_rate_bytes_per_sec / (1024 * 1024);
            if (!read_integer(limits, "max_clients", "limits.max_clients", 1, 1000000,
                              parsed.max_clients) ||
                !read_integer(limits, "max_unauthenticated_per_ip",
                    "limits.max_unauthenticated_per_ip", 1, 1000000,
                    parsed.max_unauthenticated_per_ip) ||
                !read_integer(limits, "max_new_clients_per_second",
                    "limits.max_new_clients_per_second", 1, 1000000,
                    parsed.max_new_clients_per_second) ||
                !read_integer(limits, "max_tcp_outbounds_per_client",
                    "limits.max_tcp_outbounds_per_client", 1, 1000000,
                    parsed.max_tcp_outbounds_per_client) ||
                !read_integer(limits, "max_udp_flows_per_client",
                    "limits.max_udp_flows_per_client", 1, 1000000,
                    parsed.max_udp_flows_per_client) ||
                !read_integer(limits, "handshake_timeout", "limits.handshake_timeout",
                              1, 60, handshake) ||
                !read_integer(limits, "connect_timeout", "limits.connect_timeout",
                              1, 120, connect) ||
                !read_integer(limits, "max_client_rate_mbps",
                              "limits.max_client_rate_mbps", 1, 1024, rate)) return false;
            parsed.handshake_timeout_ms = handshake * 1000;
            parsed.connect_timeout_ms = connect * 1000;
            parsed.max_client_rate_bytes_per_sec = rate * 1024 * 1024;
        }

        if (j.contains("secret")) {
            std::string secret;
            if (!read_string(j, "secret", "secret", secret)) return false;
            if (!Secret::parse_psk(secret, parsed.psk)) {
                return false;
            }
        } else if (j.contains("password")) {
            TX_ERROR("password is no longer accepted; use secret with a high-entropy PSK");
            return false;
        }

        if (!read_string(j, "log_level", "log_level", parsed.log_level)) return false;
        parsed.log_level = lower(parsed.log_level);
        if (parsed.log_level != "debug" && parsed.log_level != "info" &&
            parsed.log_level != "warn" && parsed.log_level != "error")
            return config_error("log_level", "unsupported log level");

        if (!parsed.validate()) return false;
        config = std::move(parsed);
        return true;

    } catch (const json::exception& e) {
        TX_ERROR("Failed to parse config: %s", e.what());
        return false;
    }

    return false;
}

} // namespace tx
