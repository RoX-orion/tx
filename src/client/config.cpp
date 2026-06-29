#include "config.h"
#include "tx/common/log.h"
#include "tx/crypto/secret.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>
#include <sys/stat.h>

using json = nlohmann::json;

namespace tx {

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool path_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

static std::string dirname_of(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) {
        return ".";
    }
    if (pos == 0) {
        return path.substr(0, 1);
    }
    return path.substr(0, pos);
}

static std::string join_path(const std::string& base, const std::string& leaf) {
    if (base.empty() || base == ".") {
        return leaf;
    }
    char last = base.back();
    if (last == '/' || last == '\\') {
        return base + leaf;
    }
    return base + "/" + leaf;
}

static std::string parent_dir(const std::string& path) {
    return dirname_of(path);
}

static std::string resolve_config_path(const std::string& config_path,
                                       const std::string& value_path) {
    if (value_path.empty()) {
        return value_path;
    }

    if (value_path[0] == '/' || value_path[0] == '\\' ||
        (value_path.size() > 1 && value_path[1] == ':')) {
        return value_path;
    }

    if (path_exists(value_path)) {
        return value_path;
    }

    std::string dir = dirname_of(config_path);
    const std::string candidate0 = join_path(dir, value_path);
    if (path_exists(candidate0)) {
        return candidate0;
    }

    std::string probe_dir = dir;
    for (int i = 0; i < 4; ++i) {
        probe_dir = parent_dir(probe_dir);
        const std::string candidate = join_path(probe_dir, value_path);
        if (path_exists(candidate)) {
            return candidate;
        }
    }

    return candidate0;
}

bool ClientConfig::validate() const {
    if (server_host.empty()) {
        TX_ERROR("Server host not configured");
        return false;
    }
    if (server_port == 0) {
        TX_ERROR("Server port not configured");
        return false;
    }
    if (psk.size() != Secret::kPskLen) {
        TX_ERROR("High-entropy secret not configured; use server.secret with base64:, hex:, or uuid-v4:");
        return false;
    }
    return true;
}

bool load_client_config(const std::string& path, ClientConfig& config) {
    std::ifstream file(path);
    if (!file.is_open()) {
        TX_ERROR("Failed to open config file: %s", path.c_str());
        return false;
    }

    try {
        json j;
        file >> j;

        // Listen config
        if (j.contains("listen")) {
            auto& listen = j["listen"];
            if (listen.contains("http")) {
                auto& http = listen["http"];
                if (http.contains("host")) config.http_host = http["host"].get<std::string>();
                if (http.contains("port")) config.http_port = http["port"].get<uint16_t>();
            }
            if (listen.contains("socks5")) {
                auto& socks5 = listen["socks5"];
                if (socks5.contains("host")) config.socks5_host = socks5["host"].get<std::string>();
                if (socks5.contains("port")) config.socks5_port = socks5["port"].get<uint16_t>();
            }
        }

        // Server config
        if (j.contains("server")) {
            auto& server = j["server"];
            if (server.contains("host")) config.server_host = server["host"].get<std::string>();
            if (server.contains("port")) config.server_port = server["port"].get<uint16_t>();
            if (server.contains("cipher")) {
                std::string cipher_name = server["cipher"].get<std::string>();
                if (!parse_aead_cipher(cipher_name, config.cipher)) {
                    TX_ERROR("Unsupported tunnel cipher: %s", cipher_name.c_str());
                    return false;
                }
            }
            if (server.contains("secret")) {
                config.secret = server["secret"].get<std::string>();
                if (!Secret::parse_psk(config.secret, config.psk)) {
                    return false;
                }
            } else if (server.contains("password")) {
                TX_ERROR("server.password is no longer accepted; use server.secret with a high-entropy PSK");
                return false;
            }
        }

        // Geo config
        if (j.contains("geo")) {
            auto& geo = j["geo"];
            if (geo.contains("geoip_path")) {
                config.router.geoip_path =
                    resolve_config_path(path, geo["geoip_path"].get<std::string>());
            }
            if (geo.contains("geosite_path")) {
                config.router.geosite_path =
                    resolve_config_path(path, geo["geosite_path"].get<std::string>());
            }
            if (geo.contains("direct_geoip")) {
                for (auto& tag : geo["direct_geoip"]) {
                    config.router.direct_geoip_tags.push_back(to_lower(tag.get<std::string>()));
                }
            }
            if (geo.contains("direct_geosite")) {
                for (auto& tag : geo["direct_geosite"]) {
                    config.router.direct_geosite_tags.push_back(to_lower(tag.get<std::string>()));
                }
            }
        }

        // Log level
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
