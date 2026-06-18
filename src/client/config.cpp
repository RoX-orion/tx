#include "config.h"
#include "tx/common/log.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>

using json = nlohmann::json;

namespace tx {

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
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
    if (password.empty()) {
        TX_ERROR("Password not configured");
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
            if (server.contains("password")) config.password = server["password"].get<std::string>();
        }

        // Geo config
        if (j.contains("geo")) {
            auto& geo = j["geo"];
            if (geo.contains("geoip_path")) config.router.geoip_path = geo["geoip_path"].get<std::string>();
            if (geo.contains("geosite_path")) config.router.geosite_path = geo["geosite_path"].get<std::string>();
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
