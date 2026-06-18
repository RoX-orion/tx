#include "config.h"
#include "tx/common/log.h"

#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

namespace tx {

bool ServerConfig::validate() const {
    if (password.empty()) {
        TX_ERROR("Password not configured");
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

        if (j.contains("password")) {
            config.password = j["password"].get<std::string>();
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
