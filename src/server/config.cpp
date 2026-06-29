#include "config.h"
#include "tx/common/log.h"
#include "tx/crypto/secret.h"

#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

namespace tx {

bool ServerConfig::validate() const {
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
            std::string cipher_name = j["cipher"].get<std::string>();
            if (!parse_aead_cipher(cipher_name, config.cipher)) {
                TX_ERROR("Unsupported tunnel cipher: %s", cipher_name.c_str());
                return false;
            }
        }

        if (j.contains("secret")) {
            config.secret = j["secret"].get<std::string>();
            if (!Secret::parse_psk(config.secret, config.psk)) {
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
