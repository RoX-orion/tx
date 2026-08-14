#include "config.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>

namespace {

bool load_text(const char* suffix, const std::string& contents,
               tx::ServerConfig& config) {
    const std::string path = std::string("/tmp/tx_server_config_") + suffix + ".json";
    {
        std::ofstream file(path);
        assert(file.is_open());
        file << contents;
    }
    const bool loaded = tx::load_server_config(path, config);
    std::remove(path.c_str());
    return loaded;
}

std::string config_json(const char* extra) {
    return std::string("{\n") +
        "  \"listen\": {\"host\":\"127.0.0.1\",\"port\":443},\n" +
        "  \"secret\":\"hex:000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f\"" +
        (extra ? std::string(",\n  ") + extra : "") +
        "\n}\n";
}

} // namespace

int main() {
    tx::ServerConfig config;
    assert(load_text("without_cipher", config_json(nullptr), config));
    assert(config.psk.size() == 32);

    tx::ServerConfig obsolete_cipher;
    assert(!load_text("obsolete_cipher",
                      config_json("\"cipher\":\"aes-256-gcm\""),
                      obsolete_cipher));

    tx::ServerConfig retained = config;
    assert(!load_text("negative_port",
                      config_json("\"listen\":{\"port\":-1}"), retained));
    assert(retained.listen_port == config.listen_port);
    assert(retained.psk == config.psk);
    assert(!load_text("large_port",
                      "{\"listen\":{\"port\":70000},\"secret\":\"hex:"
                      "000102030405060708090a0b0c0d0e0f"
                      "101112131415161718191a1b1c1d1e1f\"}", retained));
    assert(!load_text("float_limit",
                      config_json("\"limits\":{\"max_clients\":1.5}"), retained));
    assert(!load_text("wrong_log_type",
                      config_json("\"log_level\":true"), retained));

    std::printf("server config tests passed\n");
    return 0;
}
