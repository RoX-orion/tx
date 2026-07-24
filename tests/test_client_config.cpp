#include "config.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>

namespace {

std::string config_json(const char* domain_strategy_line) {
    return std::string("{\n") +
        "  \"outbounds\": [{\"tag\":\"direct-out\",\"type\":\"direct\"}],\n" +
        "  \"routing\": {\n" +
        (domain_strategy_line ? std::string("    \"domainStrategy\": \"") +
                                    domain_strategy_line + "\",\n" : "") +
        "    \"rules\": [{\"outboundTag\":\"direct-out\"}]\n" +
        "  }\n" +
        "}\n";
}

bool load_text(const char* suffix, const std::string& contents,
               tx::ClientConfig& config) {
    const std::string path = std::string("/tmp/tx_client_config_") + suffix + ".json";
    {
        std::ofstream file(path);
        assert(file.is_open());
        file << contents;
    }
    const bool loaded = tx::load_client_config(path, config);
    std::remove(path.c_str());
    return loaded;
}

} // namespace

int main() {
    tx::ClientConfig default_config;
    assert(load_text("default", config_json(nullptr), default_config));
    assert(default_config.router.domain_strategy == "AsIs");

    tx::ClientConfig explicit_config;
    assert(load_text("asis", config_json("AsIs"), explicit_config));
    assert(explicit_config.router.domain_strategy == "AsIs");

    tx::ClientConfig if_non_match;
    assert(!load_text("if_non_match", config_json("IPIfNonMatch"), if_non_match));

    tx::ClientConfig on_demand;
    assert(!load_text("on_demand", config_json("IPOnDemand"), on_demand));

    tx::ClientConfig unknown;
    assert(!load_text("unknown", config_json("surprise"), unknown));

    // A failed reload must not leave callers with a partially parsed config.
    const std::string retained_tag = default_config.outbounds.front().tag;
    const std::string retained_rule = default_config.router.rules.front().outbound_tag;
    assert(!load_text("retain_on_error", config_json("surprise"), default_config));
    assert(default_config.outbounds.size() == 1);
    assert(default_config.outbounds.front().tag == retained_tag);
    assert(default_config.router.rules.size() == 1);
    assert(default_config.router.rules.front().outbound_tag == retained_rule);

    std::printf("client config domainStrategy tests passed\n");
    return 0;
}
