#include "config.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>

namespace {

std::string config_json(const char* domain_strategy_line, const char* udp_json = nullptr) {
    return std::string("{\n") +
        "  \"outbounds\": [{\"tag\":\"direct-out\",\"type\":\"direct\"}],\n" +
        (udp_json ? std::string("  \"udp\": ") + udp_json + ",\n" : "") +
        "  \"routing\": {\n" +
        (domain_strategy_line ? std::string("    \"domainStrategy\": \"") +
                                    domain_strategy_line + "\",\n" : "") +
        "    \"rules\": [{\"outboundTag\":\"direct-out\"}]\n" +
        "  }\n" +
        "}\n";
}

std::string tx_config_json(const char* udp_over_tcp = nullptr,
                           int udp_mux_connections = -99) {
    std::string outbound =
        "{\"tag\":\"tx-out\",\"type\":\"tx\"";
    if (udp_over_tcp) {
        outbound += std::string(",\"udp-over-tcp\":") + udp_over_tcp;
    }
    if (udp_mux_connections != -99) {
        outbound += ",\"udp-mux\":{\"connections\":" +
            std::to_string(udp_mux_connections) + "}";
    }
    outbound +=
        ",\"server\":{\"host\":\"127.0.0.1\",\"port\":443,"
        "\"secret\":\"uuid-v4:123e4567-e89b-42d3-a456-426614174000\"}}";
    return std::string("{\n") +
        "  \"outbounds\": [" + outbound + "],\n" +
        "  \"routing\": {\"rules\": [{\"outboundTag\":\"tx-out\"}]}\n" +
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
    assert(default_config.udp_quic_sniff);
    assert(default_config.dns_mapping_ttl == 1800);

    tx::ClientConfig legacy_dns_fields;
    assert(load_text("legacy_dns_fields", std::string("{\n") +
                     "  \"dns\": {\"upstreams\": [\"1.1.1.1\"], \"outboundTag\": \"tx-out\", "
                     "\"direct_resolver\": \"tunnel\", \"mapping_ttl\": 120},\n" +
                     "  \"outbounds\": [{\"tag\":\"direct-out\",\"type\":\"direct\"}],\n" +
                     "  \"routing\": {\"rules\": [{\"outboundTag\":\"direct-out\"}]}\n" +
                     "}\n", legacy_dns_fields));
    assert(legacy_dns_fields.dns_mapping_ttl == 120);

    tx::ClientConfig quic_sniff_disabled;
    assert(load_text("quic_sniff_disabled",
                     config_json(nullptr, "{\"quic_sniff\":false}"),
                     quic_sniff_disabled));
    assert(!quic_sniff_disabled.udp_quic_sniff);

    tx::ClientConfig udp_mux_default;
    assert(load_text("udp_mux_default", tx_config_json(), udp_mux_default));
    assert(udp_mux_default.outbounds.front().udp_over_tcp);
    assert(udp_mux_default.outbounds.front().udp_mux_connections == 1);

    tx::ClientConfig udp_mux_three;
    assert(load_text("udp_mux_three", tx_config_json("true", 3), udp_mux_three));
    assert(udp_mux_three.outbounds.front().udp_mux_connections == 3);

    tx::ClientConfig udp_mux_dedicated;
    assert(load_text("udp_mux_dedicated", tx_config_json("true", -1), udp_mux_dedicated));
    assert(udp_mux_dedicated.outbounds.front().udp_mux_connections == -1);

    tx::ClientConfig udp_native_unsupported;
    assert(!load_text("udp_native_unsupported", tx_config_json("false"),
                      udp_native_unsupported));
    tx::ClientConfig udp_mux_zero;
    assert(!load_text("udp_mux_zero", tx_config_json("true", 0), udp_mux_zero));
    tx::ClientConfig udp_mux_too_many;
    assert(!load_text("udp_mux_too_many", tx_config_json("true", 65),
                      udp_mux_too_many));

    const std::string strict_prefix =
        "{\"outbounds\":[{\"tag\":\"direct-out\",\"type\":\"direct\"}],"
        "\"routing\":{\"rules\":[{\"outboundTag\":\"direct-out\"}]},";
    tx::ClientConfig invalid_integer;
    assert(!load_text("negative_port", strict_prefix +
        "\"listen\":{\"http\":{\"port\":-1}}}", invalid_integer));
    assert(!load_text("large_port", strict_prefix +
        "\"listen\":{\"http\":{\"port\":70000}}}", invalid_integer));
    assert(!load_text("float_capacity", strict_prefix +
        "\"dns\":{\"cache_capacity\":1.5}}", invalid_integer));
    assert(!load_text("mapping_ttl_too_short", strict_prefix +
        "\"dns\":{\"cache_ttl\":60,\"mapping_ttl\":59}}", invalid_integer));
    tx::ClientConfig equal_dns_ttls;
    assert(load_text("equal_dns_ttls", strict_prefix +
        "\"dns\":{\"cache_ttl\":60,\"mapping_ttl\":60}}", equal_dns_ttls));
    assert(equal_dns_ttls.dns_cache_ttl == equal_dns_ttls.dns_mapping_ttl);
    assert(!load_text("wrong_bool", strict_prefix +
        "\"udp\":{\"quic_sniff\":\"true\"}}", invalid_integer));
    assert(!load_text("empty_route_prefix", strict_prefix +
        "\"tun\":{\"enabled\":true,\"auto_config\":false,"
        "\"routes\":[\"10.0.0.0/\"]}}", invalid_integer));
    assert(!load_text("signed_route_prefix", strict_prefix +
        "\"tun\":{\"enabled\":true,\"auto_config\":false,"
        "\"routes\":[\"10.0.0.0/+8\"]}}", invalid_integer));

    tx::ClientConfig ipv6_only;
    assert(load_text("ipv6_only", strict_prefix +
        "\"tun\":{\"enabled\":true,\"address\":\"198.18.0.1/30\","
        "\"addresses\":[\"fd00:1234::1/126\"],\"auto_config\":false}}",
        ipv6_only));
    assert(ipv6_only.tun_addresses.size() == 1);
    assert(ipv6_only.tun_addresses.front() == "fd00:1234::1/126");
    assert(ipv6_only.tun_address.empty());

    tx::ClientConfig explicit_config;
    assert(load_text("asis", config_json("AsIs"), explicit_config));
    assert(explicit_config.router.domain_strategy == "AsIs");

    tx::ClientConfig if_non_match;
    assert(!load_text("if_non_match", config_json("IPIfNonMatch"), if_non_match));

    tx::ClientConfig on_demand;
    assert(!load_text("on_demand", config_json("IPOnDemand"), on_demand));

    tx::ClientConfig unknown;
    assert(!load_text("unknown", config_json("surprise"), unknown));

    tx::ClientConfig system_without_redirect;
    assert(!load_text("system_without_redirect", std::string("{\n") +
                     "  \"tun\": {\"enabled\": true, \"tcp_stack\": \"system\"},\n" +
                     "  \"outbounds\": [{\"tag\":\"direct-out\",\"type\":\"direct\"}],\n" +
                     "  \"routing\": {\"rules\": [{\"outboundTag\":\"direct-out\"}]}\n" +
                     "}\n", system_without_redirect));

#if defined(TX_PLATFORM_LINUX)
    tx::ClientConfig system_with_redirect;
    assert(load_text("system_with_redirect", std::string("{\n") +
                     "  \"tun\": {\"enabled\": true, \"tcp_stack\": \"system\", "
                     "\"auto_redirect\": true},\n" +
                     "  \"outbounds\": [{\"tag\":\"direct-out\",\"type\":\"direct\"}],\n" +
                     "  \"routing\": {\"rules\": [{\"outboundTag\":\"direct-out\"}]}\n" +
                     "}\n", system_with_redirect));
#endif

    // A failed reload must not leave callers with a partially parsed config.
    const std::string retained_tag = default_config.outbounds.front().tag;
    const std::string retained_rule = default_config.router.rules.front().outbound_tag;
    assert(!load_text("retain_on_error", config_json("surprise"), default_config));
    assert(default_config.outbounds.size() == 1);
    assert(default_config.outbounds.front().tag == retained_tag);
    assert(default_config.router.rules.size() == 1);
    assert(default_config.router.rules.front().outbound_tag == retained_rule);

    std::printf("client config tests passed\n");
    return 0;
}
