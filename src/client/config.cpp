#include "config.h"
#include "tx/common/log.h"
#include "tx/crypto/secret.h"
#include "tx/net/udp_flow_timeout.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <utility>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include "tx/common/network.h"
#include <sys/stat.h>

using json = nlohmann::json;

namespace tx {

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
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

static bool has_valid_ip_cidr(const std::string& cidr) {
    const size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    char* end = nullptr;
    long prefix = std::strtol(cidr.substr(slash + 1).c_str(), &end, 10);
    if (!end || *end) return false;
    uint8_t bytes[16];
    const std::string host = cidr.substr(0, slash);
    if (inet_pton(AF_INET, host.c_str(), bytes) == 1) return prefix >= 0 && prefix <= 32;
    if (inet_pton(AF_INET6, host.c_str(), bytes) == 1) return prefix >= 0 && prefix <= 128;
    return false;
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
    if (udp_idle_timeout_ms < 1000 || udp_idle_timeout_ms > 24 * 60 * 60 * 1000ULL) {
        TX_ERROR("udp.idle_timeout must be between 1 and 86400 seconds");
        return false;
    }
    if (udp_max_flows == 0 || udp_max_flows > 1000000) {
        TX_ERROR("udp.max_flows must be between 1 and 1000000");
        return false;
    }
    if (max_proxy_connections == 0 || max_proxy_connections > 1000000) {
        TX_ERROR("limits.max_proxy_connections must be between 1 and 1000000");
        return false;
    }

    if (outbounds.empty()) {
        TX_ERROR("No outbounds configured");
        return false;
    }

    if (router.rules.empty()) {
        TX_ERROR("No routing rules configured");
        return false;
    }

    if (router.domain_strategy != "AsIs") {
        TX_ERROR("routing.domainStrategy must be AsIs (unsupported value: %s)",
                 router.domain_strategy.c_str());
        return false;
    }

    if (tun_enabled) {
        if (tun_mtu <= 0) {
            TX_ERROR("tun.mtu must be between 1 and 65535");
            return false;
        }
        if (tun_mtu > 65535) {
            TX_ERROR("tun.mtu must be between 1 and 65535");
            return false;
        }
        if (tun_addresses.empty()) {
            TX_ERROR("tun.addresses must contain at least one CIDR");
            return false;
        }
        for (const auto& address : tun_addresses) {
            if (!has_valid_ip_cidr(address)) {
                TX_ERROR("Invalid TUN address CIDR: %s", address.c_str());
                return false;
            }
        }
        if (tun_tcp_stack != "lwip" && tun_tcp_stack != "system") {
            TX_ERROR("tun.tcp_stack must be lwip or system");
            return false;
        }
        if (tun_udp_stack != "lwip") {
            TX_ERROR("tun.udp_stack must be lwip");
            return false;
        }
        if (tun_tcp_stack == "lwip" && tun_auto_redirect) {
            TX_ERROR("tun.auto_redirect cannot be enabled with tcp_stack=lwip");
            return false;
        }
        if (tun_tcp_stack == "lwip" && tun_auto_route && tun_bypass_mark == 0) {
            TX_ERROR("tun.bypass_mark must be non-zero with lwip auto_route");
            return false;
        }
        if (tun_auto_route && (tun_route_table == 0 || tun_rule_priority == 0)) {
            TX_ERROR("tun.route_table and tun.rule_priority must be non-zero with auto_route");
            return false;
        }
#if !defined(TX_PLATFORM_LINUX)
        if (tun_tcp_stack == "system") {
            TX_ERROR("tun.tcp_stack=system is only supported on Linux");
            return false;
        }
#endif
        if (tun_auto_redirect) {
            if (tun_redirect_port == 0) {
                TX_ERROR("tun.redirect_port must be non-zero when auto_redirect is enabled");
                return false;
            }
            if (tun_redirect_mark == 0) {
                TX_ERROR("tun.redirect_mark must be non-zero when auto_redirect is enabled");
                return false;
            }
        }
    }
    if (dns_mode != "fake-ip") {
        TX_ERROR("dns.mode must be fake-ip");
        return false;
    }
    if (dns_cache_ttl == 0 || dns_cache_ttl > 86400) {
        TX_ERROR("dns.cache_ttl must be between 1 and 86400 seconds");
        return false;
    }
    if (dns_cache_capacity == 0 || dns_cache_capacity > 1000000) {
        TX_ERROR("dns.cache_capacity must be between 1 and 1000000");
        return false;
    }

    for (const auto& outbound : outbounds) {
        if (outbound.tag.empty()) {
            TX_ERROR("Outbound tag is empty");
            return false;
        }
        if (outbound.type == OutboundType::Tx) {
            if (outbound.server_host.empty()) {
                TX_ERROR("TX outbound %s has no server host", outbound.tag.c_str());
                return false;
            }
            if (outbound.server_port == 0) {
                TX_ERROR("TX outbound %s has invalid server port", outbound.tag.c_str());
                return false;
            }
            if (outbound.psk.size() != Secret::kPskLen) {
                TX_ERROR("TX outbound %s has no valid high-entropy secret", outbound.tag.c_str());
                return false;
            }
        }
    }

    for (const auto& rule : router.rules) {
        if (rule.outbound_tag.empty()) {
            TX_ERROR("Routing rule has empty outboundTag");
            return false;
        }
        if (outbound_index.find(rule.outbound_tag) == outbound_index.end()) {
            TX_ERROR("Routing rule references unknown outboundTag: %s",
                     rule.outbound_tag.c_str());
            return false;
        }
    }

    return true;
}

bool load_client_config(const std::string& path, ClientConfig& output_config) {
    ClientConfig config;
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

        // Outbound config
        if (j.contains("outbounds")) {
            for (auto& item : j["outbounds"]) {
                OutboundConfig outbound;
                if (item.contains("tag")) outbound.tag = item["tag"].get<std::string>();
                std::string type = item.value("type", "tx");
                type = to_lower(type);
                if (type == "direct" || type == "freedom") {
                    outbound.type = OutboundType::Direct;
                } else if (type == "block" || type == "blackhole") {
                    outbound.type = OutboundType::Block;
                } else if (type == "tx" || type == "proxy") {
                    outbound.type = OutboundType::Tx;
                } else {
                    TX_ERROR("Unsupported outbound type: %s", type.c_str());
                    return false;
                }

                if (outbound.type == OutboundType::Tx) {
                    auto& server = item.contains("server") ? item["server"] : item;
                    if (server.contains("host")) outbound.server_host = server["host"].get<std::string>();
                    if (server.contains("port")) outbound.server_port = server["port"].get<uint16_t>();
                    if (server.contains("cipher")) {
                        std::string cipher_name = server["cipher"].get<std::string>();
                        if (!parse_aead_cipher(cipher_name, outbound.cipher)) {
                            TX_ERROR("Unsupported tunnel cipher: %s", cipher_name.c_str());
                            return false;
                        }
                    }
                    if (server.contains("secret")) {
                        const std::string secret = server["secret"].get<std::string>();
                        if (!Secret::parse_psk(secret, outbound.psk)) {
                            return false;
                        }
                    } else if (server.contains("password")) {
                        TX_ERROR("server.password is no longer accepted; use server.secret with a high-entropy PSK");
                        return false;
                    }
                }

                if (config.outbound_index.find(outbound.tag) != config.outbound_index.end()) {
                    TX_ERROR("Duplicate outbound tag: %s", outbound.tag.c_str());
                    return false;
                }
                config.outbound_index[outbound.tag] = config.outbounds.size();
                config.outbounds.push_back(std::move(outbound));
            }
        }

        // Routing config
        if (j.contains("routing")) {
            auto& routing = j["routing"];
            config.router.domain_strategy =
                routing.value("domainStrategy", config.router.domain_strategy);
            if (routing.contains("geoip_path")) {
                config.router.geoip_path =
                    resolve_config_path(path, routing["geoip_path"].get<std::string>());
            }
            if (routing.contains("geosite_path")) {
                config.router.geosite_path =
                    resolve_config_path(path, routing["geosite_path"].get<std::string>());
            }
            if (routing.contains("rules")) {
                for (auto& item : routing["rules"]) {
                    RouteRule rule;
                    if (item.contains("domain")) {
                        for (auto& domain : item["domain"]) {
                            rule.domains.push_back(to_lower(domain.get<std::string>()));
                        }
                    }
                    if (item.contains("ip")) {
                        for (auto& ip : item["ip"]) {
                            rule.ips.push_back(to_lower(ip.get<std::string>()));
                        }
                    }
                    if (item.contains("outboundTag")) {
                        rule.outbound_tag = item["outboundTag"].get<std::string>();
                    }
                    config.router.rules.push_back(std::move(rule));
                }
            }
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
            config.udp_max_flows = udp.value("max_flows", config.udp_max_flows);
            config.udp_quic_sniff = udp.value("quic_sniff", config.udp_quic_sniff);
        }

        if (j.contains("limits")) {
            const auto& limits = j["limits"];
            config.max_proxy_connections = limits.value(
                "max_proxy_connections", config.max_proxy_connections);
        }

        if (j.contains("tun")) {
            auto& tun = j["tun"];
            config.tun_enabled = tun.value("enabled", config.tun_enabled);
            config.tun_fd = tun.value("fd", config.tun_fd);
            config.tun_mtu = tun.value("mtu", config.tun_mtu);
            config.tun_name = tun.value("name", config.tun_name);
            config.tun_address = tun.value("address", config.tun_address);
            if (tun.contains("addresses")) {
                config.tun_addresses.clear();
                for (const auto& address : tun["addresses"])
                    config.tun_addresses.push_back(address.get<std::string>());
                for (const auto& address : config.tun_addresses) {
                    if (address.find(':') == std::string::npos) {
                        config.tun_address = address;
                        break;
                    }
                }
            } else if (tun.contains("address")) {
                if (config.tun_addresses.empty()) {
                    config.tun_addresses.push_back(config.tun_address);
                } else {
                    config.tun_addresses[0] = config.tun_address;
                }
            }
            config.tun_auto_config = tun.value("auto_config", config.tun_auto_config);
            config.tun_auto_route = tun.value("auto_route", config.tun_auto_route);
            config.tun_auto_redirect = tun.value("auto_redirect", config.tun_auto_redirect);
            config.tun_redirect_port = tun.value("redirect_port", config.tun_redirect_port);
            config.tun_redirect_mark = tun.value("redirect_mark", config.tun_redirect_mark);
            config.tun_bypass_mark = tun.value("bypass_mark", config.tun_bypass_mark);
            config.tun_route_table = tun.value("route_table", config.tun_route_table);
            config.tun_rule_priority = tun.value("rule_priority", config.tun_rule_priority);
            if (tun.contains("routes")) {
                config.tun_routes.clear();
                for (auto& route : tun["routes"]) {
                    config.tun_routes.push_back(route.get<std::string>());
                }
            }
            if (tun.contains("mode")) {
                config.tun_mode = to_lower(tun.value("mode", config.tun_mode));
                TX_WARN("tun.mode is deprecated and no longer selects the data plane");
            }
            config.tun_tcp_stack = to_lower(tun.value("tcp_stack", config.tun_tcp_stack));
            config.tun_udp_stack = to_lower(tun.value("udp_stack", config.tun_udp_stack));
        }

        if (j.contains("dns")) {
            const auto& dns = j["dns"];
            config.dns_mode = to_lower(dns.value("mode", config.dns_mode));
            config.dns_fake_ipv4_range = dns.value("fake_ipv4_range", config.dns_fake_ipv4_range);
            config.dns_fake_ipv6_range = dns.value("fake_ipv6_range", config.dns_fake_ipv6_range);
            config.dns_cache_ttl = dns.value("cache_ttl", config.dns_cache_ttl);
            config.dns_cache_capacity = dns.value("cache_capacity", config.dns_cache_capacity);
            config.dns_outbound_tag = dns.value("outboundTag", config.dns_outbound_tag);
            if (dns.contains("upstreams")) {
                config.dns_upstreams.clear();
                for (const auto& upstream : dns["upstreams"])
                    config.dns_upstreams.push_back(upstream.get<std::string>());
            }
        }

        if (j.contains("geo") || j.contains("server")) {
            TX_ERROR("Old server/geo routing config is no longer supported; use outbounds and routing.rules");
            return false;
        }

        // Log level
        if (j.contains("log_level")) {
            config.log_level = j["log_level"].get<std::string>();
        }

    } catch (const json::exception& e) {
        TX_ERROR("Failed to parse config: %s", e.what());
        return false;
    }

    if (!config.validate()) return false;
    output_config = std::move(config);
    return true;
}

} // namespace tx
