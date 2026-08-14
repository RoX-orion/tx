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
#include <limits>
#include "tx/common/network.h"
#include <sys/stat.h>

using json = nlohmann::json;

namespace tx {

static std::string to_lower(std::string s);

namespace {

constexpr int32_t kMaxUdpMuxConnections = 64;

bool config_error(const std::string& path, const char* message) {
    TX_ERROR("Invalid config field %s: %s", path.c_str(), message);
    return false;
}

bool read_string_field(const json& object, const char* key, const std::string& path,
                       std::string& output) {
    auto it = object.find(key);
    if (it == object.end()) return true;
    if (!it->is_string()) return config_error(path, "expected string");
    output = it->get<std::string>();
    return true;
}

bool read_bool_field(const json& object, const char* key, const std::string& path,
                     bool& output) {
    auto it = object.find(key);
    if (it == object.end()) return true;
    if (!it->is_boolean()) return config_error(path, "expected boolean");
    output = it->get<bool>();
    return true;
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
bool read_integer_field(const json& object, const char* key, const std::string& path,
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

bool require_object(const json& value, const std::string& path) {
    return value.is_object() || config_error(path, "expected object");
}

bool require_array(const json& value, const std::string& path) {
    return value.is_array() || config_error(path, "expected array");
}

bool read_string_array(const json& object, const char* key, const std::string& path,
                       std::vector<std::string>& output, bool lowercase) {
    auto it = object.find(key);
    if (it == object.end()) return true;
    if (!require_array(*it, path)) return false;
    std::vector<std::string> values;
    for (size_t index = 0; index < it->size(); ++index) {
        const auto& value = (*it)[index];
        if (!value.is_string())
            return config_error(path + "[" + std::to_string(index) + "]", "expected string");
        std::string text = value.get<std::string>();
        values.push_back(lowercase ? to_lower(std::move(text)) : std::move(text));
    }
    output = std::move(values);
    return true;
}

} // namespace

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
    const std::string prefix_text = cidr.substr(slash + 1);
    if (prefix_text.empty() ||
        prefix_text.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    char* end = nullptr;
    long prefix = std::strtol(prefix_text.c_str(), &end, 10);
    if (end != prefix_text.c_str() + prefix_text.size()) return false;
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
        for (const auto& route : tun_routes) {
            if (!has_valid_ip_cidr(route)) {
                TX_ERROR("Invalid tun.routes CIDR: %s", route.c_str());
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
        if (tun_tcp_stack == "system" && !tun_auto_redirect) {
            TX_ERROR("tun.tcp_stack=system requires tun.auto_redirect=true");
            return false;
        }
        if (tun_tcp_stack == "lwip" && tun_auto_redirect) {
            TX_ERROR("tun.auto_redirect cannot be enabled with tcp_stack=lwip");
            return false;
        }
        const bool managed_routes = tun_auto_route || !tun_routes.empty();
        const uint32_t effective_mark = tun_tcp_stack == "lwip"
            ? tun_bypass_mark : tun_redirect_mark;
        if (managed_routes && effective_mark == 0) {
            TX_ERROR("effective TUN policy mark must be non-zero with managed routes");
            return false;
        }
        if (managed_routes && (tun_route_table == 0 || tun_rule_priority == 0)) {
            TX_ERROR("tun.route_table and tun.rule_priority must be non-zero with managed routes");
            return false;
        }
        if (managed_routes && tun_rule_priority == UINT32_MAX) {
            TX_ERROR("tun.rule_priority + 1 overflows");
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
    if (dns_mapping_ttl == 0 || dns_mapping_ttl > 604800) {
        TX_ERROR("dns.mapping_ttl must be between 1 and 604800 seconds");
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
            if (!outbound.udp_over_tcp) {
                TX_ERROR("TX outbound %s sets udp-over-tcp=false, but native UDP transport is not implemented",
                         outbound.tag.c_str());
                return false;
            }
            if (outbound.udp_mux_connections == 0 ||
                outbound.udp_mux_connections < -1 ||
                outbound.udp_mux_connections > kMaxUdpMuxConnections) {
                TX_ERROR("TX outbound %s udp-mux.connections must be -1 or between 1 and %d",
                         outbound.tag.c_str(), kMaxUdpMuxConnections);
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
        if (!require_object(j, "$")) return false;

        if (j.contains("listen")) {
            const auto& listen = j["listen"];
            if (!require_object(listen, "listen")) return false;
            if (listen.contains("http")) {
                const auto& http = listen["http"];
                if (!require_object(http, "listen.http") ||
                    !read_string_field(http, "host", "listen.http.host", config.http_host) ||
                    !read_integer_field(http, "port", "listen.http.port", 1, 65535,
                                        config.http_port)) return false;
            }
            if (listen.contains("socks5")) {
                const auto& socks5 = listen["socks5"];
                if (!require_object(socks5, "listen.socks5") ||
                    !read_string_field(socks5, "host", "listen.socks5.host",
                                       config.socks5_host) ||
                    !read_integer_field(socks5, "port", "listen.socks5.port", 1, 65535,
                                        config.socks5_port)) return false;
            }
        }

        if (j.contains("outbounds")) {
            const auto& outbounds = j["outbounds"];
            if (!require_array(outbounds, "outbounds")) return false;
            for (size_t index = 0; index < outbounds.size(); ++index) {
                const auto& item = outbounds[index];
                const std::string base = "outbounds[" + std::to_string(index) + "]";
                if (!require_object(item, base)) return false;
                OutboundConfig outbound;
                std::string type = "tx";
                if (!read_string_field(item, "tag", base + ".tag", outbound.tag) ||
                    !read_string_field(item, "type", base + ".type", type)) return false;
                type = to_lower(type);
                if (type == "direct" || type == "freedom") {
                    outbound.type = OutboundType::Direct;
                } else if (type == "block" || type == "blackhole") {
                    outbound.type = OutboundType::Block;
                } else if (type == "tx" || type == "proxy") {
                    outbound.type = OutboundType::Tx;
                } else {
                    return config_error(base + ".type", "unsupported outbound type");
                }

                if (outbound.type != OutboundType::Tx &&
                    (item.contains("udp-over-tcp") || item.contains("udp-mux"))) {
                    TX_ERROR("udp-over-tcp and udp-mux are only supported by TX outbounds");
                    return false;
                }
                if (outbound.type == OutboundType::Tx) {
                    if (!read_bool_field(item, "udp-over-tcp", base + ".udp-over-tcp",
                                         outbound.udp_over_tcp)) return false;
                    if (item.contains("udp-mux")) {
                        const auto& udp_mux = item["udp-mux"];
                        if (!require_object(udp_mux, base + ".udp-mux") ||
                            !read_integer_field(udp_mux, "connections",
                                base + ".udp-mux.connections", -1,
                                kMaxUdpMuxConnections, outbound.udp_mux_connections)) return false;
                        if (outbound.udp_mux_connections == 0)
                            return config_error(base + ".udp-mux.connections",
                                                "must be -1 or between 1 and 64");
                    }
                    const auto& server = item.contains("server") ? item["server"] : item;
                    const std::string server_path = item.contains("server")
                        ? base + ".server" : base;
                    if (!require_object(server, server_path) ||
                        !read_string_field(server, "host", server_path + ".host",
                                           outbound.server_host) ||
                        !read_integer_field(server, "port", server_path + ".port", 1, 65535,
                                            outbound.server_port)) return false;
                    if (server.contains("cipher")) {
                        std::string cipher_name;
                        if (!read_string_field(server, "cipher", server_path + ".cipher",
                                               cipher_name)) return false;
                        if (!parse_aead_cipher(cipher_name, outbound.cipher)) {
                            return config_error(server_path + ".cipher",
                                                "unsupported tunnel cipher");
                        }
                    }
                    if (server.contains("secret")) {
                        std::string secret;
                        if (!read_string_field(server, "secret", server_path + ".secret",
                                               secret)) return false;
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

        if (j.contains("routing")) {
            const auto& routing = j["routing"];
            if (!require_object(routing, "routing") ||
                !read_string_field(routing, "domainStrategy", "routing.domainStrategy",
                                   config.router.domain_strategy)) return false;
            if (routing.contains("geoip_path")) {
                std::string value;
                if (!read_string_field(routing, "geoip_path", "routing.geoip_path", value))
                    return false;
                config.router.geoip_path = resolve_config_path(path, value);
            }
            if (routing.contains("geosite_path")) {
                std::string value;
                if (!read_string_field(routing, "geosite_path", "routing.geosite_path", value))
                    return false;
                config.router.geosite_path = resolve_config_path(path, value);
            }
            if (routing.contains("rules")) {
                const auto& rules = routing["rules"];
                if (!require_array(rules, "routing.rules")) return false;
                for (size_t index = 0; index < rules.size(); ++index) {
                    const auto& item = rules[index];
                    const std::string base = "routing.rules[" + std::to_string(index) + "]";
                    if (!require_object(item, base)) return false;
                    RouteRule rule;
                    if (!read_string_array(item, "domain", base + ".domain",
                                           rule.domains, true) ||
                        !read_string_array(item, "ip", base + ".ip", rule.ips, true) ||
                        !read_string_field(item, "outboundTag", base + ".outboundTag",
                                           rule.outbound_tag)) return false;
                    config.router.rules.push_back(std::move(rule));
                }
            }
        }

        if (j.contains("udp")) {
            const auto& udp = j["udp"];
            if (!require_object(udp, "udp")) return false;
            uint64_t idle_timeout = kDefaultUdpFlowIdleTimeoutMs / 1000;
            if (!read_integer_field(udp, "idle_timeout", "udp.idle_timeout", 1, 86400,
                                    idle_timeout) ||
                !read_integer_field(udp, "max_flows", "udp.max_flows", 1, 1000000,
                                    config.udp_max_flows) ||
                !read_bool_field(udp, "quic_sniff", "udp.quic_sniff",
                                 config.udp_quic_sniff)) return false;
            config.udp_idle_timeout_ms = static_cast<uint64_t>(idle_timeout) * 1000;
        }

        if (j.contains("limits")) {
            const auto& limits = j["limits"];
            if (!require_object(limits, "limits") ||
                !read_integer_field(limits, "max_proxy_connections",
                    "limits.max_proxy_connections", 1, 1000000,
                    config.max_proxy_connections)) return false;
        }

        if (j.contains("tun")) {
            const auto& tun = j["tun"];
            if (!require_object(tun, "tun") ||
                !read_bool_field(tun, "enabled", "tun.enabled", config.tun_enabled) ||
                !read_integer_field(tun, "fd", "tun.fd", -1,
                                    static_cast<uint64_t>(std::numeric_limits<int>::max()),
                                    config.tun_fd) ||
                !read_integer_field(tun, "mtu", "tun.mtu", 1, 65535, config.tun_mtu) ||
                !read_string_field(tun, "name", "tun.name", config.tun_name) ||
                !read_string_field(tun, "address", "tun.address", config.tun_address))
                return false;
            if (tun.contains("addresses")) {
                if (!read_string_array(tun, "addresses", "tun.addresses",
                                       config.tun_addresses, false)) return false;
                config.tun_address.clear();
                for (const auto& address : config.tun_addresses) {
                    if (address.find(':') == std::string::npos) {
                        config.tun_address = address;
                        break;
                    }
                }
            } else if (tun.contains("address")) {
                config.tun_addresses.assign(1, config.tun_address);
            }
            if (!read_bool_field(tun, "auto_config", "tun.auto_config", config.tun_auto_config) ||
                !read_bool_field(tun, "auto_route", "tun.auto_route", config.tun_auto_route) ||
                !read_bool_field(tun, "auto_redirect", "tun.auto_redirect",
                                 config.tun_auto_redirect) ||
                !read_integer_field(tun, "redirect_port", "tun.redirect_port", 1, 65535,
                                    config.tun_redirect_port) ||
                !read_integer_field(tun, "redirect_mark", "tun.redirect_mark", 0,
                                    UINT32_MAX, config.tun_redirect_mark) ||
                !read_integer_field(tun, "bypass_mark", "tun.bypass_mark", 0,
                                    UINT32_MAX, config.tun_bypass_mark) ||
                !read_integer_field(tun, "route_table", "tun.route_table", 0,
                                    UINT32_MAX, config.tun_route_table) ||
                !read_integer_field(tun, "rule_priority", "tun.rule_priority", 0,
                                    UINT32_MAX, config.tun_rule_priority) ||
                !read_string_array(tun, "routes", "tun.routes", config.tun_routes, false))
                return false;
            if (tun.contains("mode")) {
                if (!read_string_field(tun, "mode", "tun.mode", config.tun_mode)) return false;
                config.tun_mode = to_lower(config.tun_mode);
                TX_WARN("tun.mode is deprecated and no longer selects the data plane");
            }
            if (!read_string_field(tun, "tcp_stack", "tun.tcp_stack",
                                   config.tun_tcp_stack) ||
                !read_string_field(tun, "udp_stack", "tun.udp_stack",
                                   config.tun_udp_stack)) return false;
            config.tun_tcp_stack = to_lower(config.tun_tcp_stack);
            config.tun_udp_stack = to_lower(config.tun_udp_stack);
        }

        if (j.contains("dns")) {
            const auto& dns = j["dns"];
            if (!require_object(dns, "dns") ||
                !read_string_field(dns, "mode", "dns.mode", config.dns_mode) ||
                !read_string_field(dns, "fake_ipv4_range", "dns.fake_ipv4_range",
                                   config.dns_fake_ipv4_range) ||
                !read_string_field(dns, "fake_ipv6_range", "dns.fake_ipv6_range",
                                   config.dns_fake_ipv6_range) ||
                !read_integer_field(dns, "cache_ttl", "dns.cache_ttl", 1, 86400,
                                    config.dns_cache_ttl) ||
                !read_integer_field(dns, "mapping_ttl", "dns.mapping_ttl", 1, 604800,
                                    config.dns_mapping_ttl) ||
                !read_integer_field(dns, "cache_capacity", "dns.cache_capacity", 1,
                                    1000000, config.dns_cache_capacity)) return false;
            config.dns_mode = to_lower(config.dns_mode);
        }

        if (j.contains("geo") || j.contains("server")) {
            TX_ERROR("Old server/geo routing config is no longer supported; use outbounds and routing.rules");
            return false;
        }

        if (!read_string_field(j, "log_level", "log_level", config.log_level)) return false;
        config.log_level = to_lower(config.log_level);
        if (config.log_level != "debug" && config.log_level != "info" &&
            config.log_level != "warn" && config.log_level != "error")
            return config_error("log_level", "unsupported log level");

    } catch (const json::exception& e) {
        TX_ERROR("Failed to parse config: %s", e.what());
        return false;
    }

    if (!config.validate()) return false;
    output_config = std::move(config);
    return true;
}

} // namespace tx
