#include "tx/router/router.h"
#include "tx/common/log.h"
#include <algorithm>
#include <cctype>

namespace tx {

namespace {

std::string to_lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool has_prefix(const std::string& s, const char* prefix) {
    const std::string p(prefix);
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool domain_matches_literal(const std::string& host, const std::string& pattern) {
    if (host == pattern) return true;
    if (host.size() <= pattern.size()) return false;
    const size_t suffix_pos = host.size() - pattern.size();
    return host[suffix_pos - 1] == '.' && host.compare(suffix_pos, pattern.size(), pattern) == 0;
}

bool is_private_address(const IpAddr& ip) {
    if (ip.family == IpAddr::IPv4 || ip.is_ipv4_mapped_ipv6()) {
        const uint8_t* bytes = ip.family == IpAddr::IPv4 ? ip.data.v4 : ip.data.v6 + 12;
        return bytes[0] == 0 || bytes[0] == 10 || bytes[0] == 127 ||
               (bytes[0] == 100 && (bytes[1] & 0xc0u) == 0x40u) ||
               (bytes[0] == 169 && bytes[1] == 254) ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19)) ||
               bytes[0] >= 224;
    }
    const uint8_t* bytes = ip.data.v6;
    bool all_zero = true;
    for (size_t i = 0; i < 16; ++i) all_zero = all_zero && bytes[i] == 0;
    bool loopback = true;
    for (size_t i = 0; i < 15; ++i) loopback = loopback && bytes[i] == 0;
    loopback = loopback && bytes[15] == 1;
    return all_zero || loopback || (bytes[0] & 0xfeu) == 0xfcu ||
           (bytes[0] == 0xfe && (bytes[1] & 0xc0u) == 0x80u) || bytes[0] == 0xff;
}

} // namespace

Router::Router() : loaded_(false) {}
Router::~Router() = default;

bool Router::load(const RouterConfig& config) {
    if (config.domain_strategy != "AsIs") {
        TX_ERROR("Router only supports domainStrategy=AsIs (got: %s)",
                 config.domain_strategy.c_str());
        return false;
    }
    config_ = config;
    for (auto& rule : config_.rules) {
        for (auto& domain : rule.domains) {
            domain = to_lower_ascii(domain);
        }
        for (auto& ip : rule.ips) {
            ip = to_lower_ascii(ip);
        }
    }

    // Load GeoIP data
    if (!config.geoip_path.empty()) {
        if (!geoip_.load(config.geoip_path)) {
            TX_ERROR("Failed to load GeoIP from: %s", config.geoip_path.c_str());
            return false;
        }
    }

    // Load GeoSite data
    if (!config.geosite_path.empty()) {
        if (!geosite_.load(config.geosite_path)) {
            TX_ERROR("Failed to load GeoSite from: %s", config.geosite_path.c_str());
            return false;
        }
    }

    for (const auto& rule : config_.rules) {
        for (const auto& domain : rule.domains) {
            if (!has_prefix(domain, "geosite:")) continue;
            const std::string tag = domain.substr(8);
            if (config.geosite_path.empty() || tag.empty() || !geosite_.has_tag(tag)) {
                TX_ERROR("routing rule references unavailable GeoSite tag: %s",
                         tag.c_str());
                return false;
            }
        }
        for (const auto& ip : rule.ips) {
            if (!has_prefix(ip, "geoip:") || ip == "geoip:private") continue;
            const std::string tag = ip.substr(6);
            if (config.geoip_path.empty() || tag.empty() || !geoip_.has_tag(tag)) {
                TX_ERROR("routing rule references unavailable GeoIP tag: %s", tag.c_str());
                return false;
            }
        }
    }

    loaded_ = true;
    TX_INFO("Router loaded: %zu rules, domainStrategy=%s", config_.rules.size(),
            config_.domain_strategy.c_str());
    return true;
}

RouteDecision Router::decide_target(const TargetAddr& target) const {
    if (target.type == AddrType::Domain) {
        RouteDecision decision = decide_by_host(target.host);
        TX_DEBUG("[AsIs] target=domain value=%s rule=%s outboundTag=%s",
                 target.host.c_str(), decision.matched ? "matched" : "fallback",
                 decision.outbound_tag.c_str());
        return decision;
    }

    IpAddr ip;
    if (!IpAddr::parse(target.host, target.port, ip)) {
        TX_WARN("Invalid numeric routing target: %s", target.host.c_str());
        return fallback_decision();
    }
    RouteDecision decision = decide_by_ip(ip);
    TX_DEBUG("[AsIs] target=%s value=%s rule=%s outboundTag=%s",
             target.type == AddrType::IPv6 ? "ipv6" : "ipv4", target.host.c_str(),
             decision.matched ? "matched" : "fallback", decision.outbound_tag.c_str());
    return decision;
}

RouteDecision Router::decide_by_host(const std::string& host) const {
    const std::string lower_host = to_lower_ascii(host);
    for (const auto& rule : config_.rules) {
        if (match_domain_rule(lower_host, rule)) {
            TX_DEBUG("[AsIs] domain rule matched: %s -> outboundTag=%s",
                     lower_host.c_str(), rule.outbound_tag.c_str());
            return RouteDecision{rule.outbound_tag, true};
        }
    }

    return fallback_decision();
}

RouteDecision Router::decide_by_ip(const IpAddr& ip) const {
    for (const auto& rule : config_.rules) {
        if (match_ip_rule(ip, rule)) {
            TX_DEBUG("[AsIs] IP rule matched: %s -> outboundTag=%s",
                     ip.to_string().c_str(), rule.outbound_tag.c_str());
            return RouteDecision{rule.outbound_tag, true};
        }
    }

    return fallback_decision();
}

RouteDecision Router::fallback_decision() const {
    if (!config_.rules.empty()) {
        return RouteDecision{config_.rules.back().outbound_tag, false};
    }
    return RouteDecision{"", false};
}

bool Router::match_domain_rule(const std::string& host, const RouteRule& rule) const {
    if (host.empty() || rule.domains.empty()) return false;

    for (const auto& item : rule.domains) {
        if (has_prefix(item, "geosite:")) {
            const std::string tag = item.substr(8);
            if (geosite_.match(host, tag)) {
                return true;
            }
        } else if (domain_matches_literal(host, item)) {
            return true;
        }
    }

    return false;
}

bool Router::match_ip_rule(const IpAddr& ip, const RouteRule& rule) const {
    if (rule.ips.empty()) return false;

    for (const auto& item : rule.ips) {
        if (item == "private" || item == "geoip:private") {
            if (is_private_address(ip)) {
                return true;
            }
        } else if (has_prefix(item, "geoip:")) {
            const std::string tag = item.substr(6);
            if (geoip_.match(ip, tag)) {
                return true;
            }
        }
    }

    return false;
}

} // namespace tx
