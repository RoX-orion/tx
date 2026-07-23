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
            TX_WARN("Failed to load GeoIP from: %s", config.geoip_path.c_str());
        }
    }

    // Load GeoSite data
    if (!config.geosite_path.empty()) {
        if (!geosite_.load(config.geosite_path)) {
            TX_WARN("Failed to load GeoSite from: %s", config.geosite_path.c_str());
        }
    }

    loaded_ = true;
    TX_INFO("Router loaded: %zu rules, domainStrategy=%s", config_.rules.size(),
            config_.domain_strategy.c_str());
    return true;
}

RouteDecision Router::decide(const std::string& host, const IpAddr& ip) const {
    // Keep this compatibility overload AsIs: a supplied domain is authoritative
    // and must not fall through to the resolved IP.
    if (!host.empty()) {
        RouteDecision decision = decide_by_host(host);
        return decision.matched ? decision : fallback_decision();
    }
    return decide_by_ip(ip);
}

RouteDecision Router::decide_target(const TargetAddr& target) const {
    if (target.type == AddrType::Domain) {
        RouteDecision decision = decide_by_host(target.host);
        if (!decision.matched) decision = fallback_decision();
        TX_DEBUG("[AsIs] target=domain value=%s rule=%s outboundTag=%s",
                 target.host.c_str(), decision.matched ? "matched" : "fallback",
                 decision.outbound_tag.c_str());
        return decision;
    }

    const IpAddr ip = IpAddr::from_string(target.host, target.port);
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

    return RouteDecision{"", false};
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
            if (geosite_.match_domain(host, tag)) {
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
            if (ip.is_loopback() || ip.is_lan()) {
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
