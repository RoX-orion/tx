#include "tx/router/router.h"
#include "tx/common/log.h"
#include <algorithm>

namespace tx {

Router::Router() : loaded_(false) {}
Router::~Router() = default;

bool Router::load(const RouterConfig& config) {
    config_ = config;

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
    TX_INFO("Router loaded: %zu direct GeoIP tags, %zu direct GeoSite tags",
            config.direct_geoip_tags.size(), config.direct_geosite_tags.size());
    return true;
}

RouteAction Router::decide(const std::string& host, const IpAddr& ip) const {
    // 1. Loopback / LAN → Direct
    if (ip.is_loopback() || ip.is_lan()) {
        return RouteAction::Direct;
    }

    // 2. GeoIP check
    for (const auto& tag : config_.direct_geoip_tags) {
        if (geoip_.match(ip, tag)) {
            TX_DEBUG("GeoIP match: %s → %s (direct)", ip.to_string().c_str(), tag.c_str());
            return RouteAction::Direct;
        }
    }

    // 3. GeoSite check (by hostname)
    if (!host.empty()) {
        for (const auto& tag : config_.direct_geosite_tags) {
            if (geosite_.match(host, tag)) {
                TX_DEBUG("GeoSite match: %s → %s (direct)", host.c_str(), tag.c_str());
                return RouteAction::Direct;
            }
        }
    }

    // 4. Default → Proxy
    TX_DEBUG("No match for %s (%s) → proxy", host.c_str(), ip.to_string().c_str());
    return RouteAction::Proxy;
}

RouteAction Router::decide_by_host(const std::string& host) const {
    // Try GeoSite first (hostname-based)
    for (const auto& tag : config_.direct_geosite_tags) {
        if (geosite_.match(host, tag)) {
            return RouteAction::Direct;
        }
    }

    // Can't check GeoIP without an IP, default to proxy
    // (caller should resolve DNS first, then call decide())
    return RouteAction::Proxy;
}

RouteAction Router::decide_by_ip(const IpAddr& ip) const {
    if (ip.is_loopback() || ip.is_lan()) {
        return RouteAction::Direct;
    }

    for (const auto& tag : config_.direct_geoip_tags) {
        if (geoip_.match(ip, tag)) {
            return RouteAction::Direct;
        }
    }

    return RouteAction::Proxy;
}

} // namespace tx
