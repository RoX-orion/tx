#pragma once

#include <string>
#include <vector>
#include <memory>
#include "tx/common/types.h"
#include "tx/geo/geoip.h"
#include "tx/geo/geosite.h"

namespace tx {

struct RouteRule {
    std::vector<std::string> domains; // e.g., ["geosite:cn", "example.com"]
    std::vector<std::string> ips;     // e.g., ["geoip:cn", "geoip:private"]
    std::string outbound_tag;
};

struct RouteDecision {
    std::string outbound_tag;
    bool matched = false;
};

// Routing configuration
struct RouterConfig {
    std::string geoip_path;
    std::string geosite_path;
    std::vector<RouteRule> rules;
};

// Router: evaluates configured rules from top to bottom.
class Router {
public:
    Router();
    ~Router();

    // Load geo data files and configure routing rules
    bool load(const RouterConfig& config);

    // Make routing decision
    RouteDecision decide(const std::string& host, const IpAddr& resolved_ip) const;

    // Overload: when we only have hostname (no IP yet)
    RouteDecision decide_by_host(const std::string& host) const;

    // Overload: when we only have IP (no hostname)
    RouteDecision decide_by_ip(const IpAddr& ip) const;

    // Last rule is the fallback when no matcher applies.
    RouteDecision fallback_decision() const;

    bool loaded() const { return loaded_; }

private:
    bool match_domain_rule(const std::string& host, const RouteRule& rule) const;
    bool match_ip_rule(const IpAddr& ip, const RouteRule& rule) const;

    GeoIpMatcher   geoip_;
    GeoSiteMatcher geosite_;
    RouterConfig   config_;
    bool           loaded_;
};

} // namespace tx
