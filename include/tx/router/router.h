#pragma once

#include <string>
#include <vector>
#include <memory>
#include "tx/common/types.h"
#include "tx/geo/geoip.h"
#include "tx/geo/geosite.h"

namespace tx {

// Routing configuration
struct RouterConfig {
    std::string geoip_path;
    std::string geosite_path;
    std::vector<std::string> direct_geoip_tags;    // e.g., ["cn", "private"]
    std::vector<std::string> direct_geosite_tags;  // e.g., ["cn"]
};

// Router: decides whether to connect directly or through proxy.
//
// Decision logic (in order):
//   1. Loopback / LAN addresses → Direct
//   2. GeoIP match for any direct tag → Direct
//   3. GeoSite match for any direct tag → Direct
//   4. Default → Proxy
class Router {
public:
    Router();
    ~Router();

    // Load geo data files and configure routing rules
    bool load(const RouterConfig& config);

    // Make routing decision
    RouteAction decide(const std::string& host, const IpAddr& resolved_ip) const;

    // Overload: when we only have hostname (no IP yet)
    RouteAction decide_by_host(const std::string& host) const;

    // Overload: when we only have IP (no hostname)
    RouteAction decide_by_ip(const IpAddr& ip) const;

    bool loaded() const { return loaded_; }

private:
    GeoIpMatcher   geoip_;
    GeoSiteMatcher geosite_;
    RouterConfig   config_;
    bool           loaded_;
};

} // namespace tx
