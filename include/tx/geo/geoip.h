#pragma once

#include <cstdint>
#include <string>
#include "tx/geo/radix_tree.h"
#include "tx/common/types.h"

namespace tx {

// GeoIP matcher: loads geoip.dat, parses CIDR blocks, builds RadixTree indexes.
class GeoIpMatcher {
public:
    GeoIpMatcher();
    ~GeoIpMatcher();

    // Load from geoip.dat file
    bool load(const std::string& path);

    // Check if IP belongs to a specific country code
    bool match(const IpAddr& addr, const std::string& country) const;

    // Lookup country code for an IP
    std::string lookup(const IpAddr& addr) const;

    // Access underlying trees
    const RadixTree& ipv4_tree() const { return tree_v4_; }
    const RadixTree& ipv6_tree() const { return tree_v6_; }

private:
    // Parse V2Ray geoip.dat protobuf format into the radix trees
    bool parse_geoip(const uint8_t* data, size_t len);

    RadixTree tree_v4_;
    RadixTree tree_v6_;
};

} // namespace tx
