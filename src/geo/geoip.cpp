#include "tx/geo/geoip.h"
#include "tx/common/log.h"
#include "geo_file.h"
#include <algorithm>
#include <cctype>
#include <functional>
#include <vector>

namespace tx {

// ===== Minimal protobuf wire format parser =====
// V2Ray geoip.dat uses proto2 with simple nested messages.
// We parse the wire format directly without a protobuf library.

namespace {

static std::string to_lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Read a varint from data, advance position
static bool read_varint(const uint8_t* data, size_t len, size_t& pos, uint64_t& val) {
    val = 0;
    int shift = 0;
    while (pos < len) {
        uint8_t b = data[pos++];
        val |= static_cast<uint64_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) return true;
        shift += 7;
        if (shift >= 64) return false; // overflow
    }
    return false;
}

// Read a length-delimited field
static bool read_length_delimited(const uint8_t* data, size_t len, size_t& pos,
                                   const uint8_t*& field_data, size_t& field_len) {
    uint64_t flen;
    if (!read_varint(data, len, pos, flen)) return false;
    if (pos + flen > len) return false;
    field_data = data + pos;
    field_len = static_cast<size_t>(flen);
    pos += field_len;
    return true;
}

// Parse CIDR message: required bytes ip = 1; required uint32 prefix = 2;
static bool parse_cidr(const uint8_t* data, size_t len,
                        const uint8_t*& ip, size_t& ip_len, uint32_t& prefix) {
    ip = nullptr; ip_len = 0; prefix = 0;
    size_t pos = 0;
    bool has_ip = false, has_prefix = false;

    while (pos < len) {
        uint64_t tag;
        if (!read_varint(data, len, pos, tag)) return false;
        uint32_t field_num = static_cast<uint32_t>(tag >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag & 0x07);

        switch (field_num) {
            case 1: // bytes ip
                if (wire_type != 2) return false;
                if (!read_length_delimited(data, len, pos, ip, ip_len)) return false;
                has_ip = true;
                break;
            case 2: // uint32 prefix
                if (wire_type != 0) return false;
                {
                    uint64_t v;
                    if (!read_varint(data, len, pos, v)) return false;
                    prefix = static_cast<uint32_t>(v);
                    has_prefix = true;
                }
                break;
            default:
                // Skip unknown field
                if (wire_type == 0) { uint64_t v; read_varint(data, len, pos, v); }
                else if (wire_type == 2) { const uint8_t* d; size_t dl; read_length_delimited(data, len, pos, d, dl); }
                else if (wire_type == 5) { pos += 4; }
                else if (wire_type == 1) { pos += 8; }
                else return false;
        }
    }
    return has_ip && has_prefix;
}

// Parse GeoIP message: required string country_code = 1; repeated CIDR cidr = 2;
static bool parse_geoip_entry(const uint8_t* data, size_t len,
                               std::string& country_code,
                               std::vector<std::pair<const uint8_t*, size_t>>& cidrs,
                               std::vector<uint32_t>& prefixes) {
    size_t pos = 0;
    bool has_code = false;

    while (pos < len) {
        uint64_t tag;
        if (!read_varint(data, len, pos, tag)) return false;
        uint32_t field_num = static_cast<uint32_t>(tag >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag & 0x07);

        switch (field_num) {
            case 1: { // string country_code
                if (wire_type != 2) return false;
                const uint8_t* s; size_t sl;
                if (!read_length_delimited(data, len, pos, s, sl)) return false;
                country_code.assign(reinterpret_cast<const char*>(s), sl);
                has_code = true;
                break;
            }
            case 2: { // CIDR message
                if (wire_type != 2) return false;
                const uint8_t* cd; size_t cl;
                if (!read_length_delimited(data, len, pos, cd, cl)) return false;
                const uint8_t* ip; size_t ip_len; uint32_t prefix;
                if (parse_cidr(cd, cl, ip, ip_len, prefix)) {
                    cidrs.push_back({ip, ip_len});
                    prefixes.push_back(prefix);
                }
                break;
            }
            default:
                if (wire_type == 0) { uint64_t v; read_varint(data, len, pos, v); }
                else if (wire_type == 2) { const uint8_t* d; size_t dl; read_length_delimited(data, len, pos, d, dl); }
                else if (wire_type == 5) { pos += 4; }
                else if (wire_type == 1) { pos += 8; }
                else return false;
        }
    }
    return has_code;
}

// Parse GeoIPList: repeated GeoIP entry = 1;
static bool parse_geoip_list(const uint8_t* data, size_t len,
                              std::function<void(const std::string&,
                                                  const std::vector<std::pair<const uint8_t*, size_t>>&,
                                                  const std::vector<uint32_t>&)> callback) {
    size_t pos = 0;

    while (pos < len) {
        uint64_t tag;
        if (!read_varint(data, len, pos, tag)) return false;
        uint32_t field_num = static_cast<uint32_t>(tag >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag & 0x07);

        if (field_num == 1 && wire_type == 2) {
            const uint8_t* entry_data; size_t entry_len;
            if (!read_length_delimited(data, len, pos, entry_data, entry_len)) return false;

            std::string country;
            std::vector<std::pair<const uint8_t*, size_t>> cidrs;
            std::vector<uint32_t> prefixes;
            if (parse_geoip_entry(entry_data, entry_len, country, cidrs, prefixes)) {
                callback(country, cidrs, prefixes);
            }
        } else {
            if (wire_type == 0) { uint64_t v; read_varint(data, len, pos, v); }
            else if (wire_type == 2) { const uint8_t* d; size_t dl; read_length_delimited(data, len, pos, d, dl); }
            else if (wire_type == 5) { pos += 4; }
            else if (wire_type == 1) { pos += 8; }
            else return false;
        }
    }
    return true;
}

} // anonymous namespace

// ===== GeoIpMatcher implementation =====

GeoIpMatcher::GeoIpMatcher() = default;
GeoIpMatcher::~GeoIpMatcher() = default;

bool GeoIpMatcher::load(const std::string& path) {
    std::vector<uint8_t> data;
    if (!detail::read_geo_file(path, data)) {
        return false;
    }
    return parse_geoip(data.data(), data.size());
}

bool GeoIpMatcher::parse_geoip(const uint8_t* data, size_t len) {
    size_t count = 0;

    bool ok = parse_geoip_list(data, len,
        [this, &count](const std::string& country,
                        const std::vector<std::pair<const uint8_t*, size_t>>& cidrs,
                        const std::vector<uint32_t>& prefixes) {
            const std::string normalized_country = to_lower_ascii(country);

            for (size_t i = 0; i < cidrs.size(); i++) {
                const uint8_t* ip = cidrs[i].first;
                size_t ip_len = cidrs[i].second;
                uint32_t prefix = prefixes[i];

                if (ip_len == 4) {
                    tree_v4_.insert(ip, static_cast<uint8_t>(prefix), normalized_country, false);
                    count++;
                } else if (ip_len == 16) {
                    tree_v6_.insert(ip, static_cast<uint8_t>(prefix), normalized_country, true);
                    count++;
                }
            }
        });

    TX_INFO("GeoIP loaded: %zu CIDR entries (v4: %zu, v6: %zu)",
            count, tree_v4_.size(), tree_v6_.size());
    return ok;
}

bool GeoIpMatcher::match(const IpAddr& addr, const std::string& country) const {
    const std::string normalized_country = to_lower_ascii(country);

    if (addr.family == IpAddr::IPv4) {
        // Check if it's an IPv4-mapped IPv6 address
        return tree_v4_.match(addr.data.v4, false, normalized_country);
    } else {
        // Check IPv4-mapped first
        if (addr.is_ipv4_mapped_ipv6()) {
            return tree_v4_.match(addr.data.v6 + 12, false, normalized_country);
        }
        return tree_v6_.match(addr.data.v6, true, normalized_country);
    }
}

std::string GeoIpMatcher::lookup(const IpAddr& addr) const {
    if (addr.family == IpAddr::IPv4) {
        return tree_v4_.lookup(addr.data.v4, false);
    }
    if (addr.is_ipv4_mapped_ipv6()) {
        return tree_v4_.lookup(addr.data.v6 + 12, false);
    }
    return tree_v6_.lookup(addr.data.v6, true);
}

} // namespace tx
