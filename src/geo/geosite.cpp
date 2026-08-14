#include "tx/geo/geosite.h"
#include "tx/common/log.h"
#include "geo_file.h"
#include "protobuf_reader.h"
#include <algorithm>
#include <cctype>
#include <functional>

namespace tx {

// ===== Protobuf parser for geosite.dat =====
namespace {

static std::string to_lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool read_varint(const uint8_t* data, size_t len, size_t& pos, uint64_t& val) {
    return detail::read_proto_varint(data, len, pos, val);
}

static bool read_length_delimited(const uint8_t* data, size_t len, size_t& pos,
                                   const uint8_t*& field_data, size_t& field_len) {
    return detail::read_proto_bytes(data, len, pos, field_data, field_len);
}

static bool skip_field(const uint8_t* data, size_t len, size_t& pos, uint32_t wt) {
    return detail::skip_proto_field(data, len, pos, wt);
}

static bool read_string(const uint8_t* data, size_t len, size_t& pos, std::string& out) {
    const uint8_t* s; size_t sl;
    if (!read_length_delimited(data, len, pos, s, sl)) return false;
    out.assign(reinterpret_cast<const char*>(s), sl);
    return true;
}

// DomainAttribute: required string key = 1; optional bool bool_value = 2; optional int64 int_value = 3;
struct PbDomainAttribute {
    std::string key;
    bool bool_value = false;
    int64_t int_value = 0;
};

static bool parse_domain_attribute(const uint8_t* data, size_t len, PbDomainAttribute& attr) {
    size_t pos = 0;
    bool has_key = false;
    while (pos < len) {
        uint64_t tag;
        if (!read_varint(data, len, pos, tag)) return false;
        uint32_t fn = static_cast<uint32_t>(tag >> 3);
        uint32_t wt = static_cast<uint32_t>(tag & 0x07);

        switch (fn) {
            case 1:
                if (wt != 2) return false;
                if (!read_string(data, len, pos, attr.key)) return false;
                has_key = true;
                break;
            case 2:
                if (wt != 0) return false;
                { uint64_t v; if (!read_varint(data, len, pos, v)) return false; attr.bool_value = (v != 0); }
                break;
            case 3:
                if (wt != 0) return false;
                { uint64_t v; if (!read_varint(data, len, pos, v)) return false; attr.int_value = static_cast<int64_t>(v); }
                break;
            default:
                if (!skip_field(data, len, pos, wt)) return false;
        }
    }
    return has_key;
}

// Domain: required Type type = 1; required string value = 2; repeated DomainAttribute attribute = 3;
struct PbDomain {
    uint32_t type = 0;
    std::string value;
    std::vector<PbDomainAttribute> attributes;
};

static bool parse_domain(const uint8_t* data, size_t len, PbDomain& domain) {
    size_t pos = 0;
    bool has_type = false;
    bool has_value = false;
    while (pos < len) {
        uint64_t tag;
        if (!read_varint(data, len, pos, tag)) return false;
        uint32_t fn = static_cast<uint32_t>(tag >> 3);
        uint32_t wt = static_cast<uint32_t>(tag & 0x07);

        switch (fn) {
            case 1: // type (enum/varint)
                if (wt != 0) return false;
                { uint64_t v; if (!read_varint(data, len, pos, v) || v > 3) return false; domain.type = static_cast<uint32_t>(v); has_type = true; }
                break;
            case 2: // value (string)
                if (wt != 2) return false;
                if (!read_string(data, len, pos, domain.value)) return false;
                has_value = true;
                break;
            case 3: { // DomainAttribute (embedded message)
                if (wt != 2) return false;
                const uint8_t* ad; size_t al;
                if (!read_length_delimited(data, len, pos, ad, al)) return false;
                PbDomainAttribute attr;
                if (!parse_domain_attribute(ad, al, attr)) return false;
                domain.attributes.push_back(std::move(attr));
                break;
            }
            default:
                if (!skip_field(data, len, pos, wt)) return false;
        }
    }
    return has_type && has_value && !domain.value.empty();
}

// GeoSite: required string country_code = 1; repeated Domain domain = 2;
struct PbGeoSite {
    std::string country_code;
    std::vector<PbDomain> domains;
};

static bool parse_geosite_entry(const uint8_t* data, size_t len, PbGeoSite& site) {
    size_t pos = 0;
    bool has_code = false;
    while (pos < len) {
        uint64_t tag;
        if (!read_varint(data, len, pos, tag)) return false;
        uint32_t fn = static_cast<uint32_t>(tag >> 3);
        uint32_t wt = static_cast<uint32_t>(tag & 0x07);

        switch (fn) {
            case 1:
                if (wt != 2) return false;
                if (!read_string(data, len, pos, site.country_code)) return false;
                has_code = true;
                break;
            case 2: {
                if (wt != 2) return false;
                const uint8_t* dd; size_t dl;
                if (!read_length_delimited(data, len, pos, dd, dl)) return false;
                PbDomain domain;
                if (!parse_domain(dd, dl, domain)) return false;
                site.domains.push_back(std::move(domain));
                break;
            }
            default:
                if (!skip_field(data, len, pos, wt)) return false;
        }
    }
    return has_code && !site.country_code.empty();
}

// GeoSiteList: repeated GeoSite entry = 1;
static bool parse_geosite_list(const uint8_t* data, size_t len,
                                std::vector<PbGeoSite>& sites) {
    size_t pos = 0;
    while (pos < len) {
        uint64_t tag;
        if (!read_varint(data, len, pos, tag)) return false;
        uint32_t fn = static_cast<uint32_t>(tag >> 3);
        uint32_t wt = static_cast<uint32_t>(tag & 0x07);

        if (fn == 1 && wt == 2) {
            const uint8_t* ed; size_t el;
            if (!read_length_delimited(data, len, pos, ed, el)) return false;
            PbGeoSite site;
            if (!parse_geosite_entry(ed, el, site)) return false;
            sites.push_back(std::move(site));
        } else {
            if (fn == 1) return false;
            if (!skip_field(data, len, pos, wt)) return false;
        }
    }
    return true;
}

} // anonymous namespace

// ===== GeoSiteMatcher implementation =====

GeoSiteMatcher::GeoSiteMatcher() = default;
GeoSiteMatcher::~GeoSiteMatcher() = default;

bool GeoSiteMatcher::load(const std::string& path) {
    std::vector<uint8_t> data;
    if (!detail::read_geo_file(path, data)) {
        return false;
    }
    return parse_geosite(data.data(), data.size());
}

bool GeoSiteMatcher::parse_geosite(const uint8_t* data, size_t len) {
    size_t domain_count = 0;
    std::vector<PbGeoSite> sites;
    if (!parse_geosite_list(data, len, sites)) return false;

    for (auto& site : sites) {
            const std::string country = to_lower_ascii(site.country_code);
            if (std::find(tag_order_.begin(), tag_order_.end(), country) ==
                tag_order_.end()) tag_order_.push_back(country);

            for (auto& dom : site.domains) {
                domain_count++;
                const std::string value = to_lower_ascii(dom.value);

                switch (dom.type) {
                    case 0: // Plain — substring match
                        ac_automaton_.add_pattern(value, country);
                        break;
                    case 2: // Domain — suffix match
                        domain_trie_.insert_domain(value, country);
                        break;
                    case 3: // Full — exact match
                        exact_map_[country].push_back(value);
                        break;
                    case 1: // Regex
                        try {
                            regex_patterns_.push_back({std::regex(value), country});
                        } catch (const std::regex_error& e) {
                            TX_ERROR("Invalid regex in geosite '%s': %s (%s)",
                                    country.c_str(), value.c_str(), e.what());
                            return false;
                        }
                        break;
                    default:
                        return false;
                }
            }
    }

    // Build Aho-Corasick automaton
    ac_automaton_.build();

    TX_INFO("GeoSite loaded: %zu domains, trie nodes: %zu, AC patterns: %zu, exact entries: %zu, regex: %zu",
            domain_count, domain_trie_.size(), ac_automaton_.pattern_count(),
            exact_map_.size(), regex_patterns_.size());
    return true;
}

bool GeoSiteMatcher::match(const std::string& domain, const std::string& tag) const {
    const std::string normalized_domain = to_lower_ascii(domain);
    const std::string normalized_tag = to_lower_ascii(tag);

    // 1. Check exact match
    auto exact_it = exact_map_.find(normalized_tag);
    if (exact_it != exact_map_.end()) {
        for (const auto& e : exact_it->second) {
            if (normalized_domain == e) return true;
        }
    }

    // 2. Check suffix match (ReverseTrie)
    if (domain_trie_.match(normalized_domain, normalized_tag)) {
        return true;
    }

    // 3. Check substring match (Aho-Corasick)
    if (ac_automaton_.search(normalized_domain, normalized_tag)) {
        return true;
    }

    // 4. Check regex match
    for (const auto& re : regex_patterns_) {
        if (re.country == normalized_tag) {
            try {
                if (std::regex_search(normalized_domain, re.pattern)) return true;
            } catch (...) {}
        }
    }

    return false;
}

bool GeoSiteMatcher::match_domain(const std::string& domain, const std::string& tag) const {
    const std::string normalized_domain = to_lower_ascii(domain);
    const std::string normalized_tag = to_lower_ascii(tag);

    auto exact_it = exact_map_.find(normalized_tag);
    if (exact_it != exact_map_.end()) {
        for (const auto& e : exact_it->second) {
            if (normalized_domain == e) return true;
        }
    }

    return domain_trie_.match(normalized_domain, normalized_tag);
}

std::string GeoSiteMatcher::lookup(const std::string& domain) const {
    for (const auto& tag : tag_order_) if (match(domain, tag)) return tag;
    return "";
}

bool GeoSiteMatcher::has_tag(const std::string& tag) const {
    const std::string normalized = to_lower_ascii(tag);
    return std::find(tag_order_.begin(), tag_order_.end(), normalized) != tag_order_.end();
}

} // namespace tx
