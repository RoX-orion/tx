#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <regex>
#include <unordered_map>
#include "tx/geo/trie.h"
#include "tx/geo/aho_corasick.h"
#include "tx/geo/geo_data.h"

namespace tx {

// GeoSite matcher: loads geosite.dat, builds ReverseTrie + AhoCorasick indexes.
//
// Matching strategy:
//   Domain type → ReverseTrie (suffix match)
//   Plain type  → AhoCorasick (substring match)
//   Full type   → exact match set (hash lookup)
//   Regex type  → std::regex (fallback, few patterns)
class GeoSiteMatcher {
public:
    GeoSiteMatcher();
    ~GeoSiteMatcher();

    // Load from geosite.dat file
    bool load(const std::string& path);

    // Check if domain matches a specific geosite tag
    bool match(const std::string& domain, const std::string& tag) const;

    // Check only exact and domain-suffix rules. This is safer for routing
    // because Plain keyword rules can match unrelated domains.
    bool match_domain(const std::string& domain, const std::string& tag) const;

    // Lookup first matching geosite tag for a domain
    std::string lookup(const std::string& domain) const;

private:
    struct RegexEntry {
        std::regex pattern;
        std::string country;
    };

    // Parse V2Ray geosite.dat protobuf format
    bool parse_geosite(const uint8_t* data, size_t len);

    // Domain suffix patterns (ReverseTrie)
    ReverseTrie domain_trie_;

    // Substring patterns (AhoCorasick)
    AhoCorasick ac_automaton_;

    // Exact match patterns (hash set per country)
    std::unordered_map<std::string, std::vector<std::string>> exact_map_;

    // Regex patterns (rare, fallback)
    std::vector<RegexEntry> regex_patterns_;

    GeoData data_;
};

} // namespace tx
