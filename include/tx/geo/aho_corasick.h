#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <queue>

namespace tx {

// Aho-Corasick automaton for multi-pattern substring matching.
//
// Used for Plain type GeoSite rules (keyword/substring matching).
// Builds a trie with failure links for O(n + m + z) matching,
// where n = text length, m = total pattern length, z = number of matches.
//
// Uses Double Array representation for cache-friendly storage.
class AhoCorasick {
public:
    AhoCorasick();
    ~AhoCorasick();

    // Add a pattern with associated country code
    void add_pattern(const std::string& pattern, const std::string& country);

    // Build the automaton (must be called after all patterns are added)
    void build();

    // Search text for patterns. Returns true if any pattern from the
    // specified country is found.
    bool search(const std::string& text, const std::string& country) const;

    // Search returning all matching countries
    std::vector<std::string> search_all(const std::string& text) const;

    bool empty() const { return states_.empty(); }
    size_t pattern_count() const { return pattern_count_; }

private:
    struct State {
        // Children transitions (ASCII printable range)
        std::array<int, 128> goto_map;
        int fail_link;
        // Output: country codes matched at this state
        std::vector<std::string> output;

        State() : fail_link(0) {
            goto_map.fill(-1);
        }
    };

    std::vector<State> states_;
    size_t pattern_count_;
    bool built_;
};

} // namespace tx
