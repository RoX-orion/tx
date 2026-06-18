#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <unordered_map>

namespace tx {

// Reverse Suffix Trie for domain matching.
//
// Domains are reversed before insertion:
//   "google.com" → "moc.elgoo"
//   "sub.example.com" → "moc.elpmaxe.bus"
//
// This allows efficient suffix matching: to check if a domain ends with
// "example.com", we reverse both and do a prefix walk from the root.
class ReverseTrie {
public:
    ReverseTrie();
    ~ReverseTrie();

    // Insert a domain pattern. The domain should be the raw pattern
    // (e.g., "google.com" for suffix match, "full:www.google.com" for exact).
    // country: the geosite tag (e.g., "cn")
    void insert_domain(const std::string& domain, const std::string& country);

    // Lookup a domain. Returns matching country codes.
    // For suffix match: "mail.google.com" matches "google.com"
    // For exact match: only "google.com" matches "google.com"
    bool match(const std::string& domain, const std::string& country) const;

    // Lookup returning first matching country
    std::string lookup(const std::string& domain) const;

    size_t size() const { return size_; }

private:
    struct Node {
        // Children indexed by character (ASCII 0-127)
        std::unordered_map<char, Node*> children;
        // If this node is a terminal (end of a pattern), store country codes
        std::vector<std::string> countries;
        bool is_terminal = false;
    };

    // Reverse a string
    static std::string reverse(const std::string& s);

    Node* root_;
    size_t size_;
};

} // namespace tx
