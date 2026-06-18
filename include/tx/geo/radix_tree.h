#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>

namespace tx {

// Compressed Radix Tree (Patricia Trie) for IP CIDR matching.
// Stores prefixes and maps them to country codes.
//
// Each node represents a bit prefix. Leaf or internal nodes can be
// terminal (meaning a CIDR block ends here). Path compression merges
// single-child chains into a single edge label.
class RadixTree {
public:
    RadixTree();
    ~RadixTree();

    // Insert a CIDR block into the tree.
    // ip_bytes: 4 bytes (IPv4) or 16 bytes (IPv6)
    // prefix_len: number of significant bits (e.g., 24 for /24)
    // country: country code to associate with this CIDR
    void insert(const uint8_t* ip_bytes, uint8_t prefix_len,
                const std::string& country, bool is_ipv6);

    // Lookup an IP address. Returns the country code if found, empty string otherwise.
    // ip_bytes: 4 bytes (IPv4) or 16 bytes (IPv6)
    std::string lookup(const uint8_t* ip_bytes, bool is_ipv6) const;

    // Check if an IP matches a specific country code
    bool match(const uint8_t* ip_bytes, bool is_ipv6, const std::string& country) const;

    // Number of entries
    size_t size() const { return size_; }

    // Memory usage estimate
    size_t memory_usage() const;

private:
    struct Node {
        // Bit position where this node's prefix diverges from parent
        uint16_t bit_pos;
        // If terminal, the country code
        std::string country;
        bool is_terminal;
        // Children: 0 = left (bit 0), 1 = right (bit 1)
        Node* children[2];

        Node() : bit_pos(0), is_terminal(false) {
            children[0] = nullptr;
            children[1] = nullptr;
        }
    };

    // Get bit at position 'pos' in byte array
    static int get_bit(const uint8_t* bytes, size_t pos);

    // Recursive memory counting
    size_t memory_usage(const Node* node) const;

    // Recursive cleanup
    void destroy(Node* node);

    Node* root_;
    size_t size_;
};

} // namespace tx
