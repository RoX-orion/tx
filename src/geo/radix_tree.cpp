#include "tx/geo/radix_tree.h"
#include "tx/common/log.h"
#include <cstring>

namespace tx {

RadixTree::RadixTree() : root_(new Node), size_(0) {}

RadixTree::~RadixTree() {
    destroy(root_);
}

void RadixTree::destroy(Node* node) {
    if (!node) return;
    destroy(node->children[0]);
    destroy(node->children[1]);
    delete node;
}

int RadixTree::get_bit(const uint8_t* bytes, size_t pos) {
    size_t byte_idx = pos / 8;
    int bit_idx = 7 - (pos % 8);
    return (bytes[byte_idx] >> bit_idx) & 1;
}

void RadixTree::insert(const uint8_t* ip_bytes, uint8_t prefix_len,
                        const std::string& country, bool is_ipv6) {
    if (prefix_len == 0) return;

    size_t total_bits = is_ipv6 ? 128 : 32;
    if (prefix_len > total_bits) prefix_len = static_cast<uint8_t>(total_bits);

    Node* current = root_;
    size_t depth = 0;

    while (depth < prefix_len) {
        int bit = get_bit(ip_bytes, depth);
        if (current->children[bit] == nullptr) {
            // Create new node
            current->children[bit] = new Node;
            current->children[bit]->bit_pos = static_cast<uint16_t>(depth);
        }
        current = current->children[bit];
        depth++;
    }

    if (!current->is_terminal) {
        size_++;
    }
    current->is_terminal = true;
    current->country = country;
}

std::string RadixTree::lookup(const uint8_t* ip_bytes, bool is_ipv6) const {
    Node* current = root_;
    std::string result;
    size_t total_bits = is_ipv6 ? 128 : 32;

    for (size_t depth = 0; depth < total_bits; depth++) {
        if (current->is_terminal) {
            result = current->country;
        }

        int bit = get_bit(ip_bytes, depth);
        if (current->children[bit] == nullptr) {
            break;
        }
        current = current->children[bit];
    }

    // Check the last node
    if (current && current->is_terminal) {
        result = current->country;
    }

    return result;
}

bool RadixTree::match(const uint8_t* ip_bytes, bool is_ipv6,
                       const std::string& country) const {
    Node* current = root_;
    size_t total_bits = is_ipv6 ? 128 : 32;

    for (size_t depth = 0; depth < total_bits; depth++) {
        if (current->is_terminal && current->country == country) {
            return true;
        }

        int bit = get_bit(ip_bytes, depth);
        if (current->children[bit] == nullptr) {
            break;
        }
        current = current->children[bit];
    }

    if (current && current->is_terminal && current->country == country) {
        return true;
    }

    return false;
}

size_t RadixTree::memory_usage() const {
    return memory_usage(root_);
}

size_t RadixTree::memory_usage(const Node* node) const {
    if (!node) return 0;
    size_t total = sizeof(Node) + node->country.capacity();
    total += memory_usage(node->children[0]);
    total += memory_usage(node->children[1]);
    return total;
}

} // namespace tx
