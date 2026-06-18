#include "tx/geo/trie.h"
#include "tx/common/log.h"
#include <algorithm>

namespace tx {

ReverseTrie::ReverseTrie() : root_(new Node), size_(0) {}

ReverseTrie::~ReverseTrie() {
    // Iterative cleanup using stack
    std::vector<Node*> stack = {root_};
    while (!stack.empty()) {
        Node* n = stack.back();
        stack.pop_back();
        for (auto& kv : n->children) {
            stack.push_back(kv.second);
        }
        delete n;
    }
}

std::string ReverseTrie::reverse(const std::string& s) {
    std::string r(s.rbegin(), s.rend());
    return r;
}

void ReverseTrie::insert_domain(const std::string& domain, const std::string& country) {
    // Reverse the domain for suffix matching
    std::string reversed = reverse(domain);
    Node* current = root_;

    for (char c : reversed) {
        if (current->children.find(c) == current->children.end()) {
            current->children[c] = new Node;
        }
        current = current->children[c];
    }

    if (!current->is_terminal) {
        size_++;
    }
    current->is_terminal = true;

    // Add country if not already present
    auto& countries = current->countries;
    if (std::find(countries.begin(), countries.end(), country) == countries.end()) {
        countries.push_back(country);
    }
}

bool ReverseTrie::match(const std::string& domain, const std::string& country) const {
    // Walk the reversed domain through the trie
    // At each node that's a terminal, check if the country matches
    std::string reversed = reverse(domain);
    Node* current = root_;

    // Check root (matches everything)
    if (current->is_terminal) {
        for (const auto& c : current->countries) {
            if (c == country) return true;
        }
    }

    for (char ch : reversed) {
        auto it = current->children.find(ch);
        if (it == current->children.end()) {
            break;
        }
        current = it->second;

        if (current->is_terminal) {
            for (const auto& c : current->countries) {
                if (c == country) return true;
            }
        }
    }

    return false;
}

std::string ReverseTrie::lookup(const std::string& domain) const {
    std::string reversed = reverse(domain);
    Node* current = root_;
    std::string result;

    if (current->is_terminal && !current->countries.empty()) {
        result = current->countries[0];
    }

    for (char ch : reversed) {
        auto it = current->children.find(ch);
        if (it == current->children.end()) {
            break;
        }
        current = it->second;

        if (current->is_terminal && !current->countries.empty()) {
            result = current->countries[0];
        }
    }

    return result;
}

} // namespace tx
