#include "tx/geo/aho_corasick.h"
#include "tx/common/log.h"
#include <algorithm>
#include <set>

namespace tx {

AhoCorasick::AhoCorasick() : pattern_count_(0), built_(false) {
    // Root state
    states_.emplace_back();
}

AhoCorasick::~AhoCorasick() = default;

void AhoCorasick::add_pattern(const std::string& pattern, const std::string& country) {
    if (pattern.empty() || built_) return;

    int current = 0;
    for (char c : pattern) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= 128) continue; // skip non-ASCII

        if (states_[current].goto_map[uc] == -1) {
            states_[current].goto_map[uc] = static_cast<int>(states_.size());
            states_.emplace_back();
        }
        current = states_[current].goto_map[uc];
    }

    // Add country output at terminal state
    auto& out = states_[current].output;
    if (std::find(out.begin(), out.end(), country) == out.end()) {
        out.push_back(country);
    }
    pattern_count_++;
}

void AhoCorasick::build() {
    if (built_) return;
    built_ = true;

    // Build failure links using BFS
    std::queue<int> queue;

    // Initialize depth-1 states: fail → root (0)
    for (int c = 0; c < 128; c++) {
        int s = states_[0].goto_map[c];
        if (s != -1) {
            states_[s].fail_link = 0;
            queue.push(s);
        } else {
            states_[0].goto_map[c] = 0; // missing transitions go to root
        }
    }

    // BFS to set failure links
    while (!queue.empty()) {
        int u = queue.front();
        queue.pop();

        for (int c = 0; c < 128; c++) {
            int v = states_[u].goto_map[c];
            if (v == -1) {
                states_[u].goto_map[c] =
                    states_[states_[u].fail_link].goto_map[c];
                continue;
            }

            queue.push(v);
            states_[v].fail_link =
                states_[states_[u].fail_link].goto_map[c];

            // Merge output from failure link
            auto& fail_out = states_[states_[v].fail_link].output;
            auto& v_out = states_[v].output;
            for (const auto& country : fail_out) {
                if (std::find(v_out.begin(), v_out.end(), country) == v_out.end()) {
                    v_out.push_back(country);
                }
            }
        }
    }

}

bool AhoCorasick::search(const std::string& text, const std::string& country) const {
    if (!built_ || states_.size() <= 1) return false;

    int current = 0;
    for (char c : text) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= 128) {
            current = 0;
            continue;
        }

        current = states_[current].goto_map[uc];

        // Check output at current state
        for (const auto& matched : states_[current].output) {
            if (matched == country) return true;
        }
    }

    return false;
}

std::vector<std::string> AhoCorasick::search_all(const std::string& text) const {
    if (!built_ || states_.size() <= 1) return {};

    std::set<std::string> found;
    int current = 0;

    for (char c : text) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= 128) {
            current = 0;
            continue;
        }

        current = states_[current].goto_map[uc];

        for (const auto& matched : states_[current].output) {
            found.insert(matched);
        }
    }

    return std::vector<std::string>(found.begin(), found.end());
}

} // namespace tx
