#pragma once

#include "tx/common/types.h"

#include <cstddef>
#include <cstdint>
#include <list>
#include <string>
#include <unordered_map>
#include <vector>

namespace tx {

// Minimal authoritative fake-IP DNS engine. It handles one IN A/AAAA question
// per message and preserves stable forward/reverse mappings for routing.
class FakeIpDns {
public:
    FakeIpDns();

    bool configure(const std::string& ipv4_range,
                   const std::string& ipv6_range,
                   uint32_t ttl_seconds,
                   std::string& error,
                   size_t capacity = 4096);

    // Returns true when handled locally. A/AAAA receive fake addresses,
    // HTTPS/SVCB receive NOERROR/NODATA, and malformed requests receive
    // FORMERR. Other valid types return false and must be forwarded.
    bool respond(const uint8_t* query, size_t query_len,
                 std::vector<uint8_t>& response);

    bool reverse_lookup(const std::string& address, std::string& domain);
    size_t mapping_count() const { return reverse_.size(); }

private:
    struct Mapping {
        std::string ipv4;
        std::string ipv6;
        uint64_t expires_at = 0;
        std::list<std::string>::iterator lru_position;
    };
    struct ReverseMapping {
        std::string domain;
        uint64_t expires_at = 0;
    };
    std::string allocate_ipv4();
    std::string allocate_ipv6();
    void expire_mappings(uint64_t now);
    void erase_mapping(std::unordered_map<std::string, Mapping>::iterator mapping);
    void touch_mapping(std::unordered_map<std::string, Mapping>::iterator mapping,
                       uint64_t now);
    bool ensure_mapping_capacity(uint64_t now);

    std::unordered_map<std::string, Mapping> forward_;
    std::unordered_map<std::string, ReverseMapping> reverse_;
    std::list<std::string> lru_;
    uint32_t ipv4_network_ = 0;
    uint8_t ipv4_prefix_ = 16;
    uint32_t next_ipv4_ = 4;
    uint8_t ipv6_prefix_[16] = {};
    uint8_t ipv6_prefix_bits_ = 96;
    uint32_t next_ipv6_ = 4;
    uint32_t ttl_ = 60;
    size_t capacity_ = 4096;
};

} // namespace tx
