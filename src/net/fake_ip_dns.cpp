#include "tx/net/fake_ip_dns.h"
#include "tx/common/endian.h"

#include <algorithm>
#include <chrono>
#include "tx/common/network.h"
#include <cctype>
#include <cstring>

namespace tx {
namespace {

void append_u16(std::vector<uint8_t>& out, uint16_t value) {
    uint8_t data[2]; store_be16(data, value); out.insert(out.end(), data, data + 2);
}
void append_u32(std::vector<uint8_t>& out, uint32_t value) {
    uint8_t data[4]; store_be32(data, value); out.insert(out.end(), data, data + 4);
}
bool parse_prefix(const std::string& cidr, std::string& host, long& prefix) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    host = cidr.substr(0, slash);
    const std::string prefix_text = cidr.substr(slash + 1);
    if (prefix_text.empty() ||
        prefix_text.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    char* end = nullptr;
    prefix = std::strtol(prefix_text.c_str(), &end, 10);
    return end == prefix_text.c_str() + prefix_text.size();
}
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!value.empty() && value.back() == '.') value.pop_back();
    return value;
}

uint64_t now_seconds() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<seconds>(
        steady_clock::now().time_since_epoch()).count());
}

} // namespace

bool FakeIpDns::parse_question(const uint8_t* query, size_t query_len,
                               Question& question) {
    question = Question();
    if (!query || query_len < 12 || (load_be16(query + 2) & 0x8000u) != 0 ||
        (load_be16(query + 2) & 0x7800u) != 0 || load_be16(query + 4) != 1) {
        return false;
    }
    size_t pos = 12;
    while (pos < query_len) {
        const uint8_t label_len = query[pos++];
        if (label_len == 0) break;
        if ((label_len & 0xc0u) != 0 || label_len > 63 ||
            pos + label_len > query_len) {
            return false;
        }
        if (!question.domain.empty()) question.domain.push_back('.');
        question.domain.append(reinterpret_cast<const char*>(query + pos), label_len);
        pos += label_len;
        if (question.domain.size() > 253) return false;
    }
    if (pos == 12 || pos + 4 > query_len || query[pos - 1] != 0) return false;
    question.type = load_be16(query + pos);
    question.klass = load_be16(query + pos + 2);
    if (question.klass != 1 || question.domain.empty()) return false;
    std::transform(question.domain.begin(), question.domain.end(), question.domain.begin(),
                   [](unsigned char value) {
                       return static_cast<char>(std::tolower(value));
                   });
    if (!question.domain.empty() && question.domain.back() == '.')
        question.domain.pop_back();
    return !question.domain.empty();
}

FakeIpDns::FakeIpDns() {
    std::string error;
    configure("198.18.0.0/16", "fd00:198:18::/96", 60, error);
}

bool FakeIpDns::configure(const std::string& ipv4_range,
                          const std::string& ipv6_range,
                          uint32_t ttl_seconds,
                          std::string& error, size_t capacity,
                          uint32_t mapping_ttl_seconds) {
    std::string host;
    long prefix = 0;
    in_addr address4;
    if (!parse_prefix(ipv4_range, host, prefix) || prefix < 8 || prefix > 29 ||
        inet_pton(AF_INET, host.c_str(), &address4) != 1) {
        error = "dns.fake_ipv4_range must be an IPv4 CIDR with prefix /8 through /29";
        return false;
    }
    in6_addr address6;
    long prefix6 = 0;
    if (!parse_prefix(ipv6_range, host, prefix6) || prefix6 < 32 || prefix6 > 96 ||
        inet_pton(AF_INET6, host.c_str(), &address6) != 1) {
        error = "dns.fake_ipv6_range must be an IPv6 CIDR with prefix /32 through /96";
        return false;
    }
    if (capacity == 0) {
        error = "fake-IP DNS cache capacity must be positive";
        return false;
    }
    const uint64_t ipv4_host_count = 1ULL << (32 - prefix);
    const uint64_t ipv4_capacity = ipv4_host_count > 5 ? ipv4_host_count - 5 : 0;
    const uint64_t ipv6_capacity = (1ULL << 32) - 4;
    if (capacity > ipv4_capacity || capacity > ipv6_capacity) {
        error = "dns.cache_capacity exceeds the configured fake-IP address pool";
        return false;
    }
    ipv4_prefix_ = static_cast<uint8_t>(prefix);
    const uint32_t mask = prefix == 0 ? 0 : 0xffffffffu << (32 - prefix);
    ipv4_network_ = ntohl(address4.s_addr) & mask;
    ipv6_prefix_bits_ = static_cast<uint8_t>(prefix6);
    std::memcpy(ipv6_prefix_, &address6, 16);
    const size_t full_bytes = ipv6_prefix_bits_ / 8;
    const uint8_t partial_bits = static_cast<uint8_t>(ipv6_prefix_bits_ % 8);
    if (partial_bits != 0) {
        ipv6_prefix_[full_bytes] &=
            static_cast<uint8_t>(0xffu << (8 - partial_bits));
    }
    const size_t clear_from = full_bytes + (partial_bits != 0 ? 1 : 0);
    std::memset(ipv6_prefix_ + clear_from, 0, sizeof(ipv6_prefix_) - clear_from);
    dns_ttl_ = ttl_seconds ? ttl_seconds : 60;
    mapping_ttl_ = mapping_ttl_seconds ? mapping_ttl_seconds : 1800;
    capacity_ = capacity;
    // The network address, TUN gateway (.1), DNS (.2), and .3 are reserved.
    next_ipv4_ = 4;
    next_ipv6_ = 4;
    forward_.clear();
    reverse_.clear();
    lru_.clear();
    return true;
}

std::string FakeIpDns::allocate_ipv4() {
    const uint64_t host_count = 1ULL << (32 - ipv4_prefix_);
    // Reserve network, gateway, DNS and .3; do not use the broadcast address.
    const uint64_t first = 4;
    const uint64_t limit = host_count - 1;
    if (limit <= first) return std::string();
    for (uint64_t attempts = 0; attempts < limit - first; ++attempts) {
        if (next_ipv4_ < first || next_ipv4_ >= limit) next_ipv4_ = static_cast<uint32_t>(first);
        const uint32_t host = next_ipv4_++;
        in_addr address;
        address.s_addr = htonl(ipv4_network_ + host);
        char text[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &address, text, sizeof(text)) &&
            reverse_.find(text) == reverse_.end()) {
            return text;
        }
    }
    return std::string();
}

std::string FakeIpDns::allocate_ipv6() {
    // The configured ranges retain at least 32 host bits. The cache cap makes
    // a bounded probe sufficient even after address reuse following expiry.
    for (size_t attempts = 0; attempts <= capacity_; ++attempts) {
        uint8_t bytes[16];
        std::memcpy(bytes, ipv6_prefix_, 16);
        if (next_ipv6_ < 4) next_ipv6_ = 4;
        const uint32_t value = next_ipv6_++;
        bytes[12] = static_cast<uint8_t>(value >> 24);
        bytes[13] = static_cast<uint8_t>(value >> 16);
        bytes[14] = static_cast<uint8_t>(value >> 8);
        bytes[15] = static_cast<uint8_t>(value);
        char text[INET6_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET6, bytes, text, sizeof(text)) &&
            reverse_.find(text) == reverse_.end()) {
            return text;
        }
    }
    return std::string();
}

void FakeIpDns::erase_mapping(std::unordered_map<std::string, Mapping>::iterator mapping) {
    if (mapping == forward_.end()) return;
    if (!mapping->second.ipv4.empty()) {
        auto reverse = reverse_.find(mapping->second.ipv4);
        if (reverse != reverse_.end() && reverse->second.domain == mapping->first)
            reverse_.erase(reverse);
    }
    if (!mapping->second.ipv6.empty()) {
        auto reverse = reverse_.find(mapping->second.ipv6);
        if (reverse != reverse_.end() && reverse->second.domain == mapping->first)
            reverse_.erase(reverse);
    }
    lru_.erase(mapping->second.lru_position);
    forward_.erase(mapping);
}

void FakeIpDns::expire_mappings(uint64_t now) {
    for (auto mapping = forward_.begin(); mapping != forward_.end();) {
        if (mapping->second.expires_at > now) {
            ++mapping;
            continue;
        }
        auto expired = mapping++;
        erase_mapping(expired);
    }
}

void FakeIpDns::touch_mapping(std::unordered_map<std::string, Mapping>::iterator mapping,
                              uint64_t now) {
    mapping->second.expires_at = now + mapping_ttl_;
    lru_.splice(lru_.end(), lru_, mapping->second.lru_position);
    mapping->second.lru_position = std::prev(lru_.end());
    if (!mapping->second.ipv4.empty())
        reverse_[mapping->second.ipv4] = ReverseMapping{mapping->first, mapping->second.expires_at};
    if (!mapping->second.ipv6.empty())
        reverse_[mapping->second.ipv6] = ReverseMapping{mapping->first, mapping->second.expires_at};
}

bool FakeIpDns::ensure_mapping_capacity(uint64_t now) {
    expire_mappings(now);
    while (forward_.size() >= capacity_) {
        if (lru_.empty()) return false;
        auto mapping = forward_.find(lru_.front());
        if (mapping == forward_.end()) {
            lru_.pop_front();
            continue;
        }
        erase_mapping(mapping);
    }
    return true;
}

bool FakeIpDns::respond(const uint8_t* query, size_t query_len,
                        std::vector<uint8_t>& response) {
    response.clear();
    if (!query) return false;
    if (query_len < 12) {
        response.assign(12, 0);
        if (query_len >= 2) {
            response[0] = query[0];
            response[1] = query[1];
        }
        store_be16(response.data() + 2, 0x8001);
        return true;
    }
    response.insert(response.end(), query, query + 12);
    const bool standard_query = (load_be16(query + 2) & 0x7800u) == 0;
    size_t pos = 12;
    std::string domain;
    bool valid = standard_query && load_be16(query + 4) == 1;
    while (valid && pos < query_len) {
        uint8_t label_len = query[pos++];
        if (label_len == 0) break;
        if ((label_len & 0xc0) || label_len > 63 || pos + label_len > query_len) {
            valid = false; break;
        }
        if (!domain.empty()) domain.push_back('.');
        domain.append(reinterpret_cast<const char*>(query + pos), label_len);
        pos += label_len;
        if (domain.size() > 253) valid = false;
    }
    if (pos + 4 > query_len) valid = false;
    uint16_t type = valid ? load_be16(query + pos) : 0;
    uint16_t klass = valid ? load_be16(query + pos + 2) : 0;
    if (valid) pos += 4;

    // Android treats VPN-provided DNS servers as recursive resolvers. Advertise
    // recursion availability (RA) and mirror the client's RD bit; an
    // authoritative-only response (AA without RA) can be rejected as unusable.
    uint16_t flags = static_cast<uint16_t>(0x8080u | (load_be16(query + 2) & 0x0100u));
    if (!valid) {
        flags |= 0x0001u;
        store_be16(response.data() + 2, flags);
        store_be16(response.data() + 4, 0);
        store_be16(response.data() + 6, 0);
        store_be16(response.data() + 8, 0);
        store_be16(response.data() + 10, 0);
        response.resize(12);
        return true;
    }
    response.assign(query, query + pos);
    domain = lower(domain);
    const bool local_type = type == 1 || type == 28 || type == 64 || type == 65;
    if (klass == 1 && !local_type) {
        response.clear();
        return false;
    }
    bool answer = klass == 1 && (type == 1 || type == 28);
    std::string address;
    if (answer) {
        const uint64_t now = now_seconds();
        expire_mappings(now);
        auto mapping_it = forward_.find(domain);
        if (mapping_it == forward_.end()) {
            if (!ensure_mapping_capacity(now)) {
                answer = false;
            } else {
                lru_.push_back(domain);
                Mapping mapping;
                mapping.expires_at = now + mapping_ttl_;
                mapping.lru_position = std::prev(lru_.end());
                mapping_it = forward_.emplace(domain, std::move(mapping)).first;
            }
        } else {
            touch_mapping(mapping_it, now);
        }
        if (!answer) {
            // Cache capacity is exhausted; return a valid empty DNS answer.
        } else {
        Mapping& mapping = mapping_it->second;
        address = type == 1 ? mapping.ipv4 : mapping.ipv6;
        if (address.empty()) {
            address = type == 1 ? allocate_ipv4() : allocate_ipv6();
            if (type == 1) mapping.ipv4 = address; else mapping.ipv6 = address;
            if (!address.empty()) {
                reverse_[address] = ReverseMapping{domain, mapping.expires_at};
            }
        }
        answer = !address.empty();
        }
    }
    store_be16(response.data() + 2, flags);
    store_be16(response.data() + 4, 1);
    store_be16(response.data() + 6, answer ? 1 : 0);
    store_be16(response.data() + 8, 0);
    store_be16(response.data() + 10, 0);
    if (!answer) return true;

    append_u16(response, 0xc00c);
    append_u16(response, type);
    append_u16(response, 1);
    append_u32(response, dns_ttl_);
    uint8_t wire[16];
    const int family = type == 1 ? AF_INET : AF_INET6;
    const uint16_t wire_len = type == 1 ? 4 : 16;
    append_u16(response, wire_len);
    if (inet_pton(family, address.c_str(), wire) != 1) return false;
    response.insert(response.end(), wire, wire + wire_len);
    return true;
}

bool FakeIpDns::reverse_lookup(const std::string& address, std::string& domain) {
    const uint64_t now = now_seconds();
    expire_mappings(now);
    auto it = reverse_.find(address);
    if (it == reverse_.end()) return false;
    auto mapping = forward_.find(it->second.domain);
    if (mapping == forward_.end()) return false;
    touch_mapping(mapping, now);
    domain = mapping->first;
    return true;
}

bool FakeIpDns::contains_address(const std::string& address) const {
    in_addr address4;
    if (inet_pton(AF_INET, address.c_str(), &address4) == 1) {
        const uint32_t value = ntohl(address4.s_addr);
        const uint32_t mask = ipv4_prefix_ == 0 ? 0 :
            0xffffffffu << (32 - ipv4_prefix_);
        return (value & mask) == ipv4_network_;
    }

    in6_addr address6;
    if (inet_pton(AF_INET6, address.c_str(), &address6) != 1) return false;
    const uint8_t* value = reinterpret_cast<const uint8_t*>(&address6);
    const size_t full_bytes = ipv6_prefix_bits_ / 8;
    const uint8_t partial_bits = static_cast<uint8_t>(ipv6_prefix_bits_ % 8);
    if (full_bytes && std::memcmp(value, ipv6_prefix_, full_bytes) != 0) return false;
    if (!partial_bits) return true;
    const uint8_t mask = static_cast<uint8_t>(0xffu << (8 - partial_bits));
    return (value[full_bytes] & mask) == (ipv6_prefix_[full_bytes] & mask);
}

} // namespace tx
