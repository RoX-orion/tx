#include "tx/net/fake_ip_dns.h"
#include "tx/common/endian.h"

#include <algorithm>
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
    char* end = nullptr;
    prefix = std::strtol(cidr.substr(slash + 1).c_str(), &end, 10);
    return end && *end == '\0';
}
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!value.empty() && value.back() == '.') value.pop_back();
    return value;
}

} // namespace

FakeIpDns::FakeIpDns() {
    std::string error;
    configure("198.18.0.0/16", "fd00:198:18::/96", 60, error);
}

bool FakeIpDns::configure(const std::string& ipv4_range,
                          const std::string& ipv6_range,
                          uint32_t ttl_seconds,
                          std::string& error) {
    std::string host;
    long prefix = 0;
    in_addr address4;
    if (!parse_prefix(ipv4_range, host, prefix) || prefix < 8 || prefix > 30 ||
        inet_pton(AF_INET, host.c_str(), &address4) != 1) {
        error = "dns.fake_ipv4_range must be an IPv4 CIDR with prefix /8 through /30";
        return false;
    }
    in6_addr address6;
    long prefix6 = 0;
    if (!parse_prefix(ipv6_range, host, prefix6) || prefix6 < 32 || prefix6 > 96 ||
        inet_pton(AF_INET6, host.c_str(), &address6) != 1) {
        error = "dns.fake_ipv6_range must be an IPv6 CIDR with prefix /32 through /96";
        return false;
    }
    ipv4_prefix_ = static_cast<uint8_t>(prefix);
    const uint32_t mask = prefix == 0 ? 0 : 0xffffffffu << (32 - prefix);
    ipv4_network_ = ntohl(address4.s_addr) & mask;
    std::memcpy(ipv6_prefix_, &address6, 16);
    ipv6_prefix_bits_ = static_cast<uint8_t>(prefix6);
    ttl_ = ttl_seconds ? ttl_seconds : 60;
    // The network address, TUN gateway (.1), DNS (.2), and .3 are reserved.
    next_ipv4_ = 4;
    next_ipv6_ = 4;
    forward_.clear();
    reverse_.clear();
    return true;
}

std::string FakeIpDns::allocate_ipv4() {
    const uint32_t capacity = (1u << (32 - ipv4_prefix_)) - 1;
    if (next_ipv4_ >= capacity) return std::string();
    in_addr address;
    address.s_addr = htonl(ipv4_network_ + next_ipv4_++);
    char text[INET_ADDRSTRLEN] = {};
    return inet_ntop(AF_INET, &address, text, sizeof(text)) ? text : std::string();
}

std::string FakeIpDns::allocate_ipv6() {
    uint8_t bytes[16];
    std::memcpy(bytes, ipv6_prefix_, 16);
    const uint32_t value = next_ipv6_++;
    bytes[12] = static_cast<uint8_t>(value >> 24);
    bytes[13] = static_cast<uint8_t>(value >> 16);
    bytes[14] = static_cast<uint8_t>(value >> 8);
    bytes[15] = static_cast<uint8_t>(value);
    char text[INET6_ADDRSTRLEN] = {};
    return inet_ntop(AF_INET6, bytes, text, sizeof(text)) ? text : std::string();
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
    response.resize(pos);
    domain = lower(domain);
    const bool local_type = type == 1 || type == 28 || type == 64 || type == 65;
    if (klass == 1 && !local_type) {
        response.clear();
        return false;
    }
    bool answer = klass == 1 && (type == 1 || type == 28);
    std::string address;
    if (answer) {
        Mapping& mapping = forward_[domain];
        address = type == 1 ? mapping.ipv4 : mapping.ipv6;
        if (address.empty()) {
            address = type == 1 ? allocate_ipv4() : allocate_ipv6();
            if (type == 1) mapping.ipv4 = address; else mapping.ipv6 = address;
            if (!address.empty()) reverse_[address] = domain;
        }
        answer = !address.empty();
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
    append_u32(response, ttl_);
    uint8_t wire[16];
    const int family = type == 1 ? AF_INET : AF_INET6;
    const uint16_t wire_len = type == 1 ? 4 : 16;
    append_u16(response, wire_len);
    if (inet_pton(family, address.c_str(), wire) != 1) return false;
    response.insert(response.end(), wire, wire + wire_len);
    return true;
}

bool FakeIpDns::reverse_lookup(const std::string& address, std::string& domain) const {
    auto it = reverse_.find(address);
    if (it == reverse_.end()) return false;
    domain = it->second;
    return true;
}

} // namespace tx
