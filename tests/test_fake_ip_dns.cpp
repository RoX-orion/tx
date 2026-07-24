#include "tx/net/fake_ip_dns.h"
#include "tx/common/endian.h"

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

static std::vector<uint8_t> query(uint16_t type, const char* label = "example") {
    std::vector<uint8_t> q(12, 0);
    tx::store_be16(q.data(), 0x1234);
    tx::store_be16(q.data() + 2, 0x0100);
    tx::store_be16(q.data() + 4, 1);
    const size_t label_len = std::strlen(label);
    assert(label_len > 0 && label_len <= 63);
    q.push_back(static_cast<uint8_t>(label_len));
    q.insert(q.end(), label, label + label_len);
    q.push_back(3); q.insert(q.end(), {'c','o','m'});
    q.push_back(0);
    q.push_back(static_cast<uint8_t>(type >> 8)); q.push_back(static_cast<uint8_t>(type));
    q.push_back(0); q.push_back(1);
    return q;
}

int main() {
    tx::FakeIpDns dns;
    std::vector<uint8_t> response;
    auto a = query(1);
    assert(dns.respond(a.data(), a.size(), response));
    assert(tx::load_be16(response.data()) == 0x1234);
    assert((tx::load_be16(response.data() + 2) & 0x0080) != 0);
    assert((tx::load_be16(response.data() + 2) & 0x0400) == 0);
    assert(tx::load_be16(response.data() + 6) == 1);
    assert(response.size() >= 4);
    const uint8_t* ipv4 = response.data() + response.size() - 4;
    char address[32];
    std::snprintf(address, sizeof(address), "%u.%u.%u.%u",
                  ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
    std::string domain;
    assert(dns.reverse_lookup(address, domain));
    assert(domain == "example.com");

    assert(std::string(address) == "198.18.0.4");

    auto aaaa = query(28);
    assert(dns.respond(aaaa.data(), aaaa.size(), response));
    assert(tx::load_be16(response.data() + 6) == 1);

    auto https = query(65);
    assert(dns.respond(https.data(), https.size(), response));
    assert(tx::load_be16(response.data() + 6) == 0);
    auto txt = query(16);
    assert(!dns.respond(txt.data(), txt.size(), response));

    uint8_t malformed[] = {0x42, 0x42, 0};
    assert(dns.respond(malformed, sizeof(malformed), response));
    assert((tx::load_be16(response.data() + 2) & 0x000f) == 1);

    std::string error;
    assert(!dns.configure("198.18.0.0/30", "fd00:198:18::/96", 60, error));
    assert(!error.empty());
    assert(dns.configure("198.18.0.0/16", "fd00:198:18::/96", 60, error, 1));
    auto first = query(1, "first");
    assert(dns.respond(first.data(), first.size(), response));
    std::string first_address = std::to_string(response[response.size() - 4]) + "." +
        std::to_string(response[response.size() - 3]) + "." +
        std::to_string(response[response.size() - 2]) + "." +
        std::to_string(response[response.size() - 1]);
    auto second = query(1, "second");
    assert(dns.respond(second.data(), second.size(), response));
    assert(!dns.reverse_lookup(first_address, domain));
    assert(dns.mapping_count() == 1);
    std::printf("fake ip dns tests passed\n");
    return 0;
}
