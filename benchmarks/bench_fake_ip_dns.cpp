#include "tx/common/endian.h"
#include "tx/net/fake_ip_dns.h"

#include <uv.h>
#include <cstdio>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> query(const std::string& label) {
    std::vector<uint8_t> out(12, 0);
    tx::store_be16(out.data() + 2, 0x0100);
    tx::store_be16(out.data() + 4, 1);
    out.push_back(static_cast<uint8_t>(label.size()));
    out.insert(out.end(), label.begin(), label.end());
    out.insert(out.end(), {3, 'c', 'o', 'm', 0, 0, 1, 0, 1});
    return out;
}

} // namespace

int main() {
    tx::FakeIpDns dns;
    std::string error;
    if (!dns.configure("198.18.0.0/16", "fd00:198:18::/96", 60,
                       error, 4096, 1800)) return 1;
    std::vector<uint8_t> response;
    for (size_t i = 0; i < 4096; ++i) {
        const auto q = query("d" + std::to_string(i));
        if (!dns.respond(q.data(), q.size(), response)) return 1;
    }

    constexpr size_t iterations = 1000000;
    const std::string missing = "203.0.113.1";
    std::string domain;
    size_t hits = 0;
    const uint64_t start = uv_hrtime();
    for (size_t i = 0; i < iterations; ++i) {
        hits += dns.reverse_lookup(missing, domain) ? 1u : 0u;
    }
    const uint64_t elapsed = uv_hrtime() - start;
    std::printf("fake_ip_reverse_miss cache=4096 iterations=%zu ns/op=%.2f hits=%zu\n",
                iterations, static_cast<double>(elapsed) / iterations, hits);
    return hits == 0 ? 0 : 1;
}
