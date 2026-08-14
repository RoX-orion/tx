#include "tx/geo/radix_tree.h"
#include "tx/geo/geoip.h"
#include "tx/common/log.h"
#include "tx/common/network.h"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <fstream>
#include <string>
#include <vector>

static void append_varint(std::vector<uint8_t>& out, uint64_t value) {
    while (value >= 0x80) {
        out.push_back(static_cast<uint8_t>(value | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

static void append_bytes(std::vector<uint8_t>& out, uint32_t field,
                         const uint8_t* data, size_t len) {
    append_varint(out, (field << 3) | 2);
    append_varint(out, len);
    out.insert(out.end(), data, data + len);
}

static void append_message(std::vector<uint8_t>& out, uint32_t field,
                           const std::vector<uint8_t>& message) {
    append_bytes(out, field, message.data(), message.size());
}

static std::vector<uint8_t> geoip_entry(const std::string& tag,
                                        const uint8_t* ip, size_t len,
                                        uint64_t prefix) {
    std::vector<uint8_t> cidr;
    append_bytes(cidr, 1, ip, len);
    append_varint(cidr, 2 << 3);
    append_varint(cidr, prefix);
    std::vector<uint8_t> entry;
    append_bytes(entry, 1, reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
    append_message(entry, 2, cidr);
    return entry;
}

static bool load_geoip(const char* suffix, const std::vector<uint8_t>& data,
                       tx::GeoIpMatcher& matcher) {
    const std::string path = std::string("/tmp/tx_test_geoip_") + suffix + ".dat";
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    const bool result = matcher.load(path);
    std::remove(path.c_str());
    return result;
}

static void test_ipv4_insert_lookup() {
    printf("  test_ipv4_insert_lookup... ");
    tx::RadixTree tree;

    // Insert 192.168.0.0/16
    struct in_addr addr;
    inet_pton(AF_INET, "192.168.0.0", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 16, "lan", false);

    // Insert 10.0.0.0/8
    inet_pton(AF_INET, "10.0.0.0", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 8, "private", false);

    // Insert 1.2.3.0/24
    inet_pton(AF_INET, "1.2.3.0", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 24, "cn", false);

    // Lookup
    inet_pton(AF_INET, "192.168.1.1", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), false) == "lan");

    inet_pton(AF_INET, "10.1.2.3", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), false) == "private");

    inet_pton(AF_INET, "1.2.3.4", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), false) == "cn");

    // Non-matching
    inet_pton(AF_INET, "8.8.8.8", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), false).empty());

    printf("OK\n");
}

static void test_longest_prefix() {
    printf("  test_longest_prefix... ");
    tx::RadixTree tree;

    struct in_addr addr;
    inet_pton(AF_INET, "1.0.0.0", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 8, "broad", false);

    inet_pton(AF_INET, "1.2.0.0", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 16, "medium", false);

    inet_pton(AF_INET, "1.2.3.0", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 24, "narrow", false);

    // Should match narrowest prefix
    inet_pton(AF_INET, "1.2.3.4", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), false) == "narrow");

    inet_pton(AF_INET, "1.2.5.6", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), false) == "medium");

    inet_pton(AF_INET, "1.5.6.7", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), false) == "broad");

    printf("OK\n");
}

static void test_match_country() {
    printf("  test_match_country... ");
    tx::RadixTree tree;

    struct in_addr addr;
    inet_pton(AF_INET, "1.2.3.0", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 24, "cn", false);

    inet_pton(AF_INET, "1.2.3.4", &addr);
    assert(tree.match(reinterpret_cast<const uint8_t*>(&addr), false, "cn"));
    assert(!tree.match(reinterpret_cast<const uint8_t*>(&addr), false, "us"));

    printf("OK\n");
}

static void test_ipv6() {
    printf("  test_ipv6... ");
    tx::RadixTree tree;

    struct in6_addr addr;
    inet_pton(AF_INET6, "2001:db8::", &addr);
    tree.insert(reinterpret_cast<const uint8_t*>(&addr), 32, "cn", true);

    inet_pton(AF_INET6, "2001:db8::1", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), true) == "cn");

    inet_pton(AF_INET6, "2001:db9::1", &addr);
    assert(tree.lookup(reinterpret_cast<const uint8_t*>(&addr), true).empty());

    printf("OK\n");
}

static void test_geoip_file_boundaries_and_duplicate_tags() {
    const uint8_t any[4] = {0, 0, 0, 0};
    const uint8_t documentation_net[4] = {203, 0, 113, 0};
    std::vector<uint8_t> list;
    append_message(list, 1, geoip_entry("FIRST", any, sizeof(any), 0));
    append_message(list, 1, geoip_entry("SECOND", documentation_net,
                                        sizeof(documentation_net), 24));
    append_message(list, 1, geoip_entry("THIRD", documentation_net,
                                        sizeof(documentation_net), 24));
    tx::GeoIpMatcher matcher;
    assert(load_geoip("zero", list, matcher));
    tx::IpAddr address;
    assert(tx::IpAddr::parse("203.0.113.9", 0, address));
    assert(matcher.match(address, "first"));
    assert(matcher.match(address, "second"));
    assert(matcher.match(address, "third"));
    // Public matcher lookup is stable by source-file tag order even when a
    // later tag has a more-specific prefix. RadixTree::lookup itself retains
    // longest-prefix semantics for callers that need it.
    assert(matcher.lookup(address) == "first");

    for (uint64_t prefix : {uint64_t(256), uint64_t(257)}) {
        std::vector<uint8_t> invalid;
        append_message(invalid, 1, geoip_entry("BAD", any, sizeof(any), prefix));
        tx::GeoIpMatcher rejected;
        assert(!load_geoip(prefix == 256 ? "prefix256" : "prefix257",
                           invalid, rejected));
    }
    tx::GeoIpMatcher malformed;
    assert(!load_geoip("length", {0x0a, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0x01}, malformed));
}

int main() {
    printf("=== GeoIP Tests ===\n");
    test_ipv4_insert_lookup();
    test_longest_prefix();
    test_match_country();
    test_ipv6();
    test_geoip_file_boundaries_and_duplicate_tags();
    printf("All GeoIP tests passed!\n");
    return 0;
}
