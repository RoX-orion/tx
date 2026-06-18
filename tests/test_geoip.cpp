#include "tx/geo/radix_tree.h"
#include "tx/common/log.h"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <arpa/inet.h>

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

int main() {
    printf("=== GeoIP Tests ===\n");
    test_ipv4_insert_lookup();
    test_longest_prefix();
    test_match_country();
    test_ipv6();
    printf("All GeoIP tests passed!\n");
    return 0;
}
