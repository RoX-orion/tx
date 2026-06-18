#include "tx/router/router.h"
#include "tx/common/log.h"

#include <cstdio>
#include <cassert>

// Note: Router tests that require geoip.dat/geosite.dat files
// are integration tests. Here we test the routing logic with
// in-memory data.

static void test_lan_detection() {
    printf("  test_lan_detection... ");
    tx::Router router;

    // LAN IPs should always be direct
    tx::IpAddr lan1 = tx::IpAddr::from_ipv4(192, 168, 1, 1);
    assert(lan1.is_lan());
    assert(router.decide_by_ip(lan1) == tx::RouteAction::Direct);

    tx::IpAddr lan2 = tx::IpAddr::from_ipv4(10, 0, 0, 1);
    assert(lan2.is_lan());
    assert(router.decide_by_ip(lan2) == tx::RouteAction::Direct);

    tx::IpAddr lan3 = tx::IpAddr::from_ipv4(172, 16, 0, 1);
    assert(lan3.is_lan());

    tx::IpAddr loopback = tx::IpAddr::from_ipv4(127, 0, 0, 1);
    assert(loopback.is_loopback());
    assert(loopback.is_lan());

    printf("OK\n");
}

static void test_public_ip() {
    printf("  test_public_ip... ");
    tx::Router router;

    // Without geo data loaded, public IPs default to proxy
    tx::IpAddr pub = tx::IpAddr::from_ipv4(8, 8, 8, 8);
    assert(!pub.is_lan());
    assert(!pub.is_loopback());
    assert(router.decide_by_ip(pub) == tx::RouteAction::Proxy);

    printf("OK\n");
}

static void test_host_routing() {
    printf("  test_host_routing... ");
    tx::Router router;

    // Without geosite data, host-based routing defaults to proxy
    assert(router.decide_by_host("example.com") == tx::RouteAction::Proxy);

    printf("OK\n");
}

int main() {
    printf("=== Router Tests ===\n");
    test_lan_detection();
    test_public_ip();
    test_host_routing();
    printf("All router tests passed!\n");
    return 0;
}
