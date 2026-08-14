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
    tx::RouterConfig config;
    tx::RouteRule private_rule;
    private_rule.ips.push_back("geoip:private");
    private_rule.outbound_tag = "direct-out";
    tx::RouteRule fallback;
    fallback.outbound_tag = "proxy-out";
    config.rules.push_back(private_rule);
    config.rules.push_back(fallback);
    router.load(config);

    // LAN IPs should always be direct
    tx::IpAddr lan1 = tx::IpAddr::from_ipv4(192, 168, 1, 1);
    assert(lan1.is_lan());
    assert(router.decide_by_ip(lan1).outbound_tag == "direct-out");

    tx::IpAddr lan2 = tx::IpAddr::from_ipv4(10, 0, 0, 1);
    assert(lan2.is_lan());
    assert(router.decide_by_ip(lan2).outbound_tag == "direct-out");

    tx::IpAddr lan3 = tx::IpAddr::from_ipv4(172, 16, 0, 1);
    assert(lan3.is_lan());

    tx::IpAddr loopback = tx::IpAddr::from_ipv4(127, 0, 0, 1);
    assert(loopback.is_loopback());
    assert(loopback.is_lan());

    const char* private_v4[] = {"0.1.2.3", "100.64.0.1", "169.254.2.3",
                                "198.18.1.1", "224.0.0.1", "255.255.255.255"};
    for (const char* text : private_v4) {
        tx::IpAddr address;
        assert(tx::IpAddr::parse(text, 0, address));
        assert(router.decide_by_ip(address).outbound_tag == "direct-out");
    }
    const char* private_v6[] = {"::", "::1", "fc00::1", "fe80::1", "ff02::1"};
    for (const char* text : private_v6) {
        tx::IpAddr address;
        assert(tx::IpAddr::parse(text, 0, address));
        assert(router.decide_by_ip(address).outbound_tag == "direct-out");
    }

    printf("OK\n");
}

static void test_public_ip() {
    printf("  test_public_ip... ");
    tx::Router router;
    tx::RouterConfig config;
    tx::RouteRule fallback;
    fallback.outbound_tag = "proxy-out";
    config.rules.push_back(fallback);
    router.load(config);

    // Without geo data loaded, public IPs default to proxy
    tx::IpAddr pub = tx::IpAddr::from_ipv4(8, 8, 8, 8);
    assert(!pub.is_lan());
    assert(!pub.is_loopback());
    assert(router.decide_by_ip(pub).outbound_tag == "proxy-out");

    printf("OK\n");
}

static void test_host_routing() {
    printf("  test_host_routing... ");
    tx::Router router;
    tx::RouterConfig config;
    tx::RouteRule direct_domain;
    direct_domain.domains.push_back("example.cn");
    direct_domain.outbound_tag = "direct-out";
    tx::RouteRule blocked_domain;
    blocked_domain.domains.push_back("blocked.example");
    blocked_domain.outbound_tag = "block";
    tx::RouteRule private_ip;
    private_ip.ips.push_back("geoip:private");
    private_ip.outbound_tag = "direct-out";
    tx::RouteRule fallback;
    fallback.outbound_tag = "proxy-out";
    config.rules.push_back(direct_domain);
    config.rules.push_back(blocked_domain);
    config.rules.push_back(private_ip);
    config.rules.push_back(fallback);
    assert(router.load(config));

    assert(router.decide_by_host("www.example.cn").outbound_tag == "direct-out");
    assert(router.decide_by_host("blocked.example").outbound_tag == "block");
    assert(!router.decide_by_host("example.com").matched);

    // AsIs must not re-route an unmatched domain through its resolved private IP.
    tx::TargetAddr unmatched_domain;
    unmatched_domain.type = tx::AddrType::Domain;
    unmatched_domain.host = "example.com";
    unmatched_domain.port = 443;
    assert(router.decide_target(unmatched_domain).outbound_tag == "proxy-out");
    assert(!router.decide_target(unmatched_domain).matched);

    tx::TargetAddr domain;
    domain.type = tx::AddrType::Domain;
    domain.host = "unmatched.example";
    domain.port = 443;
    const tx::RouteDecision domain_decision = router.decide_target(domain);
    assert(domain_decision.outbound_tag == "proxy-out");
    assert(!domain_decision.matched);

    domain.host = "blocked.example";
    const tx::RouteDecision block_decision = router.decide_target(domain);
    assert(block_decision.outbound_tag == "block");
    assert(block_decision.matched);

    tx::TargetAddr literal;
    literal.type = tx::AddrType::IPv4;
    literal.host = "192.168.1.2";
    literal.port = 443;
    assert(router.decide_target(literal).outbound_tag == "direct-out");

    printf("OK\n");
}

static void test_rejects_non_asis_strategy() {
    printf("  test_rejects_non_asis_strategy... ");
    tx::Router router;
    tx::RouterConfig config;
    config.domain_strategy = "IPIfNonMatch";
    tx::RouteRule fallback;
    fallback.outbound_tag = "proxy-out";
    config.rules.push_back(fallback);
    assert(!router.load(config));
    printf("OK\n");
}

static void test_geo_references_fail_closed() {
    tx::RouteRule fallback;
    fallback.outbound_tag = "proxy-out";

    tx::RouterConfig missing_file;
    missing_file.geosite_path = "/definitely/missing/geosite.dat";
    missing_file.rules.push_back(fallback);
    tx::Router router;
    assert(!router.load(missing_file));

    tx::RouterConfig missing_site_tag;
    tx::RouteRule site;
    site.domains.push_back("geosite:cn");
    site.outbound_tag = "direct-out";
    missing_site_tag.rules.push_back(site);
    missing_site_tag.rules.push_back(fallback);
    assert(!router.load(missing_site_tag));

    tx::RouterConfig missing_ip_tag;
    tx::RouteRule ip;
    ip.ips.push_back("geoip:cn");
    ip.outbound_tag = "direct-out";
    missing_ip_tag.rules.push_back(ip);
    missing_ip_tag.rules.push_back(fallback);
    assert(!router.load(missing_ip_tag));
}

int main() {
    printf("=== Router Tests ===\n");
    test_lan_detection();
    test_public_ip();
    test_host_routing();
    test_rejects_non_asis_strategy();
    test_geo_references_fail_closed();
    printf("All router tests passed!\n");
    return 0;
}
