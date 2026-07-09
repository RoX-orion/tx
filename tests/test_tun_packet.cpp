#include "tx/net/tun_packet.h"

#include <cassert>
#include <cstdio>
#include <cstring>

static void test_ipv4_udp_roundtrip() {
    printf("  test_ipv4_udp_roundtrip... ");
    tx::IpAddr src = tx::IpAddr::from_ipv4(8, 8, 8, 8);
    tx::IpAddr dst = tx::IpAddr::from_ipv4(10, 0, 0, 2);
    const uint8_t payload[] = {'o', 'k'};

    tx::Buffer packet;
    assert(tx::build_udp_tun_packet(src, 53, dst, 53000,
                                    payload, sizeof(payload), packet));

    tx::TunPacketView view;
    assert(tx::parse_tun_packet(packet.data(), packet.readable(), view));
    assert(!view.ipv6);
    assert(view.protocol == tx::TunL4Protocol::Udp);
    assert(view.src_ip.to_string() == "8.8.8.8:53");
    assert(view.dst_ip.to_string() == "10.0.0.2:53000");
    assert(view.payload_len == sizeof(payload));
    assert(memcmp(view.payload, payload, sizeof(payload)) == 0);
    printf("OK\n");
}

static void test_ipv6_udp_roundtrip() {
    printf("  test_ipv6_udp_roundtrip... ");
    uint8_t src6[16] = {0x20, 0x01, 0x48, 0x60};
    src6[15] = 0x88;
    uint8_t dst6[16] = {0xfd};
    dst6[15] = 0x02;
    tx::IpAddr src = tx::IpAddr::from_ipv6(src6);
    tx::IpAddr dst = tx::IpAddr::from_ipv6(dst6);
    const uint8_t payload[] = {1, 2, 3, 4};

    tx::Buffer packet;
    assert(tx::build_udp_tun_packet(src, 443, dst, 53001,
                                    payload, sizeof(payload), packet));

    tx::TunPacketView view;
    assert(tx::parse_tun_packet(packet.data(), packet.readable(), view));
    assert(view.ipv6);
    assert(view.protocol == tx::TunL4Protocol::Udp);
    assert(view.src_port == 443);
    assert(view.dst_port == 53001);
    assert(view.payload_len == sizeof(payload));
    assert(memcmp(view.payload, payload, sizeof(payload)) == 0);
    printf("OK\n");
}

int main() {
    printf("=== TUN Packet Tests ===\n");
    test_ipv4_udp_roundtrip();
    test_ipv6_udp_roundtrip();
    printf("All TUN packet tests passed!\n");
    return 0;
}
