#include "tx/net/lwip_udp_stack.h"
#include "tx/net/tun_packet.h"

#include "lwip/ip6_frag.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int main() {
    tx::LwipUdpStack stack;
    std::string error;
    uint64_t flow_id = 0;
    tx::IpAddr received_source;
    tx::IpAddr received_destination;
    std::vector<uint8_t> received_payload;
    std::vector<uint8_t> output_packet;

    assert(stack.initialize(
        "10.10.0.1/24", 1500,
        [&](uint64_t id, const tx::IpAddr& source, const tx::IpAddr& destination,
            const uint8_t* payload, size_t payload_len) {
            flow_id = id;
            received_source = source;
            received_destination = destination;
            received_payload.assign(payload, payload + payload_len);
        },
        [&](const uint8_t* packet, size_t packet_len) {
            output_packet.assign(packet, packet + packet_len);
            return true;
        }, error));

    tx::LwipUdpStack competing_stack;
    std::string competing_error;
    assert(!competing_stack.initialize(
        "10.11.0.1/24", 1500,
        [](uint64_t, const tx::IpAddr&, const tx::IpAddr&, const uint8_t*, size_t) {},
        [](const uint8_t*, size_t) { return true; }, competing_error));
    assert(!competing_error.empty());

    // Exercise the timer callback directly. On 64-bit platforms this aborts
    // unless lwIP preserves the IPv6 fragment header during reassembly.
    ip6_reass_tmr();

    const tx::IpAddr client = tx::IpAddr::from_ipv4(10, 10, 0, 2);
    const tx::IpAddr target = tx::IpAddr::from_ipv4(8, 8, 8, 8);
    const uint8_t query[] = {0x12, 0x34, 0x01, 0x00};
    tx::Buffer input_packet;
    assert(tx::build_udp_tun_packet(client, 53000, target, 53,
                                    query, sizeof(query), input_packet));
    assert(stack.input(input_packet.data(), input_packet.readable()));
    assert(flow_id != 0);
    assert(received_source == tx::IpAddr::from_ipv4(10, 10, 0, 2, 53000));
    assert(received_destination == tx::IpAddr::from_ipv4(8, 8, 8, 8, 53));
    assert(received_payload.size() == sizeof(query));
    assert(std::memcmp(received_payload.data(), query, sizeof(query)) == 0);
    const uint64_t ipv4_flow_id = flow_id;

    const uint8_t response[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01};
    assert(stack.send_response(flow_id, received_destination,
                               response, sizeof(response)));
    assert(!output_packet.empty());

    tx::TunPacketView output;
    assert(tx::parse_tun_packet(output_packet.data(), output_packet.size(), output));
    assert(output.protocol == tx::TunL4Protocol::Udp);
    assert(output.src_ip == tx::IpAddr::from_ipv4(8, 8, 8, 8, 53));
    assert(output.dst_ip == tx::IpAddr::from_ipv4(10, 10, 0, 2, 53000));
    assert(output.payload_len == sizeof(response));
    assert(std::memcmp(output.payload, response, sizeof(response)) == 0);

    const uint8_t client6_bytes[16] =
        {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const uint8_t target6_bytes[16] =
        {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88};
    const tx::IpAddr client6 = tx::IpAddr::from_ipv6(client6_bytes);
    const tx::IpAddr target6 = tx::IpAddr::from_ipv6(target6_bytes);
    tx::Buffer input_packet6;
    assert(tx::build_udp_tun_packet(client6, 53001, target6, 53,
                                    query, sizeof(query), input_packet6));
    assert(stack.input(input_packet6.data(), input_packet6.readable()));
    assert(flow_id != 0 && flow_id != ipv4_flow_id);
    assert(received_source == tx::IpAddr::from_ipv6(client6_bytes, 53001));
    assert(received_destination == tx::IpAddr::from_ipv6(target6_bytes, 53));

    output_packet.clear();
    assert(stack.send_response(flow_id, received_destination,
                               response, sizeof(response)));
    assert(tx::parse_tun_packet(output_packet.data(), output_packet.size(), output));
    assert(output.src_ip == tx::IpAddr::from_ipv6(target6_bytes, 53));
    assert(output.dst_ip == tx::IpAddr::from_ipv6(client6_bytes, 53001));

    std::vector<uint8_t> tcp_packet(input_packet.data(),
                                    input_packet.data() + input_packet.readable());
    tcp_packet[9] = 6;
    // The unified frontend now owns both TCP and UDP packets.
    assert(stack.input(tcp_packet.data(), tcp_packet.size()));

    stack.close_flow(ipv4_flow_id);
    stack.close_flow(flow_id);
    assert(!stack.send_response(flow_id, received_destination,
                                response, sizeof(response)));
    stack.shutdown();
    assert(competing_stack.initialize(
        "10.11.0.1/24", 1500,
        [](uint64_t, const tx::IpAddr&, const tx::IpAddr&, const uint8_t*, size_t) {},
        [](const uint8_t*, size_t) { return true; }, competing_error));
    competing_stack.shutdown();
    std::printf("HEV lwIP UDP stack tests passed\n");
    return 0;
}
