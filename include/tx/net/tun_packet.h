#pragma once

#include "tx/common/types.h"
#include "tx/net/buffer.h"

#include <cstddef>
#include <cstdint>

namespace tx {

enum class TunL4Protocol : uint8_t {
    Tcp = 6,
    Udp = 17,
};

struct TunPacketView {
    IpAddr src_ip;
    IpAddr dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    TunL4Protocol protocol = TunL4Protocol::Tcp;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    const uint8_t* l4_header = nullptr;
    size_t l4_header_len = 0;
    bool ipv6 = false;
};

bool parse_tun_packet(const uint8_t* data, size_t len, TunPacketView& out);

bool build_udp_tun_packet(const IpAddr& src_ip, uint16_t src_port,
                          const IpAddr& dst_ip, uint16_t dst_port,
                          const uint8_t* payload, size_t payload_len,
                          Buffer& out);

} // namespace tx
