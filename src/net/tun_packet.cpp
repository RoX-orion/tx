#include "tx/net/tun_packet.h"
#include "tx/common/endian.h"

#include <cstring>

namespace tx {

namespace {

uint32_t checksum_add(uint32_t sum, const uint8_t* data, size_t len) {
    while (len >= 2) {
        sum += load_be16(data);
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += static_cast<uint16_t>(data[0] << 8);
    }
    return sum;
}

uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

uint16_t internet_checksum(const uint8_t* data, size_t len) {
    return checksum_finish(checksum_add(0, data, len));
}

uint16_t udp_checksum_ipv4(const IpAddr& src, const IpAddr& dst,
                           const uint8_t* udp, size_t udp_len) {
    uint32_t sum = 0;
    sum = checksum_add(sum, src.data.v4, 4);
    sum = checksum_add(sum, dst.data.v4, 4);
    uint8_t pseudo[4] = {0, 17, 0, 0};
    store_be16(pseudo + 2, static_cast<uint16_t>(udp_len));
    sum = checksum_add(sum, pseudo, sizeof(pseudo));
    sum = checksum_add(sum, udp, udp_len);
    uint16_t result = checksum_finish(sum);
    return result == 0 ? 0xffff : result;
}

uint16_t udp_checksum_ipv6(const IpAddr& src, const IpAddr& dst,
                           const uint8_t* udp, size_t udp_len) {
    uint32_t sum = 0;
    sum = checksum_add(sum, src.data.v6, 16);
    sum = checksum_add(sum, dst.data.v6, 16);
    uint8_t pseudo[8] = {0};
    pseudo[0] = static_cast<uint8_t>((udp_len >> 24) & 0xff);
    pseudo[1] = static_cast<uint8_t>((udp_len >> 16) & 0xff);
    pseudo[2] = static_cast<uint8_t>((udp_len >> 8) & 0xff);
    pseudo[3] = static_cast<uint8_t>(udp_len & 0xff);
    pseudo[7] = 17;
    sum = checksum_add(sum, pseudo, sizeof(pseudo));
    sum = checksum_add(sum, udp, udp_len);
    uint16_t result = checksum_finish(sum);
    return result == 0 ? 0xffff : result;
}

} // namespace

bool parse_tun_packet(const uint8_t* data, size_t len, TunPacketView& out) {
    out = TunPacketView();
    if (!data || len < 1) return false;

    const uint8_t version = data[0] >> 4;
    if (version == 4) {
        if (len < 20) return false;
        const size_t ihl = (data[0] & 0x0f) * 4u;
        if (ihl < 20 || len < ihl) return false;

        const uint16_t total_len = load_be16(data + 2);
        if (total_len < ihl || total_len > len) return false;

        const uint16_t frag = load_be16(data + 6);
        if ((frag & 0x3fffu) != 0) return false;

        const uint8_t proto = data[9];
        if (proto != static_cast<uint8_t>(TunL4Protocol::Tcp) &&
            proto != static_cast<uint8_t>(TunL4Protocol::Udp)) {
            return false;
        }

        out.src_ip = IpAddr::from_ipv4(data[12], data[13], data[14], data[15]);
        out.dst_ip = IpAddr::from_ipv4(data[16], data[17], data[18], data[19]);
        out.protocol = static_cast<TunL4Protocol>(proto);
        out.ipv6 = false;

        const uint8_t* l4 = data + ihl;
        const size_t l4_len = total_len - ihl;
        if (proto == static_cast<uint8_t>(TunL4Protocol::Udp)) {
            if (l4_len < 8) return false;
            const uint16_t udp_len = load_be16(l4 + 4);
            if (udp_len < 8 || udp_len > l4_len) return false;
            out.src_port = load_be16(l4);
            out.dst_port = load_be16(l4 + 2);
            out.l4_header = l4;
            out.l4_header_len = 8;
            out.payload = l4 + 8;
            out.payload_len = udp_len - 8;
            out.src_ip.port = out.src_port;
            out.dst_ip.port = out.dst_port;
            return true;
        }

        if (l4_len < 20) return false;
        const size_t tcp_header_len = ((l4[12] >> 4) & 0x0f) * 4u;
        if (tcp_header_len < 20 || tcp_header_len > l4_len) return false;
        out.src_port = load_be16(l4);
        out.dst_port = load_be16(l4 + 2);
        out.l4_header = l4;
        out.l4_header_len = tcp_header_len;
        out.payload = l4 + tcp_header_len;
        out.payload_len = l4_len - tcp_header_len;
        out.src_ip.port = out.src_port;
        out.dst_ip.port = out.dst_port;
        return true;
    }

    if (version == 6) {
        if (len < 40) return false;
        const uint16_t payload_len = load_be16(data + 4);
        if (40u + payload_len > len) return false;

        const uint8_t proto = data[6];
        if (proto != static_cast<uint8_t>(TunL4Protocol::Tcp) &&
            proto != static_cast<uint8_t>(TunL4Protocol::Udp)) {
            return false;
        }

        out.src_ip = IpAddr::from_ipv6(data + 8);
        out.dst_ip = IpAddr::from_ipv6(data + 24);
        out.protocol = static_cast<TunL4Protocol>(proto);
        out.ipv6 = true;

        const uint8_t* l4 = data + 40;
        const size_t l4_len = payload_len;
        if (proto == static_cast<uint8_t>(TunL4Protocol::Udp)) {
            if (l4_len < 8) return false;
            const uint16_t udp_len = load_be16(l4 + 4);
            if (udp_len < 8 || udp_len > l4_len) return false;
            out.src_port = load_be16(l4);
            out.dst_port = load_be16(l4 + 2);
            out.l4_header = l4;
            out.l4_header_len = 8;
            out.payload = l4 + 8;
            out.payload_len = udp_len - 8;
        } else {
            if (l4_len < 20) return false;
            const size_t tcp_header_len = ((l4[12] >> 4) & 0x0f) * 4u;
            if (tcp_header_len < 20 || tcp_header_len > l4_len) return false;
            out.src_port = load_be16(l4);
            out.dst_port = load_be16(l4 + 2);
            out.l4_header = l4;
            out.l4_header_len = tcp_header_len;
            out.payload = l4 + tcp_header_len;
            out.payload_len = l4_len - tcp_header_len;
        }
        out.src_ip.port = out.src_port;
        out.dst_ip.port = out.dst_port;
        return true;
    }

    return false;
}

bool build_udp_tun_packet(const IpAddr& src_ip, uint16_t src_port,
                          const IpAddr& dst_ip, uint16_t dst_port,
                          const uint8_t* payload, size_t payload_len,
                          Buffer& out) {
    if (src_ip.family != dst_ip.family) return false;
    if (payload_len > 65507) return false;
    out.clear();

    const size_t udp_len = 8 + payload_len;
    if (src_ip.family == IpAddr::IPv4) {
        const size_t ip_len = 20 + udp_len;
        if (ip_len > 65535) return false;
        uint8_t header[28] = {0};
        header[0] = 0x45;
        store_be16(header + 2, static_cast<uint16_t>(ip_len));
        header[8] = 64;
        header[9] = 17;
        memcpy(header + 12, src_ip.data.v4, 4);
        memcpy(header + 16, dst_ip.data.v4, 4);
        store_be16(header + 10, internet_checksum(header, 20));
        store_be16(header + 20, src_port);
        store_be16(header + 22, dst_port);
        store_be16(header + 24, static_cast<uint16_t>(udp_len));
        out.append(header, sizeof(header));
        if (payload_len > 0) out.append(payload, payload_len);

        Buffer checksum_buf;
        checksum_buf.append(out.data() + 20, udp_len);
        const uint16_t csum = udp_checksum_ipv4(src_ip, dst_ip,
                                                checksum_buf.data(), checksum_buf.readable());
        uint8_t* writable = const_cast<uint8_t*>(out.data());
        store_be16(writable + 26, csum);
        return true;
    }

    const size_t ip_payload_len = udp_len;
    if (ip_payload_len > 65535) return false;
    uint8_t header[48] = {0};
    header[0] = 0x60;
    store_be16(header + 4, static_cast<uint16_t>(ip_payload_len));
    header[6] = 17;
    header[7] = 64;
    memcpy(header + 8, src_ip.data.v6, 16);
    memcpy(header + 24, dst_ip.data.v6, 16);
    store_be16(header + 40, src_port);
    store_be16(header + 42, dst_port);
    store_be16(header + 44, static_cast<uint16_t>(udp_len));
    out.append(header, sizeof(header));
    if (payload_len > 0) out.append(payload, payload_len);

    Buffer checksum_buf;
    checksum_buf.append(out.data() + 40, udp_len);
    const uint16_t csum = udp_checksum_ipv6(src_ip, dst_ip,
                                            checksum_buf.data(), checksum_buf.readable());
    uint8_t* writable = const_cast<uint8_t*>(out.data());
    store_be16(writable + 46, csum);
    return true;
}

} // namespace tx
