#include "tx/common/types.h"
#include <arpa/inet.h>
#include <sstream>

namespace tx {

IpAddr IpAddr::from_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    IpAddr addr;
    addr.family = IPv4;
    addr.data.v4[0] = a; addr.data.v4[1] = b;
    addr.data.v4[2] = c; addr.data.v4[3] = d;
    addr.port = port;
    return addr;
}

IpAddr IpAddr::from_ipv6(const uint8_t bytes[16], uint16_t port) {
    IpAddr addr;
    addr.family = IPv6;
    memcpy(addr.data.v6, bytes, 16);
    addr.port = port;
    return addr;
}

IpAddr IpAddr::from_string(const std::string& str, uint16_t port) {
    IpAddr addr;
    addr.port = port;

    struct in_addr v4;
    if (inet_pton(AF_INET, str.c_str(), &v4) == 1) {
        addr.family = IPv4;
        memcpy(addr.data.v4, &v4, 4);
        return addr;
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, str.c_str(), &v6) == 1) {
        addr.family = IPv6;
        memcpy(addr.data.v6, &v6, 16);
        return addr;
    }

    return addr;
}

std::string IpAddr::to_string() const {
    char buf[INET6_ADDRSTRLEN];
    if (family == IPv4) {
        inet_ntop(AF_INET, data.v4, buf, sizeof(buf));
    } else {
        inet_ntop(AF_INET6, data.v6, buf, sizeof(buf));
    }
    std::string result(buf);
    if (port > 0) {
        result += ":" + std::to_string(port);
    }
    return result;
}

bool IpAddr::operator==(const IpAddr& o) const {
    if (family != o.family || port != o.port) return false;
    if (family == IPv4) return memcmp(data.v4, o.data.v4, 4) == 0;
    return memcmp(data.v6, o.data.v6, 16) == 0;
}

bool IpAddr::is_loopback() const {
    if (family == IPv4) {
        return data.v4[0] == 127;
    }
    // ::1
    static const uint8_t loopback_v6[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
    return memcmp(data.v6, loopback_v6, 16) == 0;
}

bool IpAddr::is_lan() const {
    if (family == IPv4) {
        // 10.0.0.0/8
        if (data.v4[0] == 10) return true;
        // 172.16.0.0/12
        if (data.v4[0] == 172 && (data.v4[1] & 0xF0) == 16) return true;
        // 192.168.0.0/16
        if (data.v4[0] == 192 && data.v4[1] == 168) return true;
        // 169.254.0.0/16 (link-local)
        if (data.v4[0] == 169 && data.v4[1] == 254) return true;
        // Loopback
        if (is_loopback()) return true;
        return false;
    }
    // IPv6 link-local: fe80::/10
    if (data.v6[0] == 0xfe && (data.v6[1] & 0xc0) == 0x80) return true;
    // IPv6 unique local: fc00::/7
    if ((data.v6[0] & 0xfe) == 0xfc) return true;
    // Loopback
    if (is_loopback()) return true;
    return false;
}

bool IpAddr::is_ipv4_mapped_ipv6() const {
    if (family != IPv6) return false;
    static const uint8_t prefix[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
    return memcmp(data.v6, prefix, 12) == 0;
}

} // namespace tx
