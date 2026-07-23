#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstring>

namespace tx {

// Forward declarations
class TcpSession;
class Buffer;
class Router;

using TcpSessionPtr = std::shared_ptr<TcpSession>;

// IP address representation
struct IpAddr {
    enum Family { IPv4 = 4, IPv6 = 6 };

    Family family;
    union {
        uint8_t  v4[4];
        uint8_t  v6[16];
    } data;
    uint16_t port;

    IpAddr() : family(IPv4), port(0) { memset(&data, 0, sizeof(data)); }

    bool is_loopback() const;
    bool is_lan() const;
    bool is_ipv4_mapped_ipv6() const;

    static IpAddr from_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port = 0);
    static IpAddr from_ipv6(const uint8_t bytes[16], uint16_t port = 0);
    static IpAddr from_string(const std::string& str, uint16_t port = 0);

    std::string to_string() const;
    bool operator==(const IpAddr& o) const;
};

// Address types for tunnel protocol
enum class AddrType : uint8_t {
    IPv4   = 0x01,
    Domain = 0x03,
    IPv6   = 0x04,
};

// Target address (from proxy request)
struct TargetAddr {
    AddrType type;
    std::string host;   // domain or IP string
    uint16_t port;

    TargetAddr() : type(AddrType::IPv4), port(0) {}
};

// Tunnel command types
enum class TunnelCmd : uint8_t {
    Connect       = 0x01,
    Data          = 0x02,
    Disconnect    = 0x03,
    ConnectResult = 0x04,
    UdpPacket     = 0x05,
    HalfClose     = 0x06,
};

// Route decision
enum class RouteAction {
    Direct,
    Proxy,
    Block,
};

// Session ID type
using SessionId = uint32_t;

// Callback types
using ConnectCallback = std::function<void(bool success)>;
using DataCallback    = std::function<void(Buffer& data)>;
using CloseCallback   = std::function<void()>;

} // namespace tx
