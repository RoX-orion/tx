#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tx {

// Socket attributes required to keep a physical DNS query outside a native
// TUN. The fields are intentionally platform-neutral; each platform backend
// consumes only the fields it supports.
struct DnsSocketBinding {
    uint32_t mark = 0;
    std::string interface_name; // Linux SO_BINDTODEVICE
    uint32_t ipv4_interface = 0; // Windows IP_UNICAST_IF
    uint32_t ipv6_interface = 0; // Windows IPV6_UNICAST_IF
};

struct DnsEndpoint {
    std::string address;
    uint16_t port = 53;
};

struct DnsNetworkSnapshot {
    uint64_t generation = 0;
    bool available = false;
    std::vector<DnsEndpoint> endpoints;
    DnsSocketBinding socket_binding;
};

// Discovers the DNS servers and physical socket policy for a resolver. A
// snapshot is taken on demand so a DNS request cannot keep using a stale
// interface after a network change.
class DnsNetworkProvider {
public:
    virtual ~DnsNetworkProvider() = default;
    virtual DnsNetworkSnapshot snapshot() const = 0;
    virtual void invalidate() = 0;
};

// Creates the platform physical-network provider used by client direct DNS.
// Android deliberately returns nullptr: its Network-bound resolver hooks are
// the platform backend and are injected through ClientApp instead.
std::shared_ptr<DnsNetworkProvider> create_platform_dns_network_provider(
    uint32_t bypass_mark = 0, bool require_physical_network = false);

} // namespace tx
