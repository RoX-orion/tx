#pragma once

#include <cstdint>

#if defined(TX_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#endif

namespace tx {

// Windows gives IP_UNICAST_IF and IPV6_UNICAST_IF different byte-order
// contracts: IPv4 consumes a network-order index while IPv6 consumes the
// host-order interface index returned by the IP Helper APIs.
inline uint32_t windows_unicast_interface_value(int family, uint32_t index) {
    return family == AF_INET ? static_cast<uint32_t>(htonl(index)) : index;
}

} // namespace tx
