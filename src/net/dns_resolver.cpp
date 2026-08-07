#include "tx/net/dns_resolver.h"
#include "tx/common/endian.h"
#include "tx/common/log.h"
#include "tx/common/network.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#if defined(TX_PLATFORM_WINDOWS)
#include <iphlpapi.h>
#endif

namespace tx {

struct DnsResolver::Request {
    uv_work_t work;
    std::vector<std::string> upstreams;
    DnsSocketBinding static_socket_binding;
    std::shared_ptr<DnsNetworkProvider> network_provider;
    ProtectCallback protector;
    std::vector<uint8_t> query;
    std::vector<uint8_t> response;
    ResolveCallback callback;
    QueryHook query_hook;
    AddressFilterHook address_filter;
    uint64_t generation = 0;
    DnsResolver* owner = nullptr;
};

struct DnsResolver::HostRequest {
    uv_work_t work;
    std::string host;
    int family = AF_UNSPEC;
    HostResolveHook resolver;
    AddressFilterHook address_filter;
    std::vector<std::string> addresses;
    HostResolveCallback callback;
    uint64_t generation = 0;
    DnsResolver* owner = nullptr;
};

namespace {

std::atomic<uint16_t> g_dns_query_id{1};

bool append_dns_name(const std::string& host, std::vector<uint8_t>& query) {
    if (host.empty() || host.size() > 253) return false;
    size_t begin = 0;
    while (begin < host.size()) {
        const size_t end = host.find('.', begin);
        const size_t length = (end == std::string::npos ? host.size() : end) - begin;
        if (length == 0 || length > 63) return false;
        query.push_back(static_cast<uint8_t>(length));
        for (size_t i = 0; i < length; ++i) {
            const unsigned char value = static_cast<unsigned char>(host[begin + i]);
            if (value <= 0x20 || value >= 0x7f) return false;
            query.push_back(static_cast<uint8_t>(std::tolower(value)));
        }
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    query.push_back(0);
    return true;
}

bool build_host_query(const std::string& host, uint16_t type, std::vector<uint8_t>& query) {
    query.assign(12, 0);
    store_be16(query.data(), g_dns_query_id.fetch_add(1, std::memory_order_relaxed));
    store_be16(query.data() + 2, 0x0100); // RD
    store_be16(query.data() + 4, 1);
    if (!append_dns_name(host, query)) return false;
    const size_t offset = query.size();
    query.resize(offset + 4);
    store_be16(query.data() + offset, type);
    store_be16(query.data() + offset + 2, 1);
    return true;
}

bool skip_dns_name(const uint8_t* message, size_t length, size_t& offset) {
    if (!message || offset >= length) return false;
    unsigned labels = 0;
    while (offset < length) {
        const uint8_t size = message[offset++];
        if (size == 0) return true;
        if ((size & 0xc0u) == 0xc0u) {
            if (offset >= length) return false;
            ++offset;
            return true;
        }
        if ((size & 0xc0u) != 0 || size > 63 || ++labels > 127 ||
            offset + size > length) return false;
        offset += size;
    }
    return false;
}

std::vector<std::string> parse_host_response(const std::vector<uint8_t>& response,
                                             int family) {
    std::vector<std::string> addresses;
    if (response.size() < 12 || (load_be16(response.data() + 2) & 0x800fu) != 0x8000u)
        return addresses;
    const uint16_t questions = load_be16(response.data() + 4);
    const uint16_t answers = load_be16(response.data() + 6);
    size_t offset = 12;
    for (uint16_t i = 0; i < questions; ++i) {
        if (!skip_dns_name(response.data(), response.size(), offset) || offset + 4 > response.size())
            return std::vector<std::string>();
        offset += 4;
    }
    for (uint16_t i = 0; i < answers && addresses.size() < 16; ++i) {
        if (!skip_dns_name(response.data(), response.size(), offset) || offset + 10 > response.size())
            return std::vector<std::string>();
        const uint16_t type = load_be16(response.data() + offset);
        const uint16_t klass = load_be16(response.data() + offset + 2);
        const uint16_t rdlength = load_be16(response.data() + offset + 8);
        offset += 10;
        if (offset + rdlength > response.size()) return std::vector<std::string>();
        const bool want4 = (family == AF_UNSPEC || family == AF_INET) &&
            type == 1 && klass == 1 && rdlength == 4;
        const bool want6 = (family == AF_UNSPEC || family == AF_INET6) &&
            type == 28 && klass == 1 && rdlength == 16;
        if (want4 || want6) {
            char text[INET6_ADDRSTRLEN] = {};
            const int af = want4 ? AF_INET : AF_INET6;
            if (inet_ntop(af, response.data() + offset, text, sizeof(text)))
                addresses.emplace_back(text);
        }
        offset += rdlength;
    }
    return addresses;
}

void filter_host_addresses(std::vector<std::string>& addresses,
                           const DnsResolver::AddressFilterHook& filter) {
    if (!filter) return;
    addresses.erase(std::remove_if(addresses.begin(), addresses.end(),
                                   [&filter](const std::string& address) {
                                       return filter(address);
                                   }),
                    addresses.end());
}

bool response_contains_filtered_address(
    const std::vector<uint8_t>& response,
    const DnsResolver::AddressFilterHook& filter) {
    if (!filter || response.size() < 12) return false;

    size_t offset = 12;
    const uint16_t questions = load_be16(response.data() + 4);
    const uint32_t records = static_cast<uint32_t>(load_be16(response.data() + 6)) +
                             static_cast<uint32_t>(load_be16(response.data() + 8)) +
                             static_cast<uint32_t>(load_be16(response.data() + 10));
    for (uint16_t i = 0; i < questions; ++i) {
        if (!skip_dns_name(response.data(), response.size(), offset) ||
            offset + 4 > response.size()) {
            return false;
        }
        offset += 4;
    }
    for (uint32_t i = 0; i < records; ++i) {
        if (!skip_dns_name(response.data(), response.size(), offset) ||
            offset + 10 > response.size()) {
            return false;
        }
        const uint16_t type = load_be16(response.data() + offset);
        const uint16_t klass = load_be16(response.data() + offset + 2);
        const uint16_t rdlength = load_be16(response.data() + offset + 8);
        offset += 10;
        if (offset + rdlength > response.size()) return false;
        if (klass == 1 && ((type == 1 && rdlength == 4) ||
                           (type == 28 && rdlength == 16))) {
            char text[INET6_ADDRSTRLEN] = {};
            const int family = type == 1 ? AF_INET : AF_INET6;
            if (inet_ntop(family, response.data() + offset, text, sizeof(text)) &&
                filter(text)) {
                return true;
            }
        }
        offset += rdlength;
    }
    return false;
}

} // namespace

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || \
    defined(TX_PLATFORM_WINDOWS)
namespace {

#if defined(TX_PLATFORM_WINDOWS)
using DnsSocket = SOCKET;
using DnsSocklen = int;
constexpr DnsSocket kInvalidDnsSocket = INVALID_SOCKET;

void close_dns_socket(DnsSocket socket) {
    closesocket(socket);
}

int dns_socket_error() {
    return WSAGetLastError();
}

bool dns_socket_retryable(int error) {
    return error == WSAEINTR || error == WSAEWOULDBLOCK;
}

void set_dns_socket_timeout(DnsSocket socket, int timeout_ms) {
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
}
#else
using DnsSocket = int;
using DnsSocklen = socklen_t;
constexpr DnsSocket kInvalidDnsSocket = -1;

void close_dns_socket(DnsSocket socket) {
    close(socket);
}

int dns_socket_error() {
    return errno;
}

bool dns_socket_retryable(int error) {
    return error == EINTR || error == EAGAIN || error == EWOULDBLOCK;
}

void set_dns_socket_timeout(DnsSocket socket, int timeout_ms) {
    timeval timeout{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}
#endif

bool configure_socket(DnsSocket fd, int family,
                      const DnsResolver::ProtectCallback& protector,
                      const DnsSocketBinding& binding) {
    if (protector && !protector(static_cast<int>(fd))) {
        TX_ERROR("Socket protector rejected DNS socket");
        return false;
    }
#if defined(TX_PLATFORM_LINUX)
    if (binding.mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &binding.mark,
                                   sizeof(binding.mark)) != 0) {
        TX_WARN("SO_MARK 0x%x failed for DNS socket: %s", binding.mark,
                std::strerror(errno));
        return false;
    }
    if (!binding.interface_name.empty() &&
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, binding.interface_name.c_str(),
                   static_cast<socklen_t>(binding.interface_name.size() + 1)) != 0) {
        // An unmarked resolver may still be used by a normal proxy process
        // without CAP_NET_RAW. The marked TUN path must fail closed because
        // continuing would reintroduce the DNS/TUN loop.
        if (binding.mark != 0) {
            TX_WARN("SO_BINDTODEVICE(%s) failed for DNS socket: %s",
                    binding.interface_name.c_str(), std::strerror(errno));
            return false;
        }
        TX_DEBUG("SO_BINDTODEVICE(%s) unavailable; using normal DNS routing",
                 binding.interface_name.c_str());
    }
#elif defined(TX_PLATFORM_WINDOWS)
    const uint32_t interface_index = family == AF_INET6
        ? binding.ipv6_interface : binding.ipv4_interface;
    if (interface_index != 0) {
        const DWORD network_index = htonl(interface_index);
        const int level = family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
        const int option = family == AF_INET6 ? IPV6_UNICAST_IF : IP_UNICAST_IF;
        if (setsockopt(fd, level, option,
                       reinterpret_cast<const char*>(&network_index),
                       sizeof(network_index)) != 0) {
            TX_WARN("DNS interface binding failed for index %u: %d",
                    interface_index, dns_socket_error());
            return false;
        }
    }
#else
    (void)family;
    (void)binding;
#endif
    set_dns_socket_timeout(fd, 2000);
    return true;
}

bool parse_dns_port(const std::string& text, uint16_t& port) {
    if (text.empty()) return false;
    unsigned value = 0;
    for (const unsigned char character : text) {
        if (character < '0' || character > '9') return false;
        value = value * 10u + static_cast<unsigned>(character - '0');
        if (value > 65535u) return false;
    }
    if (value == 0) return false;
    port = static_cast<uint16_t>(value);
    return true;
}

bool parse_dns_endpoint(const std::string& text, DnsEndpoint& endpoint) {
    if (text.empty()) return false;
    endpoint = DnsEndpoint();
    endpoint.port = 53;

    if (text.front() == '[') {
        const size_t closing = text.find(']');
        if (closing == std::string::npos || closing == 1) return false;
        endpoint.address = text.substr(1, closing - 1);
        if (closing + 1 < text.size()) {
            if (text[closing + 1] != ':' ||
                !parse_dns_port(text.substr(closing + 2), endpoint.port)) {
                return false;
            }
        }
        return true;
    }

    // An unbracketed address with more than one colon is an IPv6 literal;
    // its optional port must use the bracketed form.
    const size_t first_colon = text.find(':');
    if (first_colon != std::string::npos && first_colon == text.rfind(':')) {
        endpoint.address = text.substr(0, first_colon);
        if (endpoint.address.empty() ||
            !parse_dns_port(text.substr(first_colon + 1), endpoint.port)) {
            return false;
        }
        return true;
    }

    endpoint.address = text;
    return true;
}

bool upstream_address(const std::string& host, int socktype,
                      sockaddr_storage& storage, DnsSocklen& length) {
    std::string numeric_host = host;
    std::string service = "53";
    if (!host.empty() && host.front() == '[') {
        const size_t closing = host.find(']');
        if (closing != std::string::npos) {
            numeric_host = host.substr(1, closing - 1);
            if (closing + 2 < host.size() && host[closing + 1] == ':')
                service = host.substr(closing + 2);
        }
    } else {
        const size_t colon = host.rfind(':');
        if (colon != std::string::npos && host.find(':') == colon) {
            numeric_host = host.substr(0, colon);
            service = host.substr(colon + 1);
        }
    }
    if (numeric_host.empty() || service.empty()) return false;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* result = nullptr;
    if (getaddrinfo(numeric_host.c_str(), service.c_str(), &hints, &result) != 0 ||
        !result) {
        return false;
    }
    std::memcpy(&storage, result->ai_addr, result->ai_addrlen);
    length = static_cast<DnsSocklen>(result->ai_addrlen);
    freeaddrinfo(result);
    return true;
}

#if defined(TX_PLATFORM_WINDOWS)
std::vector<std::string> load_windows_dns_upstreams() {
    ULONG buffer_size = 15000;
    std::vector<uint8_t> buffer;
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        buffer.resize(buffer_size);
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                            GAA_FLAG_SKIP_FRIENDLY_NAME;
        const ULONG status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                                  adapters, &buffer_size);
        if (status == ERROR_BUFFER_OVERFLOW) continue;
        if (status != NO_ERROR) return std::vector<std::string>();

        std::vector<std::string> upstreams;
        for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp) continue;
            for (auto* dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next) {
                if (!dns->Address.lpSockaddr ||
                    (dns->Address.lpSockaddr->sa_family != AF_INET &&
                     dns->Address.lpSockaddr->sa_family != AF_INET6)) {
                    continue;
                }
                char host[NI_MAXHOST] = {};
                if (getnameinfo(dns->Address.lpSockaddr,
                                static_cast<DnsSocklen>(dns->Address.iSockaddrLength),
                                host, sizeof(host), nullptr, 0,
                                NI_NUMERICHOST) != 0 || host[0] == '\0') {
                    continue;
                }
                if (std::find(upstreams.begin(), upstreams.end(), host) == upstreams.end())
                    upstreams.emplace_back(host);
            }
        }
        return upstreams;
    }
    return std::vector<std::string>();
}
#endif

bool operation_cancelled(const std::atomic<bool>* cancelled) {
    return cancelled && cancelled->load(std::memory_order_acquire);
}

bool write_all(DnsSocket fd, const uint8_t* data, size_t len,
               const std::atomic<bool>* cancelled) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(1);
    while (len) {
        if (operation_cancelled(cancelled)) {
            return false;
        }
#ifdef MSG_NOSIGNAL
        constexpr int send_flags = MSG_NOSIGNAL;
#else
        constexpr int send_flags = 0;
#endif
#if defined(TX_PLATFORM_WINDOWS)
        const int n = send(fd, reinterpret_cast<const char*>(data),
                           static_cast<int>(len), send_flags);
#else
        const ssize_t n = send(fd, data, len, send_flags);
#endif
        if (n < 0 && dns_socket_retryable(dns_socket_error()) &&
            std::chrono::steady_clock::now() < deadline) {
            continue;
        }
        if (n <= 0) return false;
        data += n; len -= static_cast<size_t>(n);
    }
    return true;
}

bool read_all(DnsSocket fd, uint8_t* data, size_t len,
              const std::atomic<bool>* cancelled) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(1);
    while (len) {
        if (operation_cancelled(cancelled)) {
            return false;
        }
#if defined(TX_PLATFORM_WINDOWS)
        const int n = recv(fd, reinterpret_cast<char*>(data), static_cast<int>(len), 0);
#else
        const ssize_t n = recv(fd, data, len, 0);
#endif
        if (n < 0 && dns_socket_retryable(dns_socket_error()) &&
            std::chrono::steady_clock::now() < deadline) {
            continue;
        }
        if (n <= 0) return false;
        data += n; len -= static_cast<size_t>(n);
    }
    return true;
}

bool connect_with_timeout(DnsSocket fd, const sockaddr* address, DnsSocklen address_len,
                          int timeout_ms, const std::atomic<bool>* cancelled) {
#if defined(TX_PLATFORM_WINDOWS)
    u_long nonblocking = 1;
    if (ioctlsocket(fd, FIONBIO, &nonblocking) != 0) return false;

    int result = connect(fd, address, address_len);
    if (result == SOCKET_ERROR) {
        const int connect_error = WSAGetLastError();
        if (connect_error != WSAEWOULDBLOCK && connect_error != WSAEINPROGRESS) {
            nonblocking = 0;
            ioctlsocket(fd, FIONBIO, &nonblocking);
            return false;
        }

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        result = SOCKET_ERROR;
        while (std::chrono::steady_clock::now() < deadline &&
               !operation_cancelled(cancelled)) {
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(fd, &writable);
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            timeval wait{0, static_cast<long>(std::max<int64_t>(
                1000, std::min<int64_t>(50000, remaining * 1000)))};
            const int selected = select(0, nullptr, &writable, nullptr, &wait);
            if (selected == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) continue;
            if (selected <= 0) continue;

            int socket_error = 0;
            int error_len = sizeof(socket_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                           reinterpret_cast<char*>(&socket_error), &error_len) == 0 &&
                socket_error == 0) {
                result = 0;
            } else if (socket_error != 0) {
                WSASetLastError(socket_error);
            }
            break;
        }
        if (result != 0 && WSAGetLastError() == 0) WSASetLastError(WSAETIMEDOUT);
    }
    nonblocking = 0;
    ioctlsocket(fd, FIONBIO, &nonblocking);
    return result == 0;
#else
    const int original_flags = fcntl(fd, F_GETFL, 0);
    if (original_flags < 0 || fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) != 0)
        return false;
    int result = connect(fd, address, address_len);
    if (result != 0 && errno == EINPROGRESS) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        result = 0;
        while (result == 0 && std::chrono::steady_clock::now() < deadline &&
               !operation_cancelled(cancelled)) {
            pollfd event{fd, POLLOUT, 0};
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            result = poll(&event, 1,
                          static_cast<int>(std::max<int64_t>(
                              1, std::min<int64_t>(50, remaining))));
            if (result < 0 && errno == EINTR) result = 0;
        }
        if (operation_cancelled(cancelled)) {
            errno = ECANCELED;
            result = -1;
        } else if (result > 0) {
            int socket_error = 0;
            socklen_t error_len = sizeof(socket_error);
            result = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len);
            if (result == 0 && socket_error != 0) {
                errno = socket_error;
                result = -1;
            }
        } else {
            if (result == 0) errno = ETIMEDOUT;
            result = -1;
        }
    }
    const int saved_errno = errno;
    fcntl(fd, F_SETFL, original_flags);
    errno = saved_errno;
    return result == 0;
#endif
}

struct DnsQuestion {
    std::vector<uint8_t> name;
    uint16_t type = 0;
    uint16_t qclass = 0;

    bool operator==(const DnsQuestion& other) const {
        return name == other.name && type == other.type && qclass == other.qclass;
    }
};

bool read_dns_name(const uint8_t* message, size_t message_len, size_t& offset,
                   std::vector<uint8_t>& normalized) {
    if (!message || offset >= message_len) return false;

    size_t cursor = offset;
    size_t next_offset = offset;
    size_t expanded_len = 0;
    unsigned jumps = 0;
    bool jumped = false;
    normalized.clear();

    for (;;) {
        if (cursor >= message_len) return false;
        const uint8_t length = message[cursor];
        if ((length & 0xc0u) == 0xc0u) {
            if (cursor + 1 >= message_len || ++jumps > 128) return false;
            const size_t pointer =
                static_cast<size_t>((length & 0x3fu) << 8) | message[cursor + 1];
            if (pointer >= message_len) return false;
            if (!jumped) next_offset = cursor + 2;
            cursor = pointer;
            jumped = true;
            continue;
        }
        if ((length & 0xc0u) != 0) return false;

        ++cursor;
        if (length == 0) {
            if (!jumped) next_offset = cursor;
            normalized.push_back(0);
            offset = next_offset;
            return true;
        }
        if (cursor + length > message_len ||
            expanded_len + static_cast<size_t>(length) + 1 > 255) {
            return false;
        }
        normalized.push_back(length);
        for (size_t i = 0; i < length; ++i) {
            normalized.push_back(static_cast<uint8_t>(
                std::tolower(static_cast<unsigned char>(message[cursor + i]))));
        }
        expanded_len += static_cast<size_t>(length) + 1;
        cursor += length;
        if (!jumped) next_offset = cursor;
    }
}

bool read_dns_questions(const std::vector<uint8_t>& message,
                        std::vector<DnsQuestion>& questions) {
    if (message.size() < 12) return false;
    const uint16_t count = load_be16(message.data() + 4);
    if (count > 64) return false;

    size_t offset = 12;
    questions.clear();
    questions.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        DnsQuestion question;
        if (!read_dns_name(message.data(), message.size(), offset, question.name) ||
            offset + 4 > message.size()) {
            return false;
        }
        question.type = load_be16(message.data() + offset);
        question.qclass = load_be16(message.data() + offset + 2);
        offset += 4;
        questions.push_back(std::move(question));
    }
    return true;
}

bool dns_response_matches_query(const std::vector<uint8_t>& query,
                                const std::vector<uint8_t>& response) {
    if (query.size() < 12 || response.size() < 12 ||
        load_be16(query.data()) != load_be16(response.data())) {
        return false;
    }

    const uint16_t query_flags = load_be16(query.data() + 2);
    const uint16_t response_flags = load_be16(response.data() + 2);
    if ((query_flags & 0x8000u) != 0 || (response_flags & 0x8000u) == 0 ||
        (query_flags & 0x7800u) != (response_flags & 0x7800u) ||
        load_be16(query.data() + 4) != load_be16(response.data() + 4)) {
        return false;
    }

    std::vector<DnsQuestion> query_questions;
    std::vector<DnsQuestion> response_questions;
    return read_dns_questions(query, query_questions) &&
           read_dns_questions(response, response_questions) &&
           query_questions == response_questions;
}

bool resolve_tcp(const DnsEndpoint& upstream, const std::vector<uint8_t>& query,
                 const DnsResolver::ProtectCallback& protector,
                 const DnsSocketBinding& binding,
                 std::vector<uint8_t>& response,
                 const std::atomic<bool>* cancelled) {
    if (operation_cancelled(cancelled)) return false;
    sockaddr_storage address{}; DnsSocklen address_len = 0;
    const std::string upstream_text = upstream.address.find(':') != std::string::npos
        ? "[" + upstream.address + "]:" + std::to_string(upstream.port)
        : upstream.address + ":" + std::to_string(upstream.port);
    if (!upstream_address(upstream_text, SOCK_STREAM, address, address_len)) {
        TX_WARN("Invalid DNS upstream address %s", upstream_text.c_str());
        return false;
    }
    DnsSocket fd = socket(address.ss_family, SOCK_STREAM, 0);
    if (fd == kInvalidDnsSocket) {
        TX_WARN("DNS TCP socket for %s failed: %d", upstream_text.c_str(),
                dns_socket_error());
        return false;
    }
    bool ok = configure_socket(fd, address.ss_family, protector, binding);
    set_dns_socket_timeout(fd, 100);
    if (ok && !connect_with_timeout(fd, reinterpret_cast<sockaddr*>(&address),
                                    address_len, 1000, cancelled)) {
        TX_DEBUG("DNS TCP connect to %s failed: %d", upstream_text.c_str(),
                 dns_socket_error());
        ok = false;
    }
    uint8_t length[2]; store_be16(length, static_cast<uint16_t>(query.size()));
    ok = ok && write_all(fd, length, 2, cancelled) &&
         write_all(fd, query.data(), query.size(), cancelled) &&
         read_all(fd, length, 2, cancelled);
    const uint16_t response_len = ok ? load_be16(length) : 0;
    if (response_len < 12) ok = false;
    if (ok) {
        response.resize(response_len);
        ok = read_all(fd, response.data(), response.size(), cancelled);
    }
    const int exchange_error = dns_socket_error();
    close_dns_socket(fd);
    if (ok && !dns_response_matches_query(query, response)) {
        TX_DEBUG("DNS TCP response from %s did not match the query",
                 upstream_text.c_str());
        ok = false;
    }
    if (!ok) {
        TX_DEBUG("DNS TCP exchange with %s failed: %d", upstream_text.c_str(),
                 exchange_error);
        response.clear();
    }
    return ok;
}

bool resolve_udp(const DnsEndpoint& upstream, const std::vector<uint8_t>& query,
                 const DnsResolver::ProtectCallback& protector,
                 const DnsSocketBinding& binding,
                 std::vector<uint8_t>& response,
                 const std::atomic<bool>* cancelled) {
    if (operation_cancelled(cancelled)) return false;
    sockaddr_storage address{}; DnsSocklen address_len = 0;
    const std::string upstream_text = upstream.address.find(':') != std::string::npos
        ? "[" + upstream.address + "]:" + std::to_string(upstream.port)
        : upstream.address + ":" + std::to_string(upstream.port);
    if (!upstream_address(upstream_text, SOCK_DGRAM, address, address_len)) {
        TX_WARN("Invalid DNS upstream address %s", upstream_text.c_str());
        return false;
    }
    DnsSocket fd = socket(address.ss_family, SOCK_DGRAM, 0);
    if (fd == kInvalidDnsSocket) {
        TX_WARN("DNS UDP socket for %s failed: %d", upstream_text.c_str(),
                dns_socket_error());
        return false;
    }
    bool ok = configure_socket(fd, address.ss_family, protector, binding);
    set_dns_socket_timeout(fd, 100);
    if (ok && connect(fd, reinterpret_cast<sockaddr*>(&address), address_len) != 0) {
        TX_DEBUG("DNS UDP connect to %s failed: %d", upstream_text.c_str(),
                 dns_socket_error());
        ok = false;
    }
    if (ok) {
#ifdef MSG_NOSIGNAL
        constexpr int send_flags = MSG_NOSIGNAL;
#else
        constexpr int send_flags = 0;
#endif
#if defined(TX_PLATFORM_WINDOWS)
        const int sent = send(fd, reinterpret_cast<const char*>(query.data()),
                              static_cast<int>(query.size()), send_flags);
        ok = sent == static_cast<int>(query.size());
#else
        const ssize_t sent = send(fd, query.data(), query.size(), send_flags);
        ok = sent == static_cast<ssize_t>(query.size());
#endif
        if (!ok) TX_DEBUG("DNS UDP send to %s failed: %d", upstream_text.c_str(),
                          dns_socket_error());
    }
    uint8_t buffer[65535];
#if defined(TX_PLATFORM_WINDOWS)
    int received = -1;
#else
    ssize_t received = -1;
#endif
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while (ok && !operation_cancelled(cancelled) &&
           std::chrono::steady_clock::now() < deadline) {
 #if defined(TX_PLATFORM_WINDOWS)
        received = recv(fd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
 #else
        received = recv(fd, buffer, sizeof(buffer), 0);
 #endif
        if (received >= 0) break;
        if (!dns_socket_retryable(dns_socket_error())) break;
    }
    const int receive_error = dns_socket_error();
    close_dns_socket(fd);
    if (received < 12) {
        TX_DEBUG("DNS UDP receive from %s failed: %d", upstream_text.c_str(),
                 receive_error);
        return false;
    }
    response.assign(buffer, buffer + received);
    if (!dns_response_matches_query(query, response)) {
        TX_DEBUG("DNS UDP response from %s did not match the query",
                 upstream_text.c_str());
        response.clear();
        return false;
    }
    if ((load_be16(response.data() + 2) & 0x0200u) != 0)
        return resolve_tcp(upstream, query, protector, binding, response, cancelled);
    return true;
}

} // namespace
#endif

DnsResolver::DnsResolver(uv_loop_t* loop) : loop_(loop) {}

bool DnsResolver::response_matches_query(const std::vector<uint8_t>& query,
                                         const std::vector<uint8_t>& response) {
    return dns_response_matches_query(query, response);
}

bool DnsResolver::response_is_truncated(const std::vector<uint8_t>& response) {
    return response.size() >= 4 && (load_be16(response.data() + 2) & 0x0200u) != 0;
}

void DnsResolver::configure(std::vector<std::string> upstreams,
                            ProtectCallback protector, uint32_t bypass_mark,
                            HostResolveHook host_resolver, QueryHook query_hook,
                            AsyncQueryHook async_query_hook,
                            std::shared_ptr<DnsNetworkProvider> network_provider,
                            AddressFilterHook address_filter) {
#if !defined(TX_PLATFORM_WINDOWS)
    if (upstreams.empty() && !query_hook && !async_query_hook && !network_provider) {
        std::ifstream resolv("/etc/resolv.conf");
        std::string line;
        while (std::getline(resolv, line)) {
            std::istringstream fields(line);
            std::string keyword;
            std::string address;
            if (fields >> keyword >> address && keyword == "nameserver")
                upstreams.push_back(address);
        }
    }
#else
    if (upstreams.empty() && !query_hook && !async_query_hook && !network_provider)
        upstreams = load_windows_dns_upstreams();
#endif
    upstreams_ = std::move(upstreams);
    protector_ = std::move(protector);
    static_socket_binding_ = DnsSocketBinding();
    static_socket_binding_.mark = bypass_mark;
    host_resolver_ = std::move(host_resolver);
    query_hook_ = std::move(query_hook);
    async_query_hook_ = std::move(async_query_hook);
    network_provider_ = std::move(network_provider);
    address_filter_ = std::move(address_filter);
}

void DnsResolver::resolve(const uint8_t* query, size_t query_len,
                          ResolveCallback callback) {
    if (!callback) return;
    if (!query || query_len < 12 || query_len > 65535 ||
        (!async_query_hook_ && !query_hook_ && !network_provider_ && upstreams_.empty())) {
        callback(std::vector<uint8_t>());
        return;
    }
    if (async_query_hook_) {
        const uint64_t generation = generation_;
        std::vector<uint8_t> request(query, query + query_len);
        auto complete = [this, generation, request, callback = std::move(callback)]
                        (std::vector<uint8_t> response) mutable {
            if (generation != generation_ ||
                (!response.empty() &&
                 (!dns_response_matches_query(request, response) ||
                  response_contains_filtered_address(response, address_filter_)))) {
                response.clear();
            }
            callback(std::move(response));
        };
        async_query_hook_(std::move(request), std::move(complete));
        return;
    }
    auto* request = new Request;
    request->work.data = request;
    request->upstreams = upstreams_;
    request->static_socket_binding = static_socket_binding_;
    request->network_provider = network_provider_;
    request->protector = protector_;
    request->query.assign(query, query + query_len);
    request->callback = std::move(callback);
    request->query_hook = query_hook_;
    request->address_filter = address_filter_;
    request->generation = generation_;
    request->owner = this;
    if (uv_queue_work(loop_, &request->work, on_work, after_work) != 0) {
        auto cb = std::move(request->callback);
        delete request;
        cb(std::vector<uint8_t>());
    }
}

void DnsResolver::on_work(uv_work_t* work) {
    auto* request = static_cast<Request*>(work->data);
    if (request->query_hook) {
        request->response = request->query_hook(request->query.data(), request->query.size());
        if (!request->response.empty() &&
            response_contains_filtered_address(request->response, request->address_filter)) {
            TX_WARN("Rejecting DNS response containing a protected Fake-IP address");
            request->response.clear();
        }
        return;
    }
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || \
    defined(TX_PLATFORM_WINDOWS)
    // uv_queue_work already uses libuv's bounded worker pool. Do all upstream
    // attempts in that worker instead of spawning two native threads per DNS
    // request, which allowed a burst of queries to exhaust process resources.
    DnsNetworkSnapshot network;
    if (request->network_provider) {
        network = request->network_provider->snapshot();
    } else {
        network.available = !request->upstreams.empty();
        network.socket_binding = request->static_socket_binding;
        for (const auto& address : request->upstreams) {
            DnsEndpoint endpoint;
            if (parse_dns_endpoint(address, endpoint)) {
                network.endpoints.push_back(std::move(endpoint));
            } else {
                TX_WARN("Invalid DNS upstream endpoint %s", address.c_str());
            }
        }
    }
    for (const auto& upstream : network.endpoints) {
        if (request->address_filter && request->address_filter(upstream.address)) {
            TX_WARN("Skipping protected Fake-IP DNS upstream %s", upstream.address.c_str());
            continue;
        }
        if (resolve_udp(upstream, request->query, request->protector,
                        network.socket_binding, request->response, nullptr)) {
            if (!response_contains_filtered_address(request->response,
                                                     request->address_filter)) return;
            TX_WARN("Rejecting DNS response from %s: protected Fake-IP address",
                    upstream.address.c_str());
            request->response.clear();
        }
        if (resolve_tcp(upstream, request->query, request->protector,
                        network.socket_binding, request->response, nullptr)) {
            if (!response_contains_filtered_address(request->response,
                                                     request->address_filter)) return;
            TX_WARN("Rejecting DNS TCP response from %s: protected Fake-IP address",
                    upstream.address.c_str());
            request->response.clear();
        }
        if (!request->response.empty()) {
            return;
        }
    }
    if (request->response.empty())
        TX_WARN("All %zu DNS upstreams failed", network.endpoints.size());
#endif
}

void DnsResolver::after_work(uv_work_t* work, int status) {
    auto* request = static_cast<Request*>(work->data);
    auto callback = std::move(request->callback);
    const bool stale = !request->owner || request->generation != request->owner->generation_;
    auto response = status == UV_ECANCELED || stale ? std::vector<uint8_t>()
                                                     : std::move(request->response);
    delete request;
    callback(std::move(response));
}

void DnsResolver::resolve_host(const std::string& host, int family,
                               HostResolveCallback callback) {
    if (!callback || host.empty()) return;
    in_addr address4{};
    in6_addr address6{};
    if (inet_pton(AF_INET, host.c_str(), &address4) == 1 ||
        inet_pton(AF_INET6, host.c_str(), &address6) == 1) {
        if (address_filter_ && address_filter_(host)) {
            TX_WARN("Rejecting protected Fake-IP target %s", host.c_str());
            callback(std::vector<std::string>());
            return;
        }
        callback(std::vector<std::string>{host});
        return;
    }
    if (!host_resolver_) {
        if (!can_query()) {
            TX_ERROR("No controlled DNS resolver is configured for %s", host.c_str());
            callback(std::vector<std::string>());
            return;
        }

        const uint64_t generation = generation_;
        auto resolve_type = [this, host, family, callback, generation](uint16_t type,
                                                                         bool fallback_ipv6) {
            std::vector<uint8_t> query;
            if (!build_host_query(host, type, query)) {
                callback(std::vector<std::string>());
                return;
            }
            resolve(query.data(), query.size(),
                [this, host, family, callback, generation, fallback_ipv6]
                (std::vector<uint8_t> response) {
                    if (generation != generation_) {
                        callback(std::vector<std::string>());
                        return;
                    }
                    std::vector<std::string> addresses =
                        parse_host_response(response, family);
                    filter_host_addresses(addresses, address_filter_);
                    if (!addresses.empty() || !fallback_ipv6) {
                        callback(std::move(addresses));
                        return;
                    }
                    std::vector<uint8_t> query6;
                    if (!build_host_query(host, 28, query6)) {
                        callback(std::vector<std::string>());
                        return;
                    }
                    resolve(query6.data(), query6.size(),
                        [this, family, callback, generation](std::vector<uint8_t> response6) {
                            if (generation != generation_) {
                                callback(std::vector<std::string>());
                                return;
                            }
                            std::vector<std::string> addresses =
                                parse_host_response(response6, family);
                            filter_host_addresses(addresses, address_filter_);
                            callback(std::move(addresses));
                        });
                });
        };
        if (family == AF_INET6) {
            resolve_type(28, false);
        } else {
            resolve_type(1, family == AF_UNSPEC);
        }
        return;
    }

    auto* request = new HostRequest;
    request->work.data = request;
    request->host = host;
    request->family = family;
    request->resolver = host_resolver_;
    request->address_filter = address_filter_;
    request->callback = std::move(callback);
    request->generation = generation_;
    request->owner = this;
    if (uv_queue_work(loop_, &request->work, on_host_work, after_host_work) != 0) {
        auto cb = std::move(request->callback);
        delete request;
        cb(std::vector<std::string>());
    }
}

void DnsResolver::on_host_work(uv_work_t* work) {
    auto* request = static_cast<HostRequest*>(work->data);
    if (request->resolver) {
        request->addresses = request->resolver(request->host, request->family);
        filter_host_addresses(request->addresses, request->address_filter);
    }
}

void DnsResolver::after_host_work(uv_work_t* work, int status) {
    auto* request = static_cast<HostRequest*>(work->data);
    auto callback = std::move(request->callback);
    const bool stale = !request->owner || request->generation != request->owner->generation_;
    auto addresses = status == UV_ECANCELED || stale
        ? std::vector<std::string>() : std::move(request->addresses);
    delete request;
    callback(std::move(addresses));
}

void DnsResolver::cancel_pending() {
    if (network_provider_) network_provider_->invalidate();
    ++generation_;
}

} // namespace tx
