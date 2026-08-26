#include "tx/net/dns_network_provider.h"

#include "tx/common/log.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <utility>

#if defined(TX_PLATFORM_LINUX)
#include <arpa/inet.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(TX_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

namespace tx {

namespace {

std::string endpoint_signature(const DnsNetworkSnapshot& snapshot) {
    std::ostringstream out;
    out << snapshot.socket_binding.mark << '|'
        << snapshot.socket_binding.interface_name << '|'
        << snapshot.socket_binding.ipv4_interface << '|'
        << snapshot.socket_binding.ipv6_interface;
    for (const auto& endpoint : snapshot.endpoints)
        out << '|' << endpoint.address << ':' << endpoint.port;
    return out.str();
}

class SnapshotProviderBase : public DnsNetworkProvider {
protected:
    DnsNetworkSnapshot finish_snapshot(DnsNetworkSnapshot snapshot) const {
        const std::string signature = endpoint_signature(snapshot);
        std::lock_guard<std::mutex> lock(mutex_);
        if (signature != signature_) {
            signature_ = signature;
            ++generation_;
        }
        snapshot.generation = generation_;
        snapshot.available = !snapshot.endpoints.empty();
        return snapshot;
    }

    void invalidate_snapshot() {
        std::lock_guard<std::mutex> lock(mutex_);
        signature_.clear();
        ++generation_;
    }

private:
    mutable std::mutex mutex_;
    mutable std::string signature_;
    mutable uint64_t generation_ = 1;
};

#if defined(TX_PLATFORM_LINUX)

bool is_loopback_address(const std::string& address) {
    in_addr address4{};
    if (inet_pton(AF_INET, address.c_str(), &address4) == 1)
        return (ntohl(address4.s_addr) >> 24) == 127;

    in6_addr address6{};
    return inet_pton(AF_INET6, address.c_str(), &address6) == 1 &&
           IN6_IS_ADDR_LOOPBACK(&address6);
}

bool append_endpoint(const std::string& address, std::vector<DnsEndpoint>& endpoints,
                     bool allow_loopback = false) {
    if (address.empty() || (!allow_loopback && is_loopback_address(address))) return false;
    if (std::find_if(endpoints.begin(), endpoints.end(),
                     [&address](const DnsEndpoint& endpoint) {
                         return endpoint.address == address;
                     }) != endpoints.end()) {
        return false;
    }
    endpoints.push_back(DnsEndpoint{address, 53});
    return true;
}

std::string interface_for_address(const sockaddr* address) {
    if (!address) return std::string();
    ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0) return std::string();

    std::string result;
    for (ifaddrs* item = interfaces; item; item = item->ifa_next) {
        if (!item->ifa_name || !item->ifa_addr ||
            (item->ifa_flags & IFF_UP) == 0 ||
            (item->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }
        if (item->ifa_addr->sa_family != address->sa_family) continue;
        bool match = false;
        if (address->sa_family == AF_INET) {
            const auto* lhs = reinterpret_cast<const sockaddr_in*>(address);
            const auto* rhs = reinterpret_cast<const sockaddr_in*>(item->ifa_addr);
            match = lhs->sin_addr.s_addr == rhs->sin_addr.s_addr;
        } else if (address->sa_family == AF_INET6) {
            const auto* lhs = reinterpret_cast<const sockaddr_in6*>(address);
            const auto* rhs = reinterpret_cast<const sockaddr_in6*>(item->ifa_addr);
            match = std::memcmp(&lhs->sin6_addr, &rhs->sin6_addr,
                                sizeof(lhs->sin6_addr)) == 0;
        }
        if (match) {
            result = item->ifa_name;
            break;
        }
    }
    freeifaddrs(interfaces);
    return result;
}

std::string discover_physical_interface(uint32_t bypass_mark) {
    struct Candidate {
        int family;
        const char* address;
    };
    const Candidate candidates[] = {
        {AF_INET, "8.8.8.8"},
        {AF_INET6, "2001:4860:4860::8888"},
    };

    for (const auto& candidate : candidates) {
        const int fd = socket(candidate.family, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        if (bypass_mark != 0 &&
            setsockopt(fd, SOL_SOCKET, SO_MARK, &bypass_mark,
                       sizeof(bypass_mark)) != 0) {
            close(fd);
            continue;
        }

        bool connected = false;
        sockaddr_storage destination{};
        socklen_t destination_length = 0;
        if (candidate.family == AF_INET) {
            auto* address = reinterpret_cast<sockaddr_in*>(&destination);
            address->sin_family = AF_INET;
            address->sin_port = htons(53);
            connected = inet_pton(AF_INET, candidate.address, &address->sin_addr) == 1;
            destination_length = sizeof(sockaddr_in);
        } else {
            auto* address = reinterpret_cast<sockaddr_in6*>(&destination);
            address->sin6_family = AF_INET6;
            address->sin6_port = htons(53);
            connected = inet_pton(AF_INET6, candidate.address, &address->sin6_addr) == 1;
            destination_length = sizeof(sockaddr_in6);
        }
        if (connected && connect(fd, reinterpret_cast<sockaddr*>(&destination),
                                destination_length) == 0) {
            sockaddr_storage local{};
            socklen_t local_length = sizeof(local);
            if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_length) == 0) {
                const std::string interface = interface_for_address(
                    reinterpret_cast<const sockaddr*>(&local));
                close(fd);
                if (!interface.empty()) return interface;
            } else {
                close(fd);
            }
        } else {
            close(fd);
        }
    }
    return std::string();
}

std::vector<DnsEndpoint> load_resolv_file(const char* path, bool allow_loopback) {
    std::ifstream file(path);
    std::vector<DnsEndpoint> endpoints;
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream fields(line);
        std::string keyword;
        std::string address;
        if (fields >> keyword >> address && keyword == "nameserver") {
            if (!address.empty() && address.front() == '[' && address.back() == ']')
                address = address.substr(1, address.size() - 2);
            append_endpoint(address, endpoints, allow_loopback);
        }
    }
    return endpoints;
}

// libsystemd is loaded dynamically so Android, minimal Linux images and
// static build environments do not need systemd development headers.
struct sd_bus;
struct sd_bus_message;
struct sd_bus_error {
    const char* name;
    const char* message;
    int need_free;
};

class SdBusApi {
public:
    using DefaultSystem = int (*)(sd_bus**);
    using CallMethod = int (*)(sd_bus*, const char*, const char*, const char*,
                               const char*, sd_bus_error*, sd_bus_message**,
                               const char*, ...);
    using GetProperty = int (*)(sd_bus*, const char*, const char*, const char*,
                                const char*, sd_bus_error*, sd_bus_message**,
                                const char*, ...);
    using MessageRead = int (*)(sd_bus_message*, const char*, ...);
    using EnterContainer = int (*)(sd_bus_message*, char, const char*);
    using ExitContainer = int (*)(sd_bus_message*);
    using ReadArray = int (*)(sd_bus_message*, char, const void**, size_t*);
    using MessageUnref = sd_bus_message* (*)(sd_bus_message*);
    using FlushCloseUnref = sd_bus* (*)(sd_bus*);
    using ErrorFree = void (*)(sd_bus_error*);

    SdBusApi() {
        library_ = dlopen("libsystemd.so.0", RTLD_LAZY | RTLD_LOCAL);
        if (!library_) return;
        default_system = load<DefaultSystem>("sd_bus_default_system");
        call_method = load<CallMethod>("sd_bus_call_method");
        get_property = load<GetProperty>("sd_bus_get_property");
        message_read = load<MessageRead>("sd_bus_message_read");
        enter_container = load<EnterContainer>("sd_bus_message_enter_container");
        exit_container = load<ExitContainer>("sd_bus_message_exit_container");
        read_array = load<ReadArray>("sd_bus_message_read_array");
        message_unref = load<MessageUnref>("sd_bus_message_unref");
        flush_close_unref = load<FlushCloseUnref>("sd_bus_flush_close_unref");
        error_free = load<ErrorFree>("sd_bus_error_free");
        available = default_system && call_method && get_property && message_read &&
                    enter_container && exit_container && read_array && message_unref &&
                    flush_close_unref && error_free;
    }

    ~SdBusApi() {
        if (library_) dlclose(library_);
    }

    template <typename Function>
    Function load(const char* name) {
        return reinterpret_cast<Function>(dlsym(library_, name));
    }

    void* library_ = nullptr;
    bool available = false;
    DefaultSystem default_system = nullptr;
    CallMethod call_method = nullptr;
    GetProperty get_property = nullptr;
    MessageRead message_read = nullptr;
    EnterContainer enter_container = nullptr;
    ExitContainer exit_container = nullptr;
    ReadArray read_array = nullptr;
    MessageUnref message_unref = nullptr;
    FlushCloseUnref flush_close_unref = nullptr;
    ErrorFree error_free = nullptr;
};

bool read_resolved_link_dns(unsigned int interface_index,
                            std::vector<DnsEndpoint>& endpoints,
                            bool allow_loopback) {
    SdBusApi api;
    if (!api.available) return false;

    sd_bus* bus = nullptr;
    if (api.default_system(&bus) < 0 || !bus) return false;

    constexpr const char* kService = "org.freedesktop.resolve1";
    constexpr const char* kManagerPath = "/org/freedesktop/resolve1";
    constexpr const char* kManagerInterface = "org.freedesktop.resolve1.Manager";
    constexpr const char* kLinkInterface = "org.freedesktop.resolve1.Link";

    sd_bus_message* link_reply = nullptr;
    sd_bus_error error{nullptr, nullptr, 0};
    int result = api.call_method(bus, kService, kManagerPath, kManagerInterface,
                                 "GetLink", &error, &link_reply, "i",
                                 static_cast<int>(interface_index));
    if (result < 0 || !link_reply) {
        api.error_free(&error);
        api.flush_close_unref(bus);
        return false;
    }
    const char* link_path = nullptr;
    result = api.message_read(link_reply, "o", &link_path);
    const std::string link_path_value = link_path ? link_path : "";
    api.message_unref(link_reply);
    api.error_free(&error);
    if (result < 0 || link_path_value.empty()) {
        api.flush_close_unref(bus);
        return false;
    }

    sd_bus_message* dns_reply = nullptr;
    error = sd_bus_error{nullptr, nullptr, 0};
    result = api.get_property(bus, kService, link_path_value.c_str(), kLinkInterface, "DNS",
                              &error, &dns_reply, "a(iay)");
    if (result < 0 || !dns_reply) {
        api.error_free(&error);
        api.flush_close_unref(bus);
        return false;
    }

    result = api.enter_container(dns_reply, 'a', "(iay)");
    while (result > 0 && api.enter_container(dns_reply, 'r', "iay") > 0) {
        int family = 0;
        const void* bytes = nullptr;
        size_t length = 0;
        // sd_bus_message_read_array() expects the cursor to be at the array
        // itself. After entering the (iay) struct, reading the family leaves
        // it exactly at the ay member; entering ay first advances past the
        // array and makes every per-link DNS address unreadable.
        const bool valid = api.message_read(dns_reply, "i", &family) >= 0 &&
                           api.read_array(dns_reply, 'y', &bytes, &length) >= 0;
        if (valid) {
            char text[INET6_ADDRSTRLEN] = {};
            if (((family == AF_INET && length == 4) ||
                 (family == AF_INET6 && length == 16)) &&
                inet_ntop(family, bytes, text, sizeof(text))) {
                append_endpoint(text, endpoints, allow_loopback);
            }
        }
        api.exit_container(dns_reply); // address struct
    }
    if (result > 0) api.exit_container(dns_reply);
    api.message_unref(dns_reply);
    api.error_free(&error);
    api.flush_close_unref(bus);
    return !endpoints.empty();
}

class LinuxDnsNetworkProvider final : public SnapshotProviderBase {
public:
    LinuxDnsNetworkProvider(uint32_t bypass_mark, bool require_physical_network)
        : bypass_mark_(bypass_mark), require_physical_network_(require_physical_network) {}

    DnsNetworkSnapshot snapshot() const override {
        DnsNetworkSnapshot result;
        const std::string interface = discover_physical_interface(bypass_mark_);
        const bool allow_loopback = !require_physical_network_;
        if (!interface.empty()) {
            const unsigned int index = if_nametoindex(interface.c_str());
            if (index != 0) {
                read_resolved_link_dns(index, result.endpoints, allow_loopback);
            }
        }
        if (result.endpoints.empty()) {
            result.endpoints = load_resolv_file("/run/systemd/resolve/resolv.conf",
                                                allow_loopback);
        }
        if (result.endpoints.empty()) {
            result.endpoints = load_resolv_file("/etc/resolv.conf", allow_loopback);
        }
        if (require_physical_network_) {
            result.socket_binding.mark = bypass_mark_;
            result.socket_binding.interface_name = interface;
        }
        return finish_snapshot(std::move(result));
    }

    void invalidate() override { invalidate_snapshot(); }

private:
    uint32_t bypass_mark_;
    bool require_physical_network_;
};

#endif

#if defined(TX_PLATFORM_WINDOWS)

bool append_windows_endpoint(const sockaddr* address, int length,
                             std::vector<DnsEndpoint>& endpoints,
                             bool allow_loopback) {
    if (!address || (address->sa_family != AF_INET && address->sa_family != AF_INET6))
        return false;
    if (!allow_loopback && address->sa_family == AF_INET &&
        (ntohl(reinterpret_cast<const sockaddr_in*>(address)->sin_addr.s_addr) >> 24) == 127) {
        return false;
    }
    if (!allow_loopback && address->sa_family == AF_INET6 &&
        IN6_IS_ADDR_LOOPBACK(&reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr)) {
        return false;
    }
    char text[NI_MAXHOST] = {};
    if (getnameinfo(address, length, text, sizeof(text), nullptr, 0,
                    NI_NUMERICHOST) != 0 || text[0] == '\0') {
        return false;
    }
    if (std::find_if(endpoints.begin(), endpoints.end(),
                     [&text](const DnsEndpoint& endpoint) {
                         return endpoint.address == text;
                     }) != endpoints.end()) {
        return false;
    }
    endpoints.push_back(DnsEndpoint{text, 53});
    return true;
}

class WindowsDnsNetworkProvider final : public SnapshotProviderBase {
public:
    WindowsDnsNetworkProvider(bool require_physical_network,
                              DnsSocketBinding fixed_socket_binding)
        : require_physical_network_(require_physical_network),
          fixed_socket_binding_(std::move(fixed_socket_binding)) {}

    DnsNetworkSnapshot snapshot() const override {
        DnsNetworkSnapshot result;
        DWORD interface4 = fixed_socket_binding_.ipv4_interface;
        DWORD interface6 = fixed_socket_binding_.ipv6_interface;
        if (!require_physical_network_) {
            sockaddr_in destination4{};
            destination4.sin_family = AF_INET;
            InetPtonA(AF_INET, "8.8.8.8", &destination4.sin_addr);
            GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&destination4),
                               &interface4);

            sockaddr_in6 destination6{};
            destination6.sin6_family = AF_INET6;
            InetPtonA(AF_INET6, "2001:4860:4860::8888", &destination6.sin6_addr);
            GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&destination6),
                               &interface6);
        } else {
            result.socket_binding.ipv4_interface = interface4;
            result.socket_binding.ipv6_interface = interface6;
        }

        ULONG buffer_size = 15000;
        std::vector<uint8_t> buffer(buffer_size);
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                            GAA_FLAG_SKIP_FRIENDLY_NAME;
        ULONG status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                            adapters, &buffer_size);
        if (status == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(buffer_size);
            adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                          adapters, &buffer_size);
        }
        if (status == NO_ERROR) {
            for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
                if (adapter->OperStatus != IfOperStatusUp) continue;
                const bool selected4 = interface4 != 0 && adapter->IfIndex == interface4;
                const bool selected6 = interface6 != 0 &&
                    adapter->Ipv6IfIndex == interface6;
                if (!selected4 && !selected6) continue;
                for (auto* dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next) {
                    const sockaddr* address = dns->Address.lpSockaddr;
                    if (!address ||
                        (address->sa_family == AF_INET && !selected4) ||
                        (address->sa_family == AF_INET6 && !selected6)) {
                        continue;
                    }
                    append_windows_endpoint(
                        address, static_cast<int>(dns->Address.iSockaddrLength),
                        result.endpoints, !require_physical_network_);
                }
            }
        }
        return finish_snapshot(std::move(result));
    }

    void invalidate() override { invalidate_snapshot(); }

private:
    bool require_physical_network_;
    DnsSocketBinding fixed_socket_binding_;
};

#endif

} // namespace

std::shared_ptr<DnsNetworkProvider> create_platform_dns_network_provider(
    uint32_t bypass_mark, bool require_physical_network,
    DnsSocketBinding fixed_socket_binding) {
#if defined(TX_PLATFORM_LINUX)
    (void)fixed_socket_binding;
    return std::make_shared<LinuxDnsNetworkProvider>(bypass_mark, require_physical_network);
#elif defined(TX_PLATFORM_WINDOWS)
    (void)bypass_mark;
    return std::make_shared<WindowsDnsNetworkProvider>(
        require_physical_network, std::move(fixed_socket_binding));
#else
    (void)bypass_mark;
    (void)require_physical_network;
    (void)fixed_socket_binding;
    return nullptr;
#endif
}

} // namespace tx
