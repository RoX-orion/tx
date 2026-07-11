#include "platform_tun.h"
#include "tx/common/log.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(TX_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#endif

namespace tx {

namespace {

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)

#if !defined(TX_PLATFORM_ANDROID)
uint32_t prefix_to_netmask(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xffffffffu;
    return htonl(0xffffffffu << (32 - prefix));
}

bool parse_ipv4_cidr(const std::string& cidr, in_addr& addr, int& prefix) {
    const size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    std::string ip = cidr.substr(0, slash);
    std::string prefix_str = cidr.substr(slash + 1);
    char* end = nullptr;
    long p = std::strtol(prefix_str.c_str(), &end, 10);
    if (!end || *end != '\0' || p < 0 || p > 32) return false;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
    prefix = static_cast<int>(p);
    return true;
}
#endif

class PosixTunDevice final : public PlatformTunDevice {
public:
    ~PosixTunDevice() override { close(); }

    bool open(const ClientConfig& config, std::string& error) override {
        name_ = config.tun_name.empty() ? "tx0" : config.tun_name;

        if (config.tun_fd >= 0) {
            fd_ = config.tun_fd;
            external_fd_ = true;
            if (!set_nonblocking(error)) {
                close();
                return false;
            }
            return true;
        }

#if defined(TX_PLATFORM_ANDROID)
        error = "Android TUN requires an fd from VpnService";
        return false;
#else
        fd_ = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
        if (fd_ < 0) {
            error = std::string("open /dev/net/tun failed: ") + std::strerror(errno);
            return false;
        }

        ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name_.c_str());

        if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
            error = std::string("TUNSETIFF failed: ") + std::strerror(errno);
            close();
            return false;
        }
        name_ = ifr.ifr_name;

        if (config.tun_auto_config &&
            !configure_interface(config, error)) {
            close();
            return false;
        }

        TX_INFO("Linux TUN device ready: %s", name_.c_str());
        return true;
#endif
    }

    void close() override {
        if (fd_ >= 0 && !external_fd_) {
            ::close(fd_);
        }
        fd_ = -1;
        external_fd_ = false;
    }

    int fd() const override { return fd_; }
    const std::string& name() const override { return name_; }

    std::ptrdiff_t read_packet(uint8_t* data, size_t len, std::string& error) override {
        if (fd_ < 0) return -1;
        for (;;) {
            ssize_t n = ::read(fd_, data, len);
            if (n >= 0) return n;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            error = std::strerror(errno);
            return -1;
        }
    }

    bool write_packet(const uint8_t* data, size_t len, std::string& error) override {
        if (fd_ < 0) return false;
        size_t written = 0;
        while (written < len) {
            ssize_t n = ::write(fd_, data + written, len - written);
            if (n > 0) {
                written += static_cast<size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            error = std::strerror(errno);
            return false;
        }
        return true;
    }

private:
    bool set_nonblocking(std::string& error) {
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0) {
            error = std::strerror(errno);
            return false;
        }
        if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            error = std::strerror(errno);
            return false;
        }
        return true;
    }

#if !defined(TX_PLATFORM_ANDROID)
    bool configure_interface(const ClientConfig& config, std::string& error) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            error = std::string("socket(AF_INET, SOCK_DGRAM) failed: ") + std::strerror(errno);
            return false;
        }

        auto close_sock = [&]() { ::close(sock); };
        ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name_.c_str());

        if (!config.tun_address.empty()) {
            sockaddr_in addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            if (inet_pton(AF_INET, config.tun_address.c_str(), &addr.sin_addr) != 1) {
                error = "tun.address must be an IPv4 address on Linux";
                close_sock();
                return false;
            }
            std::memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
            if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
                error = std::string("SIOCSIFADDR failed: ") + std::strerror(errno);
                close_sock();
                return false;
            }

            sockaddr_in mask;
            std::memset(&mask, 0, sizeof(mask));
            mask.sin_family = AF_INET;
            mask.sin_addr.s_addr = prefix_to_netmask(config.tun_prefix);
            std::memcpy(&ifr.ifr_netmask, &mask, sizeof(mask));
            if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
                error = std::string("SIOCSIFNETMASK failed: ") + std::strerror(errno);
                close_sock();
                return false;
            }
        }

        ifr.ifr_mtu = config.tun_mtu;
        if (config.tun_mtu > 0 && ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            error = std::string("SIOCSIFMTU failed: ") + std::strerror(errno);
            close_sock();
            return false;
        }

        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            error = std::string("SIOCGIFFLAGS failed: ") + std::strerror(errno);
            close_sock();
            return false;
        }
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            error = std::string("SIOCSIFFLAGS failed: ") + std::strerror(errno);
            close_sock();
            return false;
        }

        std::vector<std::string> routes = config.tun_routes;
        if (config.tun_auto_route && routes.empty()) {
            routes.push_back("0.0.0.0/1");
            routes.push_back("128.0.0.0/1");
        }

        for (const auto& route : routes) {
            if (!add_route(sock, route, error)) {
                close_sock();
                return false;
            }
        }

        close_sock();
        return true;
    }

    bool add_route(int sock, const std::string& cidr, std::string& error) {
        in_addr dst;
        int prefix = 0;
        if (!parse_ipv4_cidr(cidr, dst, prefix)) {
            error = "tun.routes only supports IPv4 CIDR on Linux: " + cidr;
            return false;
        }

        rtentry rt;
        std::memset(&rt, 0, sizeof(rt));
        sockaddr_in dst_addr;
        std::memset(&dst_addr, 0, sizeof(dst_addr));
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_addr = dst;
        std::memcpy(&rt.rt_dst, &dst_addr, sizeof(dst_addr));

        sockaddr_in genmask;
        std::memset(&genmask, 0, sizeof(genmask));
        genmask.sin_family = AF_INET;
        genmask.sin_addr.s_addr = prefix_to_netmask(prefix);
        std::memcpy(&rt.rt_genmask, &genmask, sizeof(genmask));

        rt.rt_flags = RTF_UP;
        rt.rt_dev = const_cast<char*>(name_.c_str());

        if (ioctl(sock, SIOCADDRT, &rt) < 0) {
            if (errno == EEXIST) return true;
            error = "SIOCADDRT failed for " + cidr + ": " + std::strerror(errno);
            return false;
        }
        return true;
    }
#endif

    int fd_ = -1;
    bool external_fd_ = false;
    std::string name_;
};

#endif

#if defined(TX_PLATFORM_WINDOWS)

using WINTUN_ADAPTER_HANDLE = void*;
using WINTUN_SESSION_HANDLE = void*;

using WintunCreateAdapterFn = WINTUN_ADAPTER_HANDLE (WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
using WintunCloseAdapterFn = void (WINAPI*)(WINTUN_ADAPTER_HANDLE);
using WintunDeleteDriverFn = BOOL (WINAPI*)();
using WintunGetAdapterLuidFn = void (WINAPI*)(WINTUN_ADAPTER_HANDLE, NET_LUID*);
using WintunStartSessionFn = WINTUN_SESSION_HANDLE (WINAPI*)(WINTUN_ADAPTER_HANDLE, DWORD);
using WintunEndSessionFn = void (WINAPI*)(WINTUN_SESSION_HANDLE);
using WintunReceivePacketFn = BYTE* (WINAPI*)(WINTUN_SESSION_HANDLE, DWORD*);
using WintunReleaseReceivePacketFn = void (WINAPI*)(WINTUN_SESSION_HANDLE, const BYTE*);
using WintunAllocateSendPacketFn = BYTE* (WINAPI*)(WINTUN_SESSION_HANDLE, DWORD);
using WintunSendPacketFn = void (WINAPI*)(WINTUN_SESSION_HANDLE, const BYTE*);

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return std::wstring(s.begin(), s.end());
    std::wstring out(static_cast<size_t>(len), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], len) <= 0) {
        return std::wstring(s.begin(), s.end());
    }
    out.resize(static_cast<size_t>(len - 1));
    return out;
}

bool parse_ipv4_cidr_win(const std::string& cidr, IN_ADDR& addr, UINT8& prefix) {
    const size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    std::string ip = cidr.substr(0, slash);
    char* end = nullptr;
    long p = std::strtol(cidr.substr(slash + 1).c_str(), &end, 10);
    if (!end || *end != '\0' || p < 0 || p > 32) return false;
    sockaddr_in parsed;
    int parsed_len = sizeof(parsed);
    std::memset(&parsed, 0, sizeof(parsed));
    if (WSAStringToAddressA(const_cast<char*>(ip.c_str()), AF_INET, nullptr,
                            reinterpret_cast<sockaddr*>(&parsed), &parsed_len) != 0) {
        return false;
    }
    addr = parsed.sin_addr;
    prefix = static_cast<UINT8>(p);
    return true;
}

class WintunDevice final : public PlatformTunDevice {
public:
    ~WintunDevice() override { close(); }

    bool open(const ClientConfig& config, std::string& error) override {
        name_ = config.tun_name.empty() ? "tx" : config.tun_name;
        dll_ = LoadLibraryW(L"wintun.dll");
        if (!dll_) {
            error = "failed to load wintun.dll; put wintun.dll next to tx_client.exe or in PATH";
            return false;
        }

        create_adapter_ = load<WintunCreateAdapterFn>("WintunCreateAdapter");
        close_adapter_ = load<WintunCloseAdapterFn>("WintunCloseAdapter");
        get_adapter_luid_ = load<WintunGetAdapterLuidFn>("WintunGetAdapterLUID");
        start_session_ = load<WintunStartSessionFn>("WintunStartSession");
        end_session_ = load<WintunEndSessionFn>("WintunEndSession");
        receive_packet_ = load<WintunReceivePacketFn>("WintunReceivePacket");
        release_receive_packet_ = load<WintunReleaseReceivePacketFn>("WintunReleaseReceivePacket");
        allocate_send_packet_ = load<WintunAllocateSendPacketFn>("WintunAllocateSendPacket");
        send_packet_ = load<WintunSendPacketFn>("WintunSendPacket");
        if (!create_adapter_ || !close_adapter_ || !get_adapter_luid_ ||
            !start_session_ || !end_session_ || !receive_packet_ ||
            !release_receive_packet_ || !allocate_send_packet_ || !send_packet_) {
            error = "wintun.dll is missing required exports";
            close();
            return false;
        }

        std::wstring wide_name = widen(name_);
        adapter_ = create_adapter_(wide_name.c_str(), L"tx", nullptr);
        if (!adapter_) {
            error = "WintunCreateAdapter failed";
            close();
            return false;
        }

        get_adapter_luid_(adapter_, &luid_);
        if (config.tun_auto_config &&
            !configure_interface(config, error)) {
            close();
            return false;
        }

        session_ = start_session_(adapter_, 4 * 1024 * 1024);
        if (!session_) {
            error = "WintunStartSession failed";
            close();
            return false;
        }
        TX_INFO("Windows Wintun device ready: %s", name_.c_str());
        return true;
    }

    void close() override {
        if (session_ && end_session_) {
            end_session_(session_);
        }
        session_ = nullptr;
        if (adapter_ && close_adapter_) {
            close_adapter_(adapter_);
        }
        adapter_ = nullptr;
        if (dll_) {
            FreeLibrary(dll_);
        }
        dll_ = nullptr;
    }

    const std::string& name() const override { return name_; }

    std::ptrdiff_t read_packet(uint8_t* data, size_t len, std::string& error) override {
        DWORD packet_size = 0;
        BYTE* packet = receive_packet_(session_, &packet_size);
        if (!packet) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) return 0;
            error = "WintunReceivePacket failed";
            return -1;
        }
        if (packet_size > len) {
            release_receive_packet_(session_, packet);
            error = "Wintun packet is larger than receive buffer";
            return -1;
        }
        std::memcpy(data, packet, packet_size);
        release_receive_packet_(session_, packet);
        return static_cast<std::ptrdiff_t>(packet_size);
    }

    bool write_packet(const uint8_t* data, size_t len, std::string& error) override {
        BYTE* packet = allocate_send_packet_(session_, static_cast<DWORD>(len));
        if (!packet) {
            error = "WintunAllocateSendPacket failed";
            return false;
        }
        std::memcpy(packet, data, len);
        send_packet_(session_, packet);
        return true;
    }

private:
    template <typename T>
    T load(const char* name) {
        return reinterpret_cast<T>(GetProcAddress(dll_, name));
    }

    bool configure_interface(const ClientConfig& config, std::string& error) {
        if (!config.tun_address.empty()) {
            MIB_UNICASTIPADDRESS_ROW row;
            InitializeUnicastIpAddressEntry(&row);
            row.InterfaceLuid = luid_;
            row.Address.si_family = AF_INET;
            sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&row.Address);
            int addr_len = sizeof(sockaddr_in);
            if (WSAStringToAddressA(const_cast<char*>(config.tun_address.c_str()), AF_INET,
                                    nullptr, reinterpret_cast<sockaddr*>(addr), &addr_len) != 0) {
                error = "tun.address must be an IPv4 address on Windows";
                return false;
            }
            row.OnLinkPrefixLength = static_cast<UINT8>(config.tun_prefix);
            DWORD r = CreateUnicastIpAddressEntry(&row);
            if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
                error = "CreateUnicastIpAddressEntry failed";
                return false;
            }
        }

        for (const auto& route : config.tun_routes) {
            IN_ADDR dst;
            UINT8 prefix = 0;
            if (!parse_ipv4_cidr_win(route, dst, prefix)) {
                error = "tun.routes only supports IPv4 CIDR on Windows: " + route;
                return false;
            }
            MIB_IPFORWARD_ROW2 row;
            InitializeIpForwardEntry(&row);
            row.InterfaceLuid = luid_;
            row.DestinationPrefix.Prefix.si_family = AF_INET;
            reinterpret_cast<sockaddr_in*>(&row.DestinationPrefix.Prefix)->sin_addr = dst;
            row.DestinationPrefix.PrefixLength = prefix;
            row.NextHop.si_family = AF_INET;
            row.Metric = 0;
            DWORD r = CreateIpForwardEntry2(&row);
            if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
                error = "CreateIpForwardEntry2 failed for " + route;
                return false;
            }
        }
        return true;
    }

    HMODULE dll_ = nullptr;
    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;
    NET_LUID luid_{};
    std::string name_;

    WintunCreateAdapterFn create_adapter_ = nullptr;
    WintunCloseAdapterFn close_adapter_ = nullptr;
    WintunGetAdapterLuidFn get_adapter_luid_ = nullptr;
    WintunStartSessionFn start_session_ = nullptr;
    WintunEndSessionFn end_session_ = nullptr;
    WintunReceivePacketFn receive_packet_ = nullptr;
    WintunReleaseReceivePacketFn release_receive_packet_ = nullptr;
    WintunAllocateSendPacketFn allocate_send_packet_ = nullptr;
    WintunSendPacketFn send_packet_ = nullptr;
};

#endif

} // namespace

std::unique_ptr<PlatformTunDevice> PlatformTunDevice::create() {
#if defined(TX_PLATFORM_WINDOWS)
    return std::unique_ptr<PlatformTunDevice>(new WintunDevice());
#elif defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
    return std::unique_ptr<PlatformTunDevice>(new PosixTunDevice());
#else
    return nullptr;
#endif
}

} // namespace tx
