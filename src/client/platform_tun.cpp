#include "platform_tun.h"
#include "tx/common/log.h"
#include "tx/net/tcp_server.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
#if !defined(TX_PLATFORM_ANDROID)
        remove_policy_routes();
#endif
        // The native client takes ownership of a VpnService-provided fd.
        // This gives every startup failure and tx_client_stop() one cleanup
        // path and prevents the Java side from racing a duplicate close.
        if (fd_ >= 0) {
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
            in_addr interface_addr;
            int interface_prefix = 0;
            if (!parse_ipv4_cidr(config.tun_address, interface_addr, interface_prefix)) {
                error = "tun.address must be an IPv4 CIDR on Linux";
                close_sock();
                return false;
            }
            sockaddr_in addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr = interface_addr;
            std::memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
            if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
                error = std::string("SIOCSIFADDR failed: ") + std::strerror(errno);
                close_sock();
                return false;
            }

            sockaddr_in mask;
            std::memset(&mask, 0, sizeof(mask));
            mask.sin_family = AF_INET;
            mask.sin_addr.s_addr = prefix_to_netmask(interface_prefix);
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
        if (config.tun_auto_route && routes.empty() && config.tun_tcp_stack != "lwip") {
            routes.push_back("0.0.0.0/1");
            routes.push_back("128.0.0.0/1");
        }

        if (config.tun_tcp_stack == "lwip" && config.tun_auto_route) {
            if (!install_policy_routes(config, routes, error)) {
                close_sock();
                return false;
            }
        } else {
            for (const auto& route : routes) {
                if (!add_route(sock, route, error)) {
                    close_sock();
                    return false;
                }
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

    static bool run_ip(const std::vector<std::string>& arguments) {
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("ip"));
        for (const auto& argument : arguments)
            argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr);
        pid_t child = fork();
        if (child < 0) return false;
        if (child == 0) {
            execvp("ip", argv.data());
            _exit(127);
        }
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    bool install_policy_routes(const ClientConfig& config,
                               std::vector<std::string> routes,
                               std::string& error) {
        if (routes.empty()) {
            routes = {"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"};
        }
        policy_table_ = config.tun_route_table;
        policy_priority_ = config.tun_rule_priority;
        policy_mark_ = config.tun_bypass_mark;
        const std::string table = std::to_string(policy_table_);
        const std::string priority = std::to_string(policy_priority_);
        const std::string catch_priority = std::to_string(policy_priority_ + 1);
        const std::string mark = std::to_string(policy_mark_);
        run_ip({"rule", "del", "priority", priority, "fwmark", mark, "lookup", "main"});
        run_ip({"rule", "del", "priority", catch_priority, "lookup", table});
        policy_installed_ = true;
        if (!run_ip({"rule", "add", "priority", priority, "fwmark", mark,
                     "lookup", "main"}) ||
            !run_ip({"rule", "add", "priority", catch_priority, "lookup", table})) {
            error = "failed to install Linux TUN policy rules";
            remove_policy_routes();
            return false;
        }
        for (const auto& route : routes) {
            const bool ipv6 = route.find(':') != std::string::npos;
            std::vector<std::string> args = {ipv6 ? "-6" : "-4", "route", "replace",
                                             "table", table, route, "dev", name_};
            if (!run_ip(args)) {
                error = "failed to install Linux TUN policy route: " + route;
                remove_policy_routes();
                return false;
            }
            policy_routes_.push_back(route);
        }
        return true;
    }

    void remove_policy_routes() {
        if (!policy_installed_ && policy_routes_.empty()) return;
        const std::string table = std::to_string(policy_table_);
        for (const auto& route : policy_routes_) {
            const bool ipv6 = route.find(':') != std::string::npos;
            run_ip({ipv6 ? "-6" : "-4", "route", "del", "table", table,
                    route, "dev", name_});
        }
        run_ip({"rule", "del", "priority", std::to_string(policy_priority_),
                "fwmark", std::to_string(policy_mark_), "lookup", "main"});
        run_ip({"rule", "del", "priority", std::to_string(policy_priority_ + 1),
                "lookup", table});
        policy_routes_.clear();
        policy_installed_ = false;
    }
#endif

    int fd_ = -1;
    bool external_fd_ = false;
    std::string name_;
#if !defined(TX_PLATFORM_ANDROID)
    bool policy_installed_ = false;
    uint32_t policy_table_ = 20220;
    uint32_t policy_priority_ = 10000;
    uint32_t policy_mark_ = 0x2024;
    std::vector<std::string> policy_routes_;
#endif
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
using WintunGetReadWaitEventFn = HANDLE (WINAPI*)(WINTUN_SESSION_HANDLE);
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
        snapshot_outbound_interfaces();
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
        get_read_wait_event_ = load<WintunGetReadWaitEventFn>("WintunGetReadWaitEvent");
        release_receive_packet_ = load<WintunReleaseReceivePacketFn>("WintunReleaseReceivePacket");
        allocate_send_packet_ = load<WintunAllocateSendPacketFn>("WintunAllocateSendPacket");
        send_packet_ = load<WintunSendPacketFn>("WintunSendPacket");
        if (!create_adapter_ || !close_adapter_ || !get_adapter_luid_ ||
            !start_session_ || !end_session_ || !receive_packet_ ||
            !get_read_wait_event_ || !release_receive_packet_ ||
            !allocate_send_packet_ || !send_packet_) {
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
        stop_reader();
        TcpSession::set_outbound_interfaces(0, 0);
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

    bool start_async_reader(uv_loop_t* loop, std::function<void()> callback,
                            std::string& error) override {
        if (!session_ || reader_.joinable()) return session_ != nullptr;
        read_event_ = get_read_wait_event_(session_);
        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!read_event_ || !stop_event_) {
            error = "failed to create Wintun reader events";
            stop_reader();
            return false;
        }
        async_ = new uv_async_t;
        auto* context = new AsyncContext{std::move(callback)};
        async_->data = context;
        int result = uv_async_init(loop, async_, [](uv_async_t* handle) {
            auto* ctx = static_cast<AsyncContext*>(handle->data);
            if (ctx && ctx->callback) ctx->callback();
        });
        if (result != 0) {
            delete context;
            delete async_;
            async_ = nullptr;
            error = uv_strerror(result);
            stop_reader();
            return false;
        }
        reader_stop_.store(false);
        reader_ = std::thread([this]() { reader_loop(); });
        return true;
    }

    std::ptrdiff_t read_packet(uint8_t* data, size_t len, std::string& error) override {
        if (reader_.joinable()) {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (packet_queue_.empty()) return 0;
            std::vector<uint8_t> packet = std::move(packet_queue_.front());
            packet_queue_.pop_front();
            if (packet.size() > len) {
                error = "Wintun packet is larger than receive buffer";
                return -1;
            }
            std::memcpy(data, packet.data(), packet.size());
            return static_cast<std::ptrdiff_t>(packet.size());
        }
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
    struct AsyncContext { std::function<void()> callback; };

    void snapshot_outbound_interfaces() {
        sockaddr_in destination4{};
        destination4.sin_family = AF_INET;
        InetPtonA(AF_INET, "8.8.8.8", &destination4.sin_addr);
        DWORD ipv4 = 0;
        GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&destination4), &ipv4);
        sockaddr_in6 destination6{};
        destination6.sin6_family = AF_INET6;
        InetPtonA(AF_INET6, "2001:4860:4860::8888", &destination6.sin6_addr);
        DWORD ipv6 = 0;
        GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&destination6), &ipv6);
        TcpSession::set_outbound_interfaces(ipv4, ipv6);
    }

    void reader_loop() {
        HANDLE events[2] = {stop_event_, read_event_};
        while (!reader_stop_.load()) {
            DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) break;
            for (;;) {
                DWORD packet_size = 0;
                BYTE* packet = receive_packet_(session_, &packet_size);
                if (!packet) {
                    if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
                    reader_stop_.store(true);
                    break;
                }
                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    if (packet_queue_.size() >= 1024) packet_queue_.pop_front();
                    packet_queue_.emplace_back(packet, packet + packet_size);
                }
                release_receive_packet_(session_, packet);
            }
            if (async_) uv_async_send(async_);
        }
    }

    void stop_reader() {
        reader_stop_.store(true);
        if (stop_event_) SetEvent(stop_event_);
        if (reader_.joinable()) reader_.join();
        if (stop_event_) CloseHandle(stop_event_);
        stop_event_ = nullptr;
        read_event_ = nullptr;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            packet_queue_.clear();
        }
        if (async_) {
            uv_async_t* handle = async_;
            async_ = nullptr;
            uv_close(reinterpret_cast<uv_handle_t*>(handle), [](uv_handle_t* closed) {
                auto* async = reinterpret_cast<uv_async_t*>(closed);
                delete static_cast<AsyncContext*>(async->data);
                delete async;
            });
        }
    }

    template <typename T>
    T load(const char* name) {
        return reinterpret_cast<T>(GetProcAddress(dll_, name));
    }

    bool configure_interface(const ClientConfig& config, std::string& error) {
        if (!config.tun_address.empty()) {
            IN_ADDR interface_addr;
            UINT8 interface_prefix = 0;
            if (!parse_ipv4_cidr_win(config.tun_address, interface_addr,
                                     interface_prefix)) {
                error = "tun.address must be an IPv4 CIDR on Windows";
                return false;
            }
            MIB_UNICASTIPADDRESS_ROW row;
            InitializeUnicastIpAddressEntry(&row);
            row.InterfaceLuid = luid_;
            row.Address.si_family = AF_INET;
            sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&row.Address);
            addr->sin_addr = interface_addr;
            row.OnLinkPrefixLength = interface_prefix;
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
    WintunGetReadWaitEventFn get_read_wait_event_ = nullptr;
    WintunReleaseReceivePacketFn release_receive_packet_ = nullptr;
    WintunAllocateSendPacketFn allocate_send_packet_ = nullptr;
    WintunSendPacketFn send_packet_ = nullptr;
    HANDLE read_event_ = nullptr;
    HANDLE stop_event_ = nullptr;
    uv_async_t* async_ = nullptr;
    std::thread reader_;
    std::atomic<bool> reader_stop_{false};
    std::mutex queue_mutex_;
    std::deque<std::vector<uint8_t>> packet_queue_;
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
