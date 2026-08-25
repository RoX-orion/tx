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
#include <ws2tcpip.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <io.h>
#endif

namespace tx {

namespace {

PlatformTunDevice::CommandRunner g_command_runner;

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)

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
#if !defined(TX_PLATFORM_ANDROID)
            if (!configure_linux(config, error)) {
                close();
                return false;
            }
#endif
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

        if (!configure_linux(config, error)) {
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
        remove_addresses();
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

    WriteResult write_packet(const uint8_t* data, size_t len,
                             std::string& error) override {
        if (fd_ < 0) {
            error = "TUN device is closed";
            return WriteResult::Error;
        }
        for (;;) {
            const ssize_t n = ::write(fd_, data, len);
            if (n == static_cast<ssize_t>(len)) return WriteResult::Written;
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return WriteResult::WouldBlock;
            }
            if (n >= 0) error = "partial TUN packet write";
            else error = std::strerror(errno);
            return WriteResult::Error;
        }
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
    bool configure_linux(const ClientConfig& config, std::string& error) {
        if (config.tun_auto_config && !configure_interface(config, error)) {
            return false;
        }

        std::vector<std::string> routes = config.tun_routes;
        if (config.tun_auto_route && routes.empty()) {
            routes = {"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"};
        }
        if (!routes.empty() && !install_policy_routes(config, routes, error)) {
            remove_addresses();
            return false;
        }
        return true;
    }

    bool configure_interface(const ClientConfig& config, std::string& error) {
        for (const auto& cidr : config.tun_addresses) {
            const bool ipv6 = cidr.find(':') != std::string::npos;
            const std::vector<std::string> show = {
                ipv6 ? "-6" : "-4", "address", "show", "dev", name_, "to", cidr};
            const CommandResult existing = run_ip(show);
            if (existing.exit_code != 0) {
                error = "failed to inspect Linux TUN address: " + cidr;
                remove_addresses();
                return false;
            }
            if (!existing.output.empty()) continue;
            const std::vector<std::string> add = {
                ipv6 ? "-6" : "-4", "address", "add", cidr, "dev", name_};
            if (run_ip(add).exit_code != 0) {
                error = "failed to add Linux TUN address: " + cidr;
                remove_addresses();
                return false;
            }
            installed_address_undo_.push_back(
                {ipv6 ? "-6" : "-4", "address", "del", cidr, "dev", name_});
        }

        if (config.tun_mtu > 0 &&
            run_ip({"link", "set", "dev", name_, "mtu",
                    std::to_string(config.tun_mtu)}).exit_code != 0) {
            error = "failed to set Linux TUN MTU";
            remove_addresses();
            return false;
        }
        if (run_ip({"link", "set", "dev", name_, "up"}).exit_code != 0) {
            error = "failed to bring Linux TUN interface up";
            remove_addresses();
            return false;
        }

        return true;
    }

    static CommandResult run_ip(const std::vector<std::string>& arguments) {
        if (g_command_runner) return g_command_runner(arguments);
        int output_pipe[2];
        if (pipe(output_pipe) != 0) return CommandResult{};
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("ip"));
        for (const auto& argument : arguments)
            argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr);
        pid_t child = fork();
        if (child < 0) {
            ::close(output_pipe[0]);
            ::close(output_pipe[1]);
            return CommandResult{};
        }
        if (child == 0) {
            ::close(output_pipe[0]);
            dup2(output_pipe[1], STDOUT_FILENO);
            dup2(output_pipe[1], STDERR_FILENO);
            ::close(output_pipe[1]);
            // Keep iproute2 diagnostics stable because the policy-table
            // existence check below has to distinguish an absent table from
            // a real inspection failure.
            setenv("LC_ALL", "C", 1);
            execvp("ip", argv.data());
            _exit(127);
        }
        ::close(output_pipe[1]);
        CommandResult result;
        char buffer[1024];
        for (;;) {
            const ssize_t count = ::read(output_pipe[0], buffer, sizeof(buffer));
            if (count > 0) result.output.append(buffer, static_cast<size_t>(count));
            else if (count < 0 && errno == EINTR) continue;
            else break;
        }
        ::close(output_pipe[0]);
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return result;
    }

    bool install_policy_routes(const ClientConfig& config,
                               std::vector<std::string> routes,
                               std::string& error) {
        policy_table_ = config.tun_route_table;
        policy_priority_ = config.tun_rule_priority;
        policy_mark_ = config.tun_tcp_stack == "lwip"
            ? config.tun_bypass_mark : config.tun_redirect_mark;
        const std::string table = std::to_string(policy_table_);
        const std::string priority = std::to_string(policy_priority_);
        const std::string catch_priority = std::to_string(policy_priority_ + 1);
        const std::string mark = std::to_string(policy_mark_) + "/0xffffffff";
        bool need_ipv4 = false;
        bool need_ipv6 = false;
        for (const auto& route : routes) {
            if (route.find(':') != std::string::npos) need_ipv6 = true;
            else need_ipv4 = true;
        }
        const auto reclaim_rule = [&](const char* family,
                                      const std::string& rule_priority,
                                      const std::vector<std::string>& exact_delete,
                                      const std::string& what) {
            const std::vector<std::string> show = {
                family, "rule", "show", "priority", rule_priority};
            CommandResult result = run_ip(show);
            if (result.exit_code != 0) {
                error = "failed to inspect Linux TUN policy rule: " + what;
                return false;
            }
            if (result.output.empty()) return true;

            // A crashed or older client can leave policy rules behind after
            // its non-persistent TUN interface has disappeared. Delete only
            // the rule that exactly matches this configuration, then inspect
            // the priority again so unrelated rules remain a hard conflict.
            if (run_ip(exact_delete).exit_code == 0) {
                result = run_ip(show);
                if (result.exit_code != 0) {
                    error = "failed to inspect Linux TUN policy rule: " + what;
                    return false;
                }
                if (result.output.empty()) {
                    TX_WARN("Removed stale Linux TUN policy rule: %s", what.c_str());
                    return true;
                }
            }

            error = "Linux TUN policy conflict: " + what;
            return false;
        };
        for (const char* family : {"-4", "-6"}) {
            if ((family[1] == '4' && !need_ipv4) ||
                (family[1] == '6' && !need_ipv6)) continue;
            if (!reclaim_rule(
                    family, priority,
                    {family, "rule", "del", "priority", priority, "fwmark", mark,
                     "lookup", "main"},
                    std::string(family) + " priority " + priority) ||
                !reclaim_rule(
                    family, catch_priority,
                    {family, "rule", "del", "priority", catch_priority,
                     "lookup", table},
                    std::string(family) + " priority " + catch_priority)) return false;
        }
        for (const auto& route : routes) {
            const bool ipv6 = route.find(':') != std::string::npos;
            const char* family = ipv6 ? "-6" : "-4";
            const std::vector<std::string> show = {
                family, "route", "show", "table", table, "exact", route};
            CommandResult result = run_ip(show);
            // iproute2 reports ENOENT for a table that has never contained a
            // route. That is the expected clean-start state, not a conflict.
            if (result.exit_code != 0 &&
                result.output.find("FIB table does not exist") == std::string::npos) {
                error = "failed to inspect Linux TUN policy route: " + route;
                return false;
            }
            if (result.exit_code == 0 && !result.output.empty()) {
                const CommandResult removed = run_ip(
                    {family, "route", "del", "table", table, route, "dev", name_});
                if (removed.exit_code == 0) {
                    result = run_ip(show);
                    if ((result.exit_code == 0 && result.output.empty()) ||
                        (result.exit_code != 0 &&
                         result.output.find("FIB table does not exist") !=
                             std::string::npos)) {
                        TX_WARN("Removed stale Linux TUN policy route: %s", route.c_str());
                        continue;
                    }
                    if (result.exit_code != 0) {
                        error = "failed to inspect Linux TUN policy route: " + route;
                        return false;
                    }
                }
                error = "Linux TUN policy conflict: route " + route;
                return false;
            }
        }

        for (const auto& route : routes) {
            const bool ipv6 = route.find(':') != std::string::npos;
            const char* family = ipv6 ? "-6" : "-4";
            std::vector<std::string> args = {family, "route", "add",
                                             "table", table, route, "dev", name_};
            if (run_ip(args).exit_code != 0) {
                error = "failed to install Linux TUN policy route: " + route;
                remove_policy_routes();
                return false;
            }
            policy_undo_.push_back({family, "route", "del", "table", table,
                                    route, "dev", name_});
        }
        for (const char* family : {"-4", "-6"}) {
            if ((family[1] == '4' && !need_ipv4) ||
                (family[1] == '6' && !need_ipv6)) continue;
            std::vector<std::string> add_mark = {
                family, "rule", "add", "priority", priority, "fwmark", mark,
                "lookup", "main"};
            if (run_ip(add_mark).exit_code != 0) {
                error = "failed to install Linux TUN mark bypass rule";
                remove_policy_routes();
                return false;
            }
            policy_undo_.push_back({family, "rule", "del", "priority", priority,
                                    "fwmark", mark, "lookup", "main"});
            std::vector<std::string> add_capture = {
                family, "rule", "add", "priority", catch_priority, "lookup", table};
            if (run_ip(add_capture).exit_code != 0) {
                error = "failed to install Linux TUN capture rule";
                remove_policy_routes();
                return false;
            }
            policy_undo_.push_back({family, "rule", "del", "priority", catch_priority,
                                    "lookup", table});
        }
        return true;
    }

    void remove_policy_routes() {
        for (auto it = policy_undo_.rbegin(); it != policy_undo_.rend(); ++it)
            run_ip(*it);
        policy_undo_.clear();
    }

    void remove_addresses() {
        for (auto it = installed_address_undo_.rbegin();
             it != installed_address_undo_.rend(); ++it) run_ip(*it);
        installed_address_undo_.clear();
    }
#endif

    int fd_ = -1;
    bool external_fd_ = false;
    std::string name_;
#if !defined(TX_PLATFORM_ANDROID)
    uint32_t policy_table_ = 20220;
    uint32_t policy_priority_ = 10000;
    uint32_t policy_mark_ = 0x2024;
    std::vector<std::vector<std::string>> policy_undo_;
    std::vector<std::vector<std::string>> installed_address_undo_;
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
    const std::string prefix_text = cidr.substr(slash + 1);
    if (prefix_text.empty() ||
        prefix_text.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    char* end = nullptr;
    long p = std::strtol(prefix_text.c_str(), &end, 10);
    if (end != prefix_text.c_str() + prefix_text.size() || p < 0 || p > 32) return false;
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

bool parse_ip_cidr_win(const std::string& cidr, SOCKADDR_INET& address, UINT8& prefix) {
    const size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    const std::string host = cidr.substr(0, slash);
    const std::string prefix_text = cidr.substr(slash + 1);
    if (prefix_text.empty() ||
        prefix_text.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    char* end = nullptr;
    const long parsed_prefix = std::strtol(prefix_text.c_str(), &end, 10);
    if (end != prefix_text.c_str() + prefix_text.size()) return false;
    std::memset(&address, 0, sizeof(address));
    if (host.find(':') == std::string::npos) {
        if (parsed_prefix < 0 || parsed_prefix > 32) return false;
        address.Ipv4.sin_family = AF_INET;
        if (InetPtonA(AF_INET, host.c_str(), &address.Ipv4.sin_addr) != 1) return false;
    } else {
        if (parsed_prefix < 0 || parsed_prefix > 128) return false;
        address.Ipv6.sin6_family = AF_INET6;
        if (InetPtonA(AF_INET6, host.c_str(), &address.Ipv6.sin6_addr) != 1) return false;
    }
    prefix = static_cast<UINT8>(parsed_prefix);
    return true;
}

class WintunDevice final : public PlatformTunDevice {
public:
    ~WintunDevice() override { close(); }

    bool open(const ClientConfig& config, std::string& error) override {
        if (config.tun_fd >= 0) {
            _close(config.tun_fd);
            error = "Windows does not support starting TUN from an owned CRT fd";
            return false;
        }
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
        socket_policy_ = OutboundSocketPolicy();
        for (const auto& route : installed_routes_) {
            DeleteIpForwardEntry2(&route);
        }
        installed_routes_.clear();
        for (const auto& address : installed_addresses_) {
            DeleteUnicastIpAddressEntry(&address);
        }
        installed_addresses_.clear();
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
    OutboundSocketPolicy outbound_socket_policy() const override {
        return socket_policy_;
    }

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

    WriteResult write_packet(const uint8_t* data, size_t len,
                             std::string& error) override {
        BYTE* packet = allocate_send_packet_(session_, static_cast<DWORD>(len));
        if (!packet) {
            if (GetLastError() == ERROR_BUFFER_OVERFLOW) {
                return WriteResult::WouldBlock;
            }
            error = "WintunAllocateSendPacket failed";
            return WriteResult::Error;
        }
        std::memcpy(packet, data, len);
        send_packet_(session_, packet);
        return WriteResult::Written;
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
        socket_policy_.ipv4_interface = ipv4;
        socket_policy_.ipv6_interface = ipv6;
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
        for (const auto& cidr : config.tun_addresses) {
            SOCKADDR_INET interface_addr{};
            UINT8 interface_prefix = 0;
            if (!parse_ip_cidr_win(cidr, interface_addr, interface_prefix)) {
                error = "invalid tun.addresses CIDR on Windows: " + cidr;
                return false;
            }
            MIB_UNICASTIPADDRESS_ROW row;
            InitializeUnicastIpAddressEntry(&row);
            row.InterfaceLuid = luid_;
            row.Address = interface_addr;
            row.OnLinkPrefixLength = interface_prefix;
            DWORD r = CreateUnicastIpAddressEntry(&row);
            if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
                error = "CreateUnicastIpAddressEntry failed for " + cidr;
                return false;
            }
            if (r == NO_ERROR) installed_addresses_.push_back(row);
        }

        std::vector<std::string> routes = config.tun_routes;
        if (config.tun_auto_route && routes.empty()) {
            routes = {"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"};
        }
        for (const auto& route : routes) {
            SOCKADDR_INET dst{};
            UINT8 prefix = 0;
            if (!parse_ip_cidr_win(route, dst, prefix)) {
                error = "invalid tun.routes CIDR on Windows: " + route;
                return false;
            }
            MIB_IPFORWARD_ROW2 row;
            InitializeIpForwardEntry(&row);
            row.InterfaceLuid = luid_;
            row.DestinationPrefix.Prefix = dst;
            row.DestinationPrefix.PrefixLength = prefix;
            row.NextHop.si_family = dst.si_family;
            row.Metric = 0;
            DWORD r = CreateIpForwardEntry2(&row);
            if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
                error = "CreateIpForwardEntry2 failed for " + route;
                return false;
            }
            if (r == NO_ERROR) installed_routes_.push_back(row);
        }
        return true;
    }

    HMODULE dll_ = nullptr;
    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;
    NET_LUID luid_{};
    std::string name_;
    OutboundSocketPolicy socket_policy_;

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
    std::vector<MIB_UNICASTIPADDRESS_ROW> installed_addresses_;
    std::vector<MIB_IPFORWARD_ROW2> installed_routes_;
};

#endif

} // namespace

void PlatformTunDevice::set_command_runner_for_testing(CommandRunner runner) {
    g_command_runner = std::move(runner);
}

void PlatformTunDevice::reset_command_runner_for_testing() {
    g_command_runner = CommandRunner();
}

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
