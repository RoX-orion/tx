#include "tx_api.h"
#include "tx/common/log.h"

#include <cassert>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <thread>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static tx_handle_t fake_handle(uintptr_t value) {
    return reinterpret_cast<tx_handle_t>(value);
}

static void test_log_level_concurrency() {
    std::atomic<bool> start{false};
    const auto writer = [&start](tx::LogLevel first, tx::LogLevel second) {
        while (!start.load(std::memory_order_acquire)) {}
        for (unsigned i = 0; i < 100000; ++i)
            tx::set_log_level((i & 1u) == 0 ? first : second);
    };
    std::thread first(writer, tx::LogLevel::Debug, tx::LogLevel::Warn);
    std::thread second(writer, tx::LogLevel::Info, tx::LogLevel::Error);
    start.store(true, std::memory_order_release);
    for (unsigned i = 0; i < 100000; ++i) {
        const tx::LogLevel level = tx::get_log_level();
        assert(level >= tx::LogLevel::Debug && level <= tx::LogLevel::Off);
    }
    first.join();
    second.join();
    tx::set_log_level(tx::LogLevel::Info);
}

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
static uint16_t unused_loopback_port() {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    const uint16_t port = ntohs(address.sin_port);
    assert(close(fd) == 0);
    return port;
}

static void test_server_lifecycle() {
    const std::string path = "/tmp/tx-api-server-" + std::to_string(getpid()) + ".json";
    {
        std::ofstream config(path);
        assert(config.is_open());
        config << "{\"listen\":{\"host\":\"127.0.0.1\",\"port\":"
               << unused_loopback_port()
               << "},\"secret\":\"hex:"
               << std::string(64, '1') << "\",\"log_level\":\"error\"}";
    }
    const tx_server_config_t config{path.c_str(), "error"};
    tx_handle_t handle = tx_server_start(&config);
    assert(handle != nullptr);
    assert(tx_client_stop(handle) == TX_STATUS_INVALID_HANDLE);
    assert(tx_server_wait(handle) == TX_STATUS_INVALID_STATE);
    assert(tx_server_destroy(handle) == TX_STATUS_INVALID_STATE);
    assert(tx_server_stop(handle) == TX_STATUS_OK);
    assert(tx_server_stop(handle) == TX_STATUS_OK);
    assert(tx_server_wait(handle) == TX_STATUS_OK);
    assert(tx_server_wait(handle) == TX_STATUS_OK);
    assert(tx_server_stop(handle) == TX_STATUS_OK);
    assert(tx_server_destroy(handle) == TX_STATUS_OK);
    assert(tx_server_destroy(handle) == TX_STATUS_INVALID_HANDLE);
    assert(tx_server_stop(handle) == TX_STATUS_INVALID_HANDLE);
    assert(unlink(path.c_str()) == 0);
}

struct HookLifecycleContext {
    std::atomic<tx_handle_t> handle{nullptr};
    std::atomic<int> calls{0};
    std::atomic<int> stop_status{TX_STATUS_INTERNAL_ERROR};
    std::atomic<int> wait_status{TX_STATUS_INTERNAL_ERROR};
};

static int stop_from_protect_hook(int, void* user_data) {
    auto* context = static_cast<HookLifecycleContext*>(user_data);
    const tx_handle_t handle = context->handle.load();
    if (handle) {
        context->stop_status = tx_client_stop(handle);
        context->wait_status = tx_client_wait(handle);
        ++context->calls;
    }
    return 0;
}

static int unused_resolve_hook(const char*, int, tx_android_address_t*,
                               unsigned int, void*) {
    return 0;
}

static int unused_query_hook(const unsigned char*, unsigned int,
                             unsigned char*, unsigned int,
                             unsigned int* response_length, void*) {
    if (response_length) *response_length = 0;
    return 0;
}

static void test_stop_from_hook_is_nonblocking() {
    const uint16_t http_port = unused_loopback_port();
    const uint16_t socks_port = unused_loopback_port();
    const std::string path = "/tmp/tx-api-client-" + std::to_string(getpid()) + ".json";
    {
        std::ofstream config(path);
        assert(config.is_open());
        config << "{\"listen\":{\"http\":{\"host\":\"127.0.0.1\",\"port\":"
               << http_port
               << "},\"socks5\":{\"host\":\"127.0.0.1\",\"port\":"
               << socks_port
               << "}},\"tun\":{\"enabled\":true,\"addresses\":[\"10.66.0.1/24\"],"
                  "\"auto_config\":false,\"auto_route\":false,"
                  "\"auto_redirect\":false,\"tcp_stack\":\"lwip\","
                  "\"udp_stack\":\"lwip\"},"
                  "\"outbounds\":[{\"tag\":\"direct-out\",\"type\":\"direct\"}],"
                  "\"routing\":{\"rules\":[{\"outboundTag\":\"direct-out\"}]},"
                  "\"log_level\":\"error\"}";
    }

    int tun_pipe[2];
    assert(pipe(tun_pipe) == 0);
    HookLifecycleContext context;
    tx_android_network_hooks_t hooks{};
    hooks.struct_size = sizeof(hooks);
    hooks.version = TX_ANDROID_NETWORK_HOOKS_VERSION;
    hooks.protect_socket = stop_from_protect_hook;
    hooks.resolve_host = unused_resolve_hook;
    hooks.query_dns = unused_query_hook;
    hooks.address_family_mask = TX_ANDROID_NETWORK_FAMILY_KNOWN |
                                TX_ANDROID_NETWORK_FAMILY_IPV4;
    hooks.user_data = &context;
    const tx_client_config_t config{path.c_str(), "error"};
    const tx_handle_t handle = tx_client_start_android_ex(&config, tun_pipe[0], &hooks);
    assert(handle != nullptr);
    context.handle = handle;

    const int peer = socket(AF_INET, SOCK_STREAM, 0);
    assert(peer >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(http_port);
    assert(connect(peer, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    const char request[] =
        "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n";
    assert(send(peer, request, sizeof(request) - 1, 0) ==
           static_cast<ssize_t>(sizeof(request) - 1));

    for (unsigned i = 0; i < 200 && context.calls.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    assert(context.calls.load() == 1);
    assert(context.stop_status.load() == TX_STATUS_OK);
    assert(context.wait_status.load() == TX_STATUS_REENTRANT_WAIT);
    assert(tx_client_wait(handle) == TX_STATUS_OK);
    // The callback context remains alive through wait and can now be released.
    assert(tx_client_destroy(handle) == TX_STATUS_OK);
    assert(close(peer) == 0);
    assert(close(tun_pipe[1]) == 0);
    assert(unlink(path.c_str()) == 0);
}
#endif

int main() {
    test_log_level_concurrency();
    tx_traffic_stats_t stats{};
    const tx_handle_t fake = fake_handle(1);
    const tx_client_config_t bad_client = {"/definitely/missing/tx-client.json", nullptr};
    const tx_server_config_t bad_server = {"/definitely/missing/tx-server.json", nullptr};

    assert(tx_client_start(nullptr) == nullptr);
    assert(tx_server_start(nullptr) == nullptr);
    assert(tx_client_start(&bad_client) == nullptr);
    assert(tx_server_start(&bad_server) == nullptr);
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
    int pipe_fds[2];
    assert(pipe(pipe_fds) == 0);
    assert(tx_client_start_with_tun_fd(&bad_client, pipe_fds[0]) == nullptr);
    errno = 0;
    assert(fcntl(pipe_fds[0], F_GETFD) == -1 && errno == EBADF);
    assert(close(pipe_fds[1]) == 0);
#endif
    assert(tx_client_get_traffic_stats(nullptr, &stats) == -1);
    assert(tx_client_get_traffic_stats(fake, &stats) == -1);

    tx_client_notify_network_changed(nullptr);
    tx_client_notify_network_changed(fake);
    tx_client_update_android_network_state(nullptr, 0);
    tx_client_update_android_network_state(fake, 0);
    assert(tx_client_stop(nullptr) == TX_STATUS_INVALID_ARGUMENT);
    assert(tx_client_wait(nullptr) == TX_STATUS_INVALID_ARGUMENT);
    assert(tx_client_destroy(nullptr) == TX_STATUS_INVALID_ARGUMENT);
    assert(tx_client_stop(fake) == TX_STATUS_INVALID_HANDLE);
    assert(tx_client_wait(fake) == TX_STATUS_INVALID_HANDLE);
    assert(tx_client_destroy(fake) == TX_STATUS_INVALID_HANDLE);
    assert(tx_server_stop(nullptr) == TX_STATUS_INVALID_ARGUMENT);
    assert(tx_server_wait(nullptr) == TX_STATUS_INVALID_ARGUMENT);
    assert(tx_server_destroy(nullptr) == TX_STATUS_INVALID_ARGUMENT);
    assert(tx_server_stop(fake) == TX_STATUS_INVALID_HANDLE);
    assert(tx_server_wait(fake) == TX_STATUS_INVALID_HANDLE);
    assert(tx_server_destroy(fake) == TX_STATUS_INVALID_HANDLE);

    assert(std::string(tx_version()) == "2.0.0");
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
    test_server_lifecycle();
    test_stop_from_hook_is_nonblocking();
#endif
    return 0;
}
