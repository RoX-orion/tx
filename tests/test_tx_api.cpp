#include "tx_api.h"

#include <cassert>
#include <cstdint>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

static tx_handle_t fake_handle(uintptr_t value) {
    return reinterpret_cast<tx_handle_t>(value);
}

int main() {
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
    tx_client_stop(nullptr);
    tx_client_stop(fake);
    tx_client_stop(fake);
    tx_server_stop(nullptr);
    tx_server_stop(fake);
    tx_server_stop(fake);

    assert(tx_version() != nullptr);
    return 0;
}
