#include "tx_api.h"
#include "tx/common/log.h"

// Include the app headers via relative paths
#include "../client/client_app.h"
#include "../server/server_app.h"

#include <thread>
#include <memory>
#include <atomic>
#include <utility>

struct TxClientHandle {
    std::unique_ptr<tx::ClientApp> app;
    std::thread thread;
    std::atomic<bool> running{false};
};

struct TxServerHandle {
    std::unique_ptr<tx::ServerApp> app;
    std::thread thread;
    std::atomic<bool> running{false};
};

namespace {

tx_handle_t start_client(const tx_client_config_t* config, int tun_fd,
                         tx_socket_protect_fn protect_fn, void* protect_user_data) {
    if (!config || !config->config_path) return nullptr;

    tx::SocketProtectCallback socket_protector;
    if (protect_fn) {
        socket_protector = [protect_fn, protect_user_data](int fd) {
            return protect_fn(fd, protect_user_data) != 0;
        };
    }

    auto* handle = new TxClientHandle;
    handle->app = std::make_unique<tx::ClientApp>(std::move(socket_protector));

    tx::ClientConfig cfg;
    if (!tx::load_client_config(config->config_path, cfg)) {
        delete handle;
        return nullptr;
    }

    if (config->log_level) {
        cfg.log_level = config->log_level;
    }
    if (tun_fd >= 0) {
        cfg.tun_enabled = true;
        cfg.tun_fd = tun_fd;
    }

    if (!handle->app->init(cfg)) {
        delete handle;
        return nullptr;
    }

    handle->running = true;
    handle->thread = std::thread([handle]() {
        handle->app->run();
        handle->running = false;
    });

    return static_cast<tx_handle_t>(handle);
}

} // namespace

extern "C" {

tx_handle_t tx_client_start(const tx_client_config_t* config) {
    return start_client(config, -1, nullptr, nullptr);
}

tx_handle_t tx_client_start_with_tun_fd(const tx_client_config_t* config, int tun_fd) {
    return start_client(config, tun_fd, nullptr, nullptr);
}

tx_handle_t tx_client_start_android(const tx_client_config_t* config, int tun_fd,
                                    tx_socket_protect_fn protect_fn,
                                    void* protect_user_data) {
    if (tun_fd < 0 || !protect_fn) return nullptr;
    return start_client(config, tun_fd, protect_fn, protect_user_data);
}

void tx_client_stop(tx_handle_t handle) {
    if (!handle) return;
    auto* h = static_cast<TxClientHandle*>(handle);
    h->app->stop();
    if (h->thread.joinable()) h->thread.join();
    delete h;
}

int tx_client_get_traffic_stats(tx_handle_t handle, tx_traffic_stats_t* stats) {
    if (!handle || !stats) return -1;
    auto* h = static_cast<TxClientHandle*>(handle);
    if (!h->app) return -1;
    tx::ClientTrafficStats current = h->app->traffic_stats();
    stats->direct_upload_bytes = current.direct_upload_bytes;
    stats->direct_download_bytes = current.direct_download_bytes;
    stats->proxy_upload_bytes = current.proxy_upload_bytes;
    stats->proxy_download_bytes = current.proxy_download_bytes;
    return 0;
}

tx_handle_t tx_server_start(const tx_server_config_t* config) {
    if (!config || !config->config_path) return nullptr;

    auto* handle = new TxServerHandle;
    handle->app = std::make_unique<tx::ServerApp>();

    tx::ServerConfig cfg;
    if (!tx::load_server_config(config->config_path, cfg)) {
        delete handle;
        return nullptr;
    }

    if (config->log_level) {
        cfg.log_level = config->log_level;
    }

    if (!handle->app->init(cfg)) {
        delete handle;
        return nullptr;
    }

    handle->running = true;
    handle->thread = std::thread([handle]() {
        handle->app->run();
        handle->running = false;
    });

    return static_cast<tx_handle_t>(handle);
}

void tx_server_stop(tx_handle_t handle) {
    if (!handle) return;
    auto* h = static_cast<TxServerHandle*>(handle);
    h->app->stop();
    if (h->thread.joinable()) h->thread.join();
    delete h;
}

const char* tx_version(void) {
    return "1.0.0";
}

} // extern "C"
