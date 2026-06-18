#include "tx_api.h"
#include "tx/common/log.h"

// Include the app headers via relative paths
#include "../client/client_app.h"
#include "../server/server_app.h"

#include <thread>
#include <memory>
#include <atomic>

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

extern "C" {

tx_handle_t tx_client_start(const tx_client_config_t* config) {
    if (!config || !config->config_path) return nullptr;

    auto* handle = new TxClientHandle;
    handle->app = std::make_unique<tx::ClientApp>();

    tx::ClientConfig cfg;
    if (!tx::load_client_config(config->config_path, cfg)) {
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

void tx_client_stop(tx_handle_t handle) {
    if (!handle) return;
    auto* h = static_cast<TxClientHandle*>(handle);
    h->app->stop();
    if (h->thread.joinable()) h->thread.join();
    delete h;
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
