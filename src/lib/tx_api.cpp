#include "tx_api.h"
#include "tx/common/log.h"

// Include the app headers via relative paths
#include "../client/client_app.h"
#include "../server/server_app.h"

#include <thread>
#include <memory>
#include <atomic>
#include <utility>
#include <cstring>
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <unistd.h>
#endif

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
                         const tx_android_network_hooks_t* hooks,
                         bool require_explicit_dns) {
    if (!config || !config->config_path) return nullptr;

    tx::SocketProtectCallback socket_protector;
    tx::DnsResolver::HostResolveHook host_resolver;
    tx::DnsResolver::QueryHook dns_query;
    if (hooks && hooks->protect_socket) {
        socket_protector = [hooks = *hooks](int fd) {
            return hooks.protect_socket(fd, hooks.user_data) != 0;
        };
    }
    if (hooks && hooks->resolve_host) {
        host_resolver = [hooks = *hooks](const std::string& host, int family) {
            tx_android_address_t output[TX_ANDROID_MAX_RESOLVED_ADDRESSES]{};
            int count = hooks.resolve_host(host.c_str(), family, output,
                                           TX_ANDROID_MAX_RESOLVED_ADDRESSES,
                                           hooks.user_data);
            std::vector<std::string> result;
            for (int i = 0; i < count && i < static_cast<int>(TX_ANDROID_MAX_RESOLVED_ADDRESSES); ++i)
                if (output[i].address[0]) result.emplace_back(output[i].address);
            return result;
        };
    }
    if (hooks && hooks->query_dns) {
        dns_query = [hooks = *hooks](const uint8_t* query, size_t length) {
            std::vector<uint8_t> response(65535);
            unsigned int response_length = 0;
            int ok = hooks.query_dns(query, static_cast<unsigned int>(length),
                                     response.data(), static_cast<unsigned int>(response.size()),
                                     &response_length, hooks.user_data);
            if (!ok || response_length > response.size()) return std::vector<uint8_t>();
            response.resize(response_length);
            return response;
        };
    }

    auto* handle = new TxClientHandle;
    handle->app = std::make_unique<tx::ClientApp>(std::move(socket_protector),
                                                  std::move(host_resolver),
                                                  std::move(dns_query));

    tx::ClientConfig cfg;
    if (!tx::load_client_config(config->config_path, cfg)) {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
        if (tun_fd >= 0) ::close(tun_fd);
#endif
        delete handle;
        return nullptr;
    }

    if (require_explicit_dns && cfg.dns_upstreams.empty()) {
        TX_ERROR("tx_client_start_android requires dns.upstreams or "
                 "tx_client_start_android_ex DNS hooks");
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
        if (tun_fd >= 0) ::close(tun_fd);
#endif
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
    return start_client(config, -1, nullptr, false);
}

tx_handle_t tx_client_start_with_tun_fd(const tx_client_config_t* config, int tun_fd) {
    return start_client(config, tun_fd, nullptr, false);
}

tx_handle_t tx_client_start_android(const tx_client_config_t* config, int tun_fd,
                                    tx_socket_protect_fn protect_fn,
                                    void* protect_user_data) {
    if (tun_fd < 0 || !protect_fn) return nullptr;
    tx_android_network_hooks_t hooks{};
    hooks.struct_size = sizeof(hooks);
    hooks.version = TX_ANDROID_NETWORK_HOOKS_VERSION;
    hooks.protect_socket = protect_fn;
    hooks.user_data = protect_user_data;
    return start_client(config, tun_fd, &hooks, true);
}

tx_handle_t tx_client_start_android_ex(const tx_client_config_t* config, int tun_fd,
                                       const tx_android_network_hooks_t* hooks) {
    if (tun_fd < 0 || !hooks || hooks->struct_size < sizeof(tx_android_network_hooks_t) ||
        hooks->version != TX_ANDROID_NETWORK_HOOKS_VERSION || !hooks->protect_socket ||
        !hooks->resolve_host || !hooks->query_dns) return nullptr;
    return start_client(config, tun_fd, hooks, false);
}

void tx_client_notify_network_changed(tx_handle_t handle) {
    if (!handle) return;
    auto* h = static_cast<TxClientHandle*>(handle);
    if (h->app) h->app->notify_network_changed();
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
