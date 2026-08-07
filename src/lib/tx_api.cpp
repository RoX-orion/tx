#include "tx_api.h"
#include "tx/common/log.h"

// Include the app headers via relative paths
#include "../client/client_app.h"
#include "../server/server_app.h"

#include <thread>
#include <memory>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <exception>
#include <utility>
#include <cstring>
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <unistd.h>
#endif

enum class HandleKind {
    Client,
    Server,
};

struct HandleToken {
    uint64_t serial = 0;
};

struct HandleState {
    explicit HandleState(HandleKind handle_kind) : kind(handle_kind) {}
    virtual ~HandleState() = default;

    HandleKind kind;
    std::mutex mutex;
    std::condition_variable cv;
    bool stopping = false;
    size_t active_calls = 0;
    bool worker_start_released = false;
};

struct TxClientHandle : HandleState {
    TxClientHandle() : HandleState(HandleKind::Client) {}
    std::unique_ptr<tx::ClientApp> app;
    std::thread thread;
    std::atomic<bool> running{false};
};

struct TxServerHandle : HandleState {
    TxServerHandle() : HandleState(HandleKind::Server) {}
    std::unique_ptr<tx::ServerApp> app;
    std::thread thread;
    std::atomic<bool> running{false};
};

namespace {

struct TunFdGuard {
    explicit TunFdGuard(int value) : fd(value) {}
    ~TunFdGuard() {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
        if (fd >= 0) ::close(fd);
#endif
    }
    void release() { fd = -1; }
    int fd;
};

// tx_handle_t is intentionally opaque to callers.  The registry is consulted
// by pointer value only; no API entry dereferences a caller-supplied handle
// before it has been validated.  Token objects are retained for the lifetime
// of the library so an old handle can never be reused for a new state (ABA).
class HandleRegistry {
public:
    tx_handle_t insert(const std::shared_ptr<HandleState>& state) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto token = std::make_unique<HandleToken>();
        token->serial = next_serial_++;
        HandleToken* raw = token.get();
        tokens_.push_back(std::move(token));
        states_[raw] = state;
        return static_cast<tx_handle_t>(raw);
    }

    std::shared_ptr<HandleState> find(tx_handle_t handle, HandleKind kind) {
        if (!handle) return std::shared_ptr<HandleState>();
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(static_cast<HandleToken*>(handle));
        if (it == states_.end() || !it->second || it->second->kind != kind) {
            return std::shared_ptr<HandleState>();
        }
        return it->second;
    }

    void erase(tx_handle_t handle) {
        if (!handle) return;
        std::lock_guard<std::mutex> lock(mutex_);
        states_.erase(static_cast<HandleToken*>(handle));
    }

private:
    std::mutex mutex_;
    uint64_t next_serial_ = 1;
    std::unordered_map<HandleToken*, std::shared_ptr<HandleState>> states_;
    std::vector<std::unique_ptr<HandleToken>> tokens_;
};

HandleRegistry& handle_registry() {
    static HandleRegistry registry;
    return registry;
}

class ActiveApiCall {
public:
    explicit ActiveApiCall(std::shared_ptr<HandleState> state)
        : state_(std::move(state)) {}

    ~ActiveApiCall() {
        if (!state_) return;
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->active_calls > 0) --state_->active_calls;
        if (state_->active_calls == 0) state_->cv.notify_all();
    }

    ActiveApiCall(const ActiveApiCall&) = delete;
    ActiveApiCall& operator=(const ActiveApiCall&) = delete;

private:
    std::shared_ptr<HandleState> state_;
};

std::shared_ptr<HandleState> acquire_api_call(tx_handle_t handle, HandleKind kind) {
    auto state = handle_registry().find(handle, kind);
    if (!state) return std::shared_ptr<HandleState>();
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->stopping) return std::shared_ptr<HandleState>();
    ++state->active_calls;
    return state;
}

void stop_app_safely(tx::ClientApp* app) {
    if (!app) return;
    try {
        app->stop();
    } catch (const std::exception& e) {
        TX_ERROR("tx client stop failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx client stop failed with unknown exception");
    }
}

void stop_app_safely(tx::ServerApp* app) {
    if (!app) return;
    try {
        app->stop();
    } catch (const std::exception& e) {
        TX_ERROR("tx server stop failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx server stop failed with unknown exception");
    }
}

template <typename Handle>
void finish_worker_from_self(const std::shared_ptr<Handle>& state) {
    std::thread worker = std::move(state->thread);
    if (!worker.joinable()) {
        state->app.reset();
        return;
    }

    // A callback invoked by the worker may call tx_*_stop().  Joining the
    // current thread is invalid; move the join to a short-lived reaper.  If
    // creating that reaper fails, detaching is still safe because the worker
    // owns a shared reference to state and the app remains alive until it
    // returns.
    try {
        std::thread([state, worker = std::move(worker)]() mutable {
            try {
                worker.join();
                state->app.reset();
            } catch (const std::exception& e) {
                TX_ERROR("failed to join tx worker from reaper: %s", e.what());
                if (worker.joinable()) worker.detach();
            } catch (...) {
                TX_ERROR("failed to join tx worker from reaper");
                if (worker.joinable()) worker.detach();
            }
        }).detach();
    } catch (const std::exception& e) {
        TX_ERROR("failed to create tx stop reaper: %s", e.what());
        worker.detach();
    } catch (...) {
        TX_ERROR("failed to create tx stop reaper");
        worker.detach();
    }
}

template <typename Handle>
void stop_registered_handle(tx_handle_t handle, HandleKind kind) noexcept {
    try {
        auto base = handle_registry().find(handle, kind);
        if (!base) return;
        auto state = std::static_pointer_cast<Handle>(base);

        {
            std::unique_lock<std::mutex> lock(state->mutex);
            if (state->stopping) return;
            state->stopping = true;
            // Remove the registry entry before waiting.  New calls fail
            // immediately, while calls which already acquired the state are
            // covered by active_calls below.
            handle_registry().erase(handle);
            state->cv.wait(lock, [&state]() { return state->active_calls == 0; });
        }

        stop_app_safely(state->app.get());
        if (!state->thread.joinable()) {
            state->app.reset();
            return;
        }
        if (state->thread.get_id() == std::this_thread::get_id()) {
            finish_worker_from_self(state);
            return;
        }
        try {
            state->thread.join();
        } catch (const std::exception& e) {
            TX_ERROR("failed to join tx worker: %s", e.what());
            if (state->thread.joinable()) state->thread.detach();
            return;
        } catch (...) {
            TX_ERROR("failed to join tx worker");
            if (state->thread.joinable()) state->thread.detach();
            return;
        }
        state->app.reset();
    } catch (const std::exception& e) {
        TX_ERROR("tx handle stop failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx handle stop failed with unknown exception");
    }
}

void apply_log_level(const std::string& value) {
    if (value == "debug") {
        tx::set_log_level(tx::LogLevel::Debug);
    } else if (value == "warn") {
        tx::set_log_level(tx::LogLevel::Warn);
    } else if (value == "error") {
        tx::set_log_level(tx::LogLevel::Error);
    } else {
        tx::set_log_level(tx::LogLevel::Info);
    }
}

tx_handle_t start_client(const tx_client_config_t* config, int tun_fd,
                         const tx_android_network_hooks_t* hooks) {
    TunFdGuard tun_fd_guard(tun_fd);
    if (!config || !config->config_path) return nullptr;

    tx::SocketProtectCallback socket_protector;
    tx::DnsResolver::HostResolveHook host_resolver;
    tx::DnsResolver::QueryHook dns_query;
    if (hooks && hooks->protect_socket) {
        socket_protector = [hooks = *hooks](int fd) {
            return hooks.protect_socket(fd, hooks.user_data) != 0;
        };
    }
    // Android supplies Network-bound resolver hooks. ClientApp uses them for
    // TX bootstrap and DNS/targets that the router selected as direct; TX DNS
    // itself remains inside the encrypted tunnel.
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

    auto state = std::make_shared<TxClientHandle>();
    state->app = std::make_unique<tx::ClientApp>(std::move(socket_protector),
                                                 std::move(host_resolver),
                                                 std::move(dns_query),
                                                 hooks ? hooks->address_family_mask : 0);

    tx::ClientConfig cfg;
    if (!tx::load_client_config(config->config_path, cfg)) {
        return nullptr;
    }

    if (config->log_level) {
        cfg.log_level = config->log_level;
    }
    apply_log_level(cfg.log_level);
    if (tun_fd >= 0) {
        cfg.tun_enabled = true;
        cfg.tun_fd = tun_fd;
    }

    bool initialized = false;
    try {
        initialized = state->app->init(cfg);
    } catch (...) {
        // ClientApp claims cfg.tun_fd at the beginning of init(), including
        // exceptional failure paths.  Do not let the temporary guard close
        // the descriptor a second time while state is being destroyed.
        tun_fd_guard.release();
        throw;
    }
    tun_fd_guard.release();
    if (!initialized) return nullptr;

    tx_handle_t token = handle_registry().insert(state);
    try {
        state->running = true;
        state->thread = std::thread([state]() {
            {
                std::unique_lock<std::mutex> lock(state->mutex);
                state->cv.wait(lock, [&state]() { return state->worker_start_released; });
            }
            try {
                state->app->run();
            } catch (const std::exception& e) {
                TX_ERROR("tx client worker failed: %s", e.what());
            } catch (...) {
                TX_ERROR("tx client worker failed with unknown exception");
            }
            state->running = false;
        });
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->worker_start_released = true;
        }
        state->cv.notify_all();
    } catch (...) {
        handle_registry().erase(token);
        state->stopping = true;
        stop_app_safely(state->app.get());
        if (state->thread.joinable()) {
            try {
                state->thread.join();
            } catch (...) {
                if (state->thread.joinable()) state->thread.detach();
            }
        }
        if (!state->thread.joinable()) state->app.reset();
        throw;
    }

    return token;
}

} // namespace

extern "C" {

tx_handle_t tx_client_start(const tx_client_config_t* config) noexcept {
    try {
        return start_client(config, -1, nullptr);
    } catch (const std::exception& e) {
        TX_ERROR("tx_client_start failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_client_start failed with unknown exception");
    }
    return nullptr;
}

tx_handle_t tx_client_start_with_tun_fd(const tx_client_config_t* config, int tun_fd) noexcept {
    try {
        return start_client(config, tun_fd, nullptr);
    } catch (const std::exception& e) {
        TX_ERROR("tx_client_start_with_tun_fd failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_client_start_with_tun_fd failed with unknown exception");
    }
    return nullptr;
}

tx_handle_t tx_client_start_android(const tx_client_config_t* config, int tun_fd,
                                    tx_socket_protect_fn protect_fn,
                                    void* protect_user_data) noexcept {
    if (tun_fd < 0 || !protect_fn) {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
        if (tun_fd >= 0) ::close(tun_fd);
#endif
        return nullptr;
    }
    tx_android_network_hooks_t hooks{};
    hooks.struct_size = sizeof(hooks);
    hooks.version = TX_ANDROID_NETWORK_HOOKS_VERSION;
    hooks.protect_socket = protect_fn;
    hooks.user_data = protect_user_data;
    try {
        return start_client(config, tun_fd, &hooks);
    } catch (const std::exception& e) {
        TX_ERROR("tx_client_start_android failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_client_start_android failed with unknown exception");
    }
    return nullptr;
}

tx_handle_t tx_client_start_android_ex(const tx_client_config_t* config, int tun_fd,
                                       const tx_android_network_hooks_t* hooks) noexcept {
    if (tun_fd < 0 || !hooks || hooks->struct_size < sizeof(tx_android_network_hooks_t) ||
        hooks->version != TX_ANDROID_NETWORK_HOOKS_VERSION || !hooks->protect_socket ||
        !hooks->resolve_host || !hooks->query_dns) {
        TX_ERROR("Android extended client requires protect_socket, resolve_host and query_dns");
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
        if (tun_fd >= 0) ::close(tun_fd);
#endif
        return nullptr;
    }
    // Host/DNS hooks are used only for a route that has already selected a
    // direct outbound. Fake-IP DNS and TX-bound traffic remain inside the
    // encrypted tunnel, avoiding bootstrap leaks and VPN routing loops.
    try {
        return start_client(config, tun_fd, hooks);
    } catch (const std::exception& e) {
        TX_ERROR("tx_client_start_android_ex failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_client_start_android_ex failed with unknown exception");
    }
    return nullptr;
}

void tx_client_notify_network_changed(tx_handle_t handle) noexcept {
    try {
        auto base = acquire_api_call(handle, HandleKind::Client);
        if (!base) return;
        ActiveApiCall active(base);
        auto* state = static_cast<TxClientHandle*>(base.get());
        if (state->app) state->app->notify_network_changed();
    } catch (const std::exception& e) {
        TX_ERROR("tx_client_notify_network_changed failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_client_notify_network_changed failed with unknown exception");
    }
}

void tx_client_update_android_network_state(tx_handle_t handle,
                                            unsigned int address_family_mask) noexcept {
    try {
        auto base = acquire_api_call(handle, HandleKind::Client);
        if (!base) return;
        ActiveApiCall active(base);
        auto* state = static_cast<TxClientHandle*>(base.get());
        if (!state->app) return;
        state->app->update_android_address_family_mask(address_family_mask);
        state->app->notify_network_changed();
    } catch (const std::exception& e) {
        TX_ERROR("tx_client_update_android_network_state failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_client_update_android_network_state failed with unknown exception");
    }
}

void tx_client_stop(tx_handle_t handle) noexcept {
    stop_registered_handle<TxClientHandle>(handle, HandleKind::Client);
}

int tx_client_get_traffic_stats(tx_handle_t handle, tx_traffic_stats_t* stats) noexcept {
    if (!handle || !stats) return -1;
    try {
        auto base = acquire_api_call(handle, HandleKind::Client);
        if (!base) return -1;
        ActiveApiCall active(base);
        auto* state = static_cast<TxClientHandle*>(base.get());
        if (!state->app) return -1;
        tx::ClientTrafficStats current = state->app->traffic_stats();
        stats->direct_upload_bytes = current.direct_upload_bytes;
        stats->direct_download_bytes = current.direct_download_bytes;
        stats->proxy_upload_bytes = current.proxy_upload_bytes;
        stats->proxy_download_bytes = current.proxy_download_bytes;
        return 0;
    } catch (const std::exception& e) {
        TX_ERROR("tx_client_get_traffic_stats failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_client_get_traffic_stats failed with unknown exception");
    }
    return -1;
}

tx_handle_t tx_server_start(const tx_server_config_t* config) noexcept {
    if (!config || !config->config_path) return nullptr;
    try {
        auto state = std::make_shared<TxServerHandle>();
        state->app = std::make_unique<tx::ServerApp>();

        tx::ServerConfig cfg;
        if (!tx::load_server_config(config->config_path, cfg)) return nullptr;
        if (config->log_level) cfg.log_level = config->log_level;
        if (!state->app->init(cfg)) return nullptr;

        tx_handle_t token = handle_registry().insert(state);
        try {
            state->running = true;
            state->thread = std::thread([state]() {
                {
                    std::unique_lock<std::mutex> lock(state->mutex);
                    state->cv.wait(lock, [&state]() { return state->worker_start_released; });
                }
                try {
                    state->app->run();
                } catch (const std::exception& e) {
                    TX_ERROR("tx server worker failed: %s", e.what());
                } catch (...) {
                    TX_ERROR("tx server worker failed with unknown exception");
                }
                state->running = false;
            });
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->worker_start_released = true;
            }
            state->cv.notify_all();
        } catch (...) {
            handle_registry().erase(token);
            state->stopping = true;
            stop_app_safely(state->app.get());
            if (state->thread.joinable()) {
                try {
                    state->thread.join();
                } catch (...) {
                    if (state->thread.joinable()) state->thread.detach();
                }
            }
            if (!state->thread.joinable()) state->app.reset();
            throw;
        }
        return token;
    } catch (const std::exception& e) {
        TX_ERROR("tx_server_start failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_server_start failed with unknown exception");
    }
    return nullptr;
}

void tx_server_stop(tx_handle_t handle) noexcept {
    stop_registered_handle<TxServerHandle>(handle, HandleKind::Server);
}

const char* tx_version(void) noexcept {
    return "1.0.0";
}

} // extern "C"
