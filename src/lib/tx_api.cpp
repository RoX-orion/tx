#include "tx_api.h"
#include "tx/common/log.h"
#include "tx/common/network.h"
#include "tx/version.h"

#include "../client/client_app.h"
#include "../server/server_app.h"

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(TX_PLATFORM_WINDOWS)
#include <io.h>
#else
#include <unistd.h>
#endif

enum class HandleKind { Client, Server };
enum class HandleLifecycle { Running, StopRequested, Stopped, Joined, Destroyed };

struct HandleToken {
    uint64_t serial = 0;
};

struct HandleState {
    explicit HandleState(HandleKind handle_kind) : kind(handle_kind) {}
    virtual ~HandleState() = default;

    HandleKind kind;
    std::mutex mutex;
    std::condition_variable cv;
    HandleLifecycle lifecycle = HandleLifecycle::Running;
    bool stop_called = false;
    bool joining = false;
    bool worker_start_released = false;
    size_t active_calls = 0;
    size_t active_hooks = 0;
};

struct TxClientHandle final : HandleState {
    TxClientHandle() : HandleState(HandleKind::Client) {}
    std::unique_ptr<tx::ClientApp> app;
    std::thread thread;
};

struct TxServerHandle final : HandleState {
    TxServerHandle() : HandleState(HandleKind::Server) {}
    std::unique_ptr<tx::ServerApp> app;
    std::thread thread;
};

namespace {

thread_local unsigned g_reentrant_api_context = 0;

void close_owned_fd(int fd) {
    if (fd < 0) return;
#if defined(TX_PLATFORM_WINDOWS)
    _close(fd);
#else
    ::close(fd);
#endif
}

struct TunFdGuard {
    explicit TunFdGuard(int value) : fd(value) {}
    ~TunFdGuard() { close_owned_fd(fd); }
    void release() { fd = -1; }
    int fd;
};

class HandleRegistry {
public:
    tx_handle_t insert(const std::shared_ptr<HandleState>& state) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::unique_ptr<HandleToken> token(new HandleToken());
        token->serial = next_serial_++;
        HandleToken* raw = token.get();
        tokens_.push_back(std::move(token));
        states_[raw] = state;
        return static_cast<tx_handle_t>(raw);
    }

    std::shared_ptr<HandleState> find(tx_handle_t handle, HandleKind kind) {
        if (!handle) return std::shared_ptr<HandleState>();
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = states_.find(static_cast<HandleToken*>(handle));
        if (it == states_.end() || !it->second || it->second->kind != kind)
            return std::shared_ptr<HandleState>();
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
    // Tokens remain allocated so a destroyed handle value is never reused.
    std::vector<std::unique_ptr<HandleToken>> tokens_;
};

HandleRegistry& handle_registry() {
    static HandleRegistry registry;
    return registry;
}

class WorkerContext {
public:
    WorkerContext() { ++g_reentrant_api_context; }
    ~WorkerContext() { --g_reentrant_api_context; }
    WorkerContext(const WorkerContext&) = delete;
    WorkerContext& operator=(const WorkerContext&) = delete;
};

class HookCallContext {
public:
    explicit HookCallContext(HandleState* state) : state_(state) {
        ++g_reentrant_api_context;
        if (state_) {
            std::lock_guard<std::mutex> lock(state_->mutex);
            ++state_->active_hooks;
        }
    }

    ~HookCallContext() {
        if (state_) {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->active_hooks != 0) --state_->active_hooks;
            state_->cv.notify_all();
        }
        --g_reentrant_api_context;
    }

    HookCallContext(const HookCallContext&) = delete;
    HookCallContext& operator=(const HookCallContext&) = delete;

private:
    HandleState* state_;
};

class ActiveApiCall {
public:
    explicit ActiveApiCall(std::shared_ptr<HandleState> state)
        : state_(std::move(state)) {}

    ~ActiveApiCall() {
        if (!state_) return;
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->active_calls != 0) --state_->active_calls;
        state_->cv.notify_all();
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
    if (state->lifecycle != HandleLifecycle::Running)
        return std::shared_ptr<HandleState>();
    ++state->active_calls;
    return state;
}

bool stop_app_safely(tx::ClientApp* app) {
    if (!app) return true;
    try {
        app->stop();
        return true;
    } catch (const std::exception& e) {
        TX_ERROR("tx client stop failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx client stop failed with unknown exception");
    }
    return false;
}

bool stop_app_safely(tx::ServerApp* app) {
    if (!app) return true;
    try {
        app->stop();
        return true;
    } catch (const std::exception& e) {
        TX_ERROR("tx server stop failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx server stop failed with unknown exception");
    }
    return false;
}

template <typename Handle>
tx_status_t stop_registered_handle(tx_handle_t handle, HandleKind kind) noexcept {
    if (!handle) return TX_STATUS_INVALID_ARGUMENT;
    try {
        auto base = handle_registry().find(handle, kind);
        if (!base) return TX_STATUS_INVALID_HANDLE;
        auto state = std::static_pointer_cast<Handle>(base);
        bool request_stop = false;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->lifecycle == HandleLifecycle::Destroyed)
                return TX_STATUS_INVALID_HANDLE;
            state->stop_called = true;
            if (state->lifecycle == HandleLifecycle::Running) {
                state->lifecycle = HandleLifecycle::StopRequested;
                request_stop = true;
            }
        }
        if (request_stop && !stop_app_safely(state->app.get()))
            return TX_STATUS_INTERNAL_ERROR;
        return TX_STATUS_OK;
    } catch (const std::exception& e) {
        TX_ERROR("tx stop failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx stop failed with unknown exception");
    }
    return TX_STATUS_INTERNAL_ERROR;
}

template <typename Handle>
tx_status_t wait_registered_handle(tx_handle_t handle, HandleKind kind) noexcept {
    if (!handle) return TX_STATUS_INVALID_ARGUMENT;
    try {
        auto base = handle_registry().find(handle, kind);
        if (!base) return TX_STATUS_INVALID_HANDLE;
        if (g_reentrant_api_context != 0) return TX_STATUS_REENTRANT_WAIT;
        auto state = std::static_pointer_cast<Handle>(base);

        std::unique_lock<std::mutex> lock(state->mutex);
        if (state->lifecycle == HandleLifecycle::Destroyed)
            return TX_STATUS_INVALID_HANDLE;
        if (!state->stop_called) return TX_STATUS_INVALID_STATE;
        for (;;) {
            if (state->lifecycle == HandleLifecycle::Joined) return TX_STATUS_OK;
            if (!state->joining) break;
            state->cv.wait(lock);
        }
        state->cv.wait(lock, [&state]() {
            return state->lifecycle == HandleLifecycle::Stopped &&
                   state->active_calls == 0 && state->active_hooks == 0;
        });
        state->joining = true;
        lock.unlock();

        try {
            if (!state->thread.joinable()) {
                lock.lock();
                state->joining = false;
                state->cv.notify_all();
                return TX_STATUS_INTERNAL_ERROR;
            }
            state->thread.join();
        } catch (const std::exception& e) {
            TX_ERROR("failed to join tx worker: %s", e.what());
            lock.lock();
            state->joining = false;
            state->cv.notify_all();
            return TX_STATUS_INTERNAL_ERROR;
        } catch (...) {
            TX_ERROR("failed to join tx worker");
            lock.lock();
            state->joining = false;
            state->cv.notify_all();
            return TX_STATUS_INTERNAL_ERROR;
        }

        lock.lock();
        state->joining = false;
        state->lifecycle = HandleLifecycle::Joined;
        state->cv.notify_all();
        return TX_STATUS_OK;
    } catch (const std::exception& e) {
        TX_ERROR("tx wait failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx wait failed with unknown exception");
    }
    return TX_STATUS_INTERNAL_ERROR;
}

template <typename Handle>
tx_status_t destroy_registered_handle(tx_handle_t handle, HandleKind kind) noexcept {
    if (!handle) return TX_STATUS_INVALID_ARGUMENT;
    try {
        auto base = handle_registry().find(handle, kind);
        if (!base) return TX_STATUS_INVALID_HANDLE;
        if (g_reentrant_api_context != 0) return TX_STATUS_REENTRANT_WAIT;
        auto state = std::static_pointer_cast<Handle>(base);
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->lifecycle == HandleLifecycle::Destroyed)
                return TX_STATUS_INVALID_HANDLE;
            if (state->lifecycle != HandleLifecycle::Joined || state->joining ||
                state->active_calls != 0 || state->active_hooks != 0) {
                return TX_STATUS_INVALID_STATE;
            }
            state->lifecycle = HandleLifecycle::Destroyed;
        }
        handle_registry().erase(handle);
        state->app.reset();
        return TX_STATUS_OK;
    } catch (const std::exception& e) {
        TX_ERROR("tx destroy failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx destroy failed with unknown exception");
    }
    return TX_STATUS_INTERNAL_ERROR;
}

bool apply_log_level(const std::string& value) {
    if (value == "debug") tx::set_log_level(tx::LogLevel::Debug);
    else if (value == "info") tx::set_log_level(tx::LogLevel::Info);
    else if (value == "warn") tx::set_log_level(tx::LogLevel::Warn);
    else if (value == "error") tx::set_log_level(tx::LogLevel::Error);
    else return false;
    return true;
}

template <typename Handle>
bool launch_worker(const std::shared_ptr<Handle>& state, const char* name) {
    try {
        state->thread = std::thread([state, name]() {
            {
                std::unique_lock<std::mutex> lock(state->mutex);
                state->cv.wait(lock, [&state]() {
                    return state->worker_start_released;
                });
            }
            WorkerContext context;
            try {
                state->app->run();
            } catch (const std::exception& e) {
                TX_ERROR("%s worker failed: %s", name, e.what());
            } catch (...) {
                TX_ERROR("%s worker failed with unknown exception", name);
            }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                if (state->lifecycle != HandleLifecycle::Destroyed &&
                    state->lifecycle != HandleLifecycle::Joined) {
                    state->lifecycle = HandleLifecycle::Stopped;
                }
            }
            state->cv.notify_all();
        });
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->worker_start_released = true;
        }
        state->cv.notify_all();
        return true;
    } catch (const std::exception& e) {
        TX_ERROR("failed to create %s worker: %s", name, e.what());
    } catch (...) {
        TX_ERROR("failed to create %s worker", name);
    }
    return false;
}

bool address_from_hook_is_valid(const tx_android_address_t& value,
                                int requested_family, std::string& output) {
    const void* terminator = std::memchr(value.address, '\0', sizeof(value.address));
    if (!terminator || value.address[0] == '\0' ||
        (value.family != AF_INET && value.family != AF_INET6) ||
        (requested_family == AF_INET && value.family != AF_INET) ||
        (requested_family == AF_INET6 && value.family != AF_INET6) ||
        (requested_family != AF_UNSPEC && requested_family != AF_INET &&
         requested_family != AF_INET6)) {
        return false;
    }
    const size_t length = static_cast<const char*>(terminator) - value.address;
    output.assign(value.address, length);
    in_addr address4{};
    in6_addr address6{};
    return value.family == AF_INET
        ? inet_pton(AF_INET, output.c_str(), &address4) == 1
        : inet_pton(AF_INET6, output.c_str(), &address6) == 1;
}

tx_handle_t start_client(const tx_client_config_t* config, int tun_fd,
                         const tx_android_network_hooks_t* hooks) {
    TunFdGuard tun_fd_guard(tun_fd);
    if (!config || !config->config_path) return nullptr;

    tx::ClientConfig cfg;
    if (!tx::load_client_config(config->config_path, cfg)) return nullptr;
    if (config->log_level) cfg.log_level = config->log_level;
    if (!apply_log_level(cfg.log_level)) {
        TX_ERROR("invalid client log level: %s", cfg.log_level.c_str());
        return nullptr;
    }
    if (tun_fd >= 0) {
        cfg.tun_enabled = true;
        cfg.tun_fd = tun_fd;
    }

    auto state = std::make_shared<TxClientHandle>();
    tx::SocketProtectCallback socket_protector;
    tx::DnsResolver::HostResolveHook host_resolver;
    tx::DnsResolver::QueryHook dns_query;
    TxClientHandle* raw_state = state.get();

    if (hooks && hooks->protect_socket) {
        const tx_android_network_hooks_t copied = *hooks;
        socket_protector = [raw_state, copied](int fd) {
            HookCallContext context(raw_state);
            return copied.protect_socket(fd, copied.user_data) != 0;
        };
    }
    if (hooks && hooks->resolve_host) {
        const tx_android_network_hooks_t copied = *hooks;
        host_resolver = [raw_state, copied](const std::string& host, int family) {
            HookCallContext context(raw_state);
            tx_android_address_t addresses[TX_ANDROID_MAX_RESOLVED_ADDRESSES]{};
            const int count = copied.resolve_host(
                host.c_str(), family, addresses, TX_ANDROID_MAX_RESOLVED_ADDRESSES,
                copied.user_data);
            std::vector<std::string> result;
            const int bounded_count = std::max(0, std::min(
                count, static_cast<int>(TX_ANDROID_MAX_RESOLVED_ADDRESSES)));
            for (int i = 0; i < bounded_count; ++i) {
                std::string address;
                if (address_from_hook_is_valid(addresses[i], family, address) &&
                    std::find(result.begin(), result.end(), address) == result.end()) {
                    result.push_back(std::move(address));
                }
            }
            return result;
        };
    }
    if (hooks && hooks->query_dns) {
        const tx_android_network_hooks_t copied = *hooks;
        dns_query = [raw_state, copied](const uint8_t* query, size_t length) {
            HookCallContext context(raw_state);
            if (length > std::numeric_limits<unsigned int>::max())
                return std::vector<uint8_t>();
            std::vector<uint8_t> response(65535);
            unsigned int response_length = 0;
            const int ok = copied.query_dns(
                query, static_cast<unsigned int>(length), response.data(),
                static_cast<unsigned int>(response.size()), &response_length,
                copied.user_data);
            if (!ok || response_length > response.size())
                return std::vector<uint8_t>();
            response.resize(response_length);
            return response;
        };
    }

    state->app.reset(new tx::ClientApp(std::move(socket_protector),
                                       std::move(host_resolver),
                                       std::move(dns_query),
                                       hooks ? hooks->address_family_mask : 0));
    bool initialized = false;
    try {
        initialized = state->app->init(cfg);
    } catch (...) {
        // ClientApp claims the fd at the start of init, including failures.
        tun_fd_guard.release();
        throw;
    }
    tun_fd_guard.release();
    if (!initialized) return nullptr;

    const tx_handle_t token = handle_registry().insert(state);
    if (!launch_worker(state, "tx client")) {
        handle_registry().erase(token);
        stop_app_safely(state->app.get());
        state->app.reset();
        return nullptr;
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

tx_handle_t tx_client_start_with_tun_fd(const tx_client_config_t* config,
                                        int tun_fd) noexcept {
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
        close_owned_fd(tun_fd);
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
    if (tun_fd < 0 || !hooks ||
        hooks->struct_size < sizeof(tx_android_network_hooks_t) ||
        hooks->version != TX_ANDROID_NETWORK_HOOKS_VERSION ||
        !hooks->protect_socket || !hooks->resolve_host || !hooks->query_dns) {
        TX_ERROR("Android extended client requires protect_socket, resolve_host and query_dns");
        close_owned_fd(tun_fd);
        return nullptr;
    }
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

void tx_client_update_android_network_state(
    tx_handle_t handle, unsigned int address_family_mask) noexcept {
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

tx_status_t tx_client_stop(tx_handle_t handle) noexcept {
    return stop_registered_handle<TxClientHandle>(handle, HandleKind::Client);
}

tx_status_t tx_client_wait(tx_handle_t handle) noexcept {
    return wait_registered_handle<TxClientHandle>(handle, HandleKind::Client);
}

tx_status_t tx_client_destroy(tx_handle_t handle) noexcept {
    return destroy_registered_handle<TxClientHandle>(handle, HandleKind::Client);
}

int tx_client_get_traffic_stats(tx_handle_t handle,
                                tx_traffic_stats_t* stats) noexcept {
    if (!handle || !stats) return -1;
    try {
        auto base = acquire_api_call(handle, HandleKind::Client);
        if (!base) return -1;
        ActiveApiCall active(base);
        auto* state = static_cast<TxClientHandle*>(base.get());
        if (!state->app) return -1;
        const tx::ClientTrafficStats current = state->app->traffic_stats();
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
        tx::ServerConfig cfg;
        if (!tx::load_server_config(config->config_path, cfg)) return nullptr;
        if (config->log_level) cfg.log_level = config->log_level;
        if (!apply_log_level(cfg.log_level)) {
            TX_ERROR("invalid server log level: %s", cfg.log_level.c_str());
            return nullptr;
        }

        auto state = std::make_shared<TxServerHandle>();
        state->app.reset(new tx::ServerApp());
        if (!state->app->init(cfg)) return nullptr;

        const tx_handle_t token = handle_registry().insert(state);
        if (!launch_worker(state, "tx server")) {
            handle_registry().erase(token);
            stop_app_safely(state->app.get());
            state->app.reset();
            return nullptr;
        }
        return token;
    } catch (const std::exception& e) {
        TX_ERROR("tx_server_start failed: %s", e.what());
    } catch (...) {
        TX_ERROR("tx_server_start failed with unknown exception");
    }
    return nullptr;
}

tx_status_t tx_server_stop(tx_handle_t handle) noexcept {
    return stop_registered_handle<TxServerHandle>(handle, HandleKind::Server);
}

tx_status_t tx_server_wait(tx_handle_t handle) noexcept {
    return wait_registered_handle<TxServerHandle>(handle, HandleKind::Server);
}

tx_status_t tx_server_destroy(tx_handle_t handle) noexcept {
    return destroy_registered_handle<TxServerHandle>(handle, HandleKind::Server);
}

const char* tx_version(void) noexcept {
    return TX_PROJECT_VERSION;
}

} // extern "C"
