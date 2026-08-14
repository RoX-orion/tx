#pragma once

// TX Proxy C API for shared library / Android JNI
// Provides a simple C interface to start/stop the client and server.

#ifdef __cplusplus
extern "C" {
#define TX_C_NOEXCEPT noexcept
#else
#define TX_C_NOEXCEPT
#endif

#ifdef _WIN32
    #ifdef TX_EXPORTS
        #define TX_API __declspec(dllexport)
    #else
        #define TX_API __declspec(dllimport)
    #endif
#else
    #define TX_API __attribute__((visibility("default")))
#endif

#if defined(_MSC_VER)
    #define TX_DEPRECATED(message) __declspec(deprecated(message))
#elif defined(__GNUC__) || defined(__clang__)
    #define TX_DEPRECATED(message) __attribute__((deprecated(message)))
#else
    #define TX_DEPRECATED(message)
#endif

// Opaque handle
typedef void* tx_handle_t;

typedef enum {
    TX_STATUS_OK = 0,
    TX_STATUS_INVALID_ARGUMENT = 1,
    TX_STATUS_INVALID_HANDLE = 2,
    TX_STATUS_INVALID_STATE = 3,
    TX_STATUS_REENTRANT_WAIT = 4,
    TX_STATUS_INTERNAL_ERROR = 5,
} tx_status_t;

// Called synchronously with outbound-socket setup after a socket is created
// and before it is used. The hook must bind the socket to the
// selected physical Android Network and exempt it from the VPN. The protect
// hook may run on the client loop or a libuv worker. Do not close
// the fd or retain ownership of it. Return non-zero only when both operations
// succeeded and the selected Network remained current.
typedef int (*tx_socket_protect_fn)(int socket_fd, void* user_data);

#define TX_ANDROID_NETWORK_HOOKS_VERSION 2u
#define TX_ANDROID_MAX_RESOLVED_ADDRESSES 16u
// When KNOWN is set, only the listed address families have a usable default
// route on the selected physical Android Network. A zero mask means
// "unknown", which defers filtering while LinkProperties is not ready.
#define TX_ANDROID_NETWORK_FAMILY_IPV4  (1u << 0)
#define TX_ANDROID_NETWORK_FAMILY_IPV6  (1u << 1)
#define TX_ANDROID_NETWORK_FAMILY_KNOWN (1u << 31)

typedef struct {
    int family;                 // AF_INET or AF_INET6
    char address[46];           // Numeric address, NUL terminated
} tx_android_address_t;

typedef int (*tx_android_resolve_host_fn)(const char* host, int family,
                                          tx_android_address_t* addresses,
                                          unsigned int capacity,
                                          void* user_data);
typedef int (*tx_android_query_dns_fn)(const unsigned char* query,
                                       unsigned int query_length,
                                       unsigned char* response,
                                       unsigned int response_capacity,
                                       unsigned int* response_length,
                                       void* user_data);

typedef struct {
    unsigned int struct_size;
    unsigned int version;
    tx_socket_protect_fn protect_socket;
    tx_android_resolve_host_fn resolve_host;
    tx_android_query_dns_fn query_dns;
    unsigned int address_family_mask;
    void* user_data;
} tx_android_network_hooks_t;

// Client configuration
typedef struct {
    const char* config_path;    // Path to client JSON config
    const char* log_level;      // "debug", "info", "warn", "error"
} tx_client_config_t;

// Server configuration
typedef struct {
    const char* config_path;    // Path to server JSON config
    const char* log_level;      // "debug", "info", "warn", "error"
} tx_server_config_t;

typedef struct {
    unsigned long long direct_upload_bytes;
    unsigned long long direct_download_bytes;
    unsigned long long proxy_upload_bytes;
    unsigned long long proxy_download_bytes;
} tx_traffic_stats_t;

// Start the client. Returns handle or NULL on failure.
TX_API tx_handle_t tx_client_start(const tx_client_config_t* config) TX_C_NOEXCEPT;

// Start the client with a VpnService TUN fd. Native code takes ownership even
// when startup fails and closes it before this client is stopped.
TX_API tx_handle_t tx_client_start_with_tun_fd(const tx_client_config_t* config, int tun_fd) TX_C_NOEXCEPT;

// Start the Android client with a VPN-exemption callback. TX-routed DNS is
// resolved by the remote server's system resolver; direct domain resolution
// is unavailable through this compatibility entry point.
// Native code takes ownership of tun_fd, including startup-failure paths.
// protect_user_data must remain valid until tx_client_wait() returns. This
// compatibility entry point supports direct numeric targets only; use _ex
// when direct-domain resolution is required.
TX_API TX_DEPRECATED("use tx_client_start_android_ex for direct domain targets")
tx_handle_t tx_client_start_android(const tx_client_config_t* config, int tun_fd,
                                           tx_socket_protect_fn protect_fn,
                                           void* protect_user_data) TX_C_NOEXCEPT;

// Versioned Android network integration. protect_socket is used for every
// outbound socket. resolve_host/query_dns provide physical-Network DNS only
// for targets already routed to direct. TX-routed DNS uses the encrypted
// tunnel and the server's system resolver; TX endpoints must be numeric.
// resolve_host/query_dns run on libuv workers. Android/JNI implementations
// must AttachCurrentThread/DetachCurrentThread as needed. hooks->user_data
// must remain valid until tx_client_wait() returns.
TX_API tx_handle_t tx_client_start_android_ex(const tx_client_config_t* config, int tun_fd,
                                              const tx_android_network_hooks_t* hooks) TX_C_NOEXCEPT;

// Cancel work tied to the previous Android Network and close existing outbound
// sockets. Applications reconnect while fake-IP mappings remain intact.
TX_API void tx_client_notify_network_changed(tx_handle_t handle) TX_C_NOEXCEPT;

// Update the selected Android Network's usable IP families, then close work
// tied to the previous network state. See TX_ANDROID_NETWORK_FAMILY_*.
TX_API void tx_client_update_android_network_state(tx_handle_t handle,
                                                   unsigned int address_family_mask) TX_C_NOEXCEPT;

// Three-phase asynchronous lifecycle. stop only requests shutdown and never
// joins. wait is allowed only after stop and must be called outside hooks and
// the client loop. destroy is non-blocking and is allowed only after wait.
TX_API tx_status_t tx_client_stop(tx_handle_t handle) TX_C_NOEXCEPT;
TX_API tx_status_t tx_client_wait(tx_handle_t handle) TX_C_NOEXCEPT;
TX_API tx_status_t tx_client_destroy(tx_handle_t handle) TX_C_NOEXCEPT;

// Get cumulative client traffic counters. Returns 0 on success, -1 on failure.
TX_API int tx_client_get_traffic_stats(tx_handle_t handle,
                                       tx_traffic_stats_t* stats) TX_C_NOEXCEPT;

// Start the server. Returns handle or NULL on failure.
TX_API tx_handle_t tx_server_start(const tx_server_config_t* config) TX_C_NOEXCEPT;

TX_API tx_status_t tx_server_stop(tx_handle_t handle) TX_C_NOEXCEPT;
TX_API tx_status_t tx_server_wait(tx_handle_t handle) TX_C_NOEXCEPT;
TX_API tx_status_t tx_server_destroy(tx_handle_t handle) TX_C_NOEXCEPT;

// Get version string.
TX_API const char* tx_version(void) TX_C_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#undef TX_C_NOEXCEPT
#undef TX_DEPRECATED
