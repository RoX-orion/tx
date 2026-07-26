#pragma once

// TX Proxy C API for shared library / Android JNI
// Provides a simple C interface to start/stop the client and server.

#ifdef __cplusplus
extern "C" {
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

// Opaque handle
typedef void* tx_handle_t;

// Called synchronously on the client network thread after an outbound socket
// is created and before it is used. The hook must bind the socket to the
// selected physical Android Network and exempt it from the VPN. Do not close
// the fd or retain ownership of it. Return non-zero only when both operations
// succeeded and the selected Network remained current.
typedef int (*tx_socket_protect_fn)(int socket_fd, void* user_data);

#define TX_ANDROID_NETWORK_HOOKS_VERSION 1u
#define TX_ANDROID_MAX_RESOLVED_ADDRESSES 16u

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
TX_API tx_handle_t tx_client_start(const tx_client_config_t* config);

// Start the client with a VpnService TUN fd. Native code takes ownership even
// when startup fails and closes it before this client is stopped.
TX_API tx_handle_t tx_client_start_with_tun_fd(const tx_client_config_t* config, int tun_fd);

// Start the Android client with a physical-network bind + VPN-exemption callback.
// This simplified API requires at least one dns.upstreams entry in the client
// config. Use tx_client_start_android_ex() for app-provided DNS hooks.
// Native code takes ownership of tun_fd, including startup-failure paths.
// protect_user_data must remain valid until tx_client_stop() returns.
TX_API tx_handle_t tx_client_start_android(const tx_client_config_t* config, int tun_fd,
                                           tx_socket_protect_fn protect_fn,
                                           void* protect_user_data);

// Versioned Android network integration. Hooks are copied during startup, but
// hooks->user_data must remain valid until tx_client_stop() returns.
TX_API tx_handle_t tx_client_start_android_ex(const tx_client_config_t* config, int tun_fd,
                                              const tx_android_network_hooks_t* hooks);

// Cancel work tied to the previous Android Network and close existing outbound
// sockets. Applications reconnect while fake-IP mappings remain intact.
TX_API void tx_client_notify_network_changed(tx_handle_t handle);

// Stop the client.
TX_API void tx_client_stop(tx_handle_t handle);

// Get cumulative client traffic counters. Returns 0 on success, -1 on failure.
TX_API int tx_client_get_traffic_stats(tx_handle_t handle, tx_traffic_stats_t* stats);

// Start the server. Returns handle or NULL on failure.
TX_API tx_handle_t tx_server_start(const tx_server_config_t* config);

// Stop the server.
TX_API void tx_server_stop(tx_handle_t handle);

// Get version string.
TX_API const char* tx_version(void);

#ifdef __cplusplus
}
#endif
