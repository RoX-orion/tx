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

// Start the client. Returns handle or NULL on failure.
TX_API tx_handle_t tx_client_start(const tx_client_config_t* config);

// Stop the client.
TX_API void tx_client_stop(tx_handle_t handle);

// Start the server. Returns handle or NULL on failure.
TX_API tx_handle_t tx_server_start(const tx_server_config_t* config);

// Stop the server.
TX_API void tx_server_stop(tx_handle_t handle);

// Get version string.
TX_API const char* tx_version(void);

#ifdef __cplusplus
}
#endif
