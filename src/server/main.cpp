#include "server_app.h"
#include "tx/common/log.h"
#include "tx/crypto/secret.h"

#include <cstdio>
#include <cstring>
#include <signal.h>
#include <vector>

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -c, --config <path>   Config file path (default: server.json)\n"
        "  -l, --log <level>     Log level: debug, info, warn, error (default: info)\n"
        "      --gen-secret      Generate a 32-byte base64 PSK and exit\n"
        "  -h, --help            Show this help\n",
        prog);
}

static void install_crash_handlers() {
#ifdef SIGPIPE
    // A peer can disappear while data is queued. Surface that through the
    // socket error path instead of terminating every tunnel client.
    signal(SIGPIPE, SIG_IGN);
#endif
}

int main(int argc, char* argv[]) {
    install_crash_handlers();

    const char* config_path = "server.json";
    const char* log_level = nullptr;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) { print_usage(argv[0]); return 2; }
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) {
            if (i + 1 >= argc) { print_usage(argv[0]); return 2; }
            log_level = argv[++i];
        } else if (strcmp(argv[i], "--gen-secret") == 0) {
            std::vector<uint8_t> secret;
            if (!tx::Secret::generate_psk(secret)) {
                return 1;
            }
            printf("%s\n", tx::Secret::encode_base64_secret(secret.data(), secret.size()).c_str());
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }

    if (log_level) {
        if (strcmp(log_level, "debug") == 0) tx::set_log_level(tx::LogLevel::Debug);
        else if (strcmp(log_level, "info") == 0) tx::set_log_level(tx::LogLevel::Info);
        else if (strcmp(log_level, "warn") == 0) tx::set_log_level(tx::LogLevel::Warn);
        else if (strcmp(log_level, "error") == 0) tx::set_log_level(tx::LogLevel::Error);
        else { print_usage(argv[0]); return 2; }
    }

    tx::ServerConfig config;
    if (!tx::load_server_config(config_path, config)) {
        TX_ERROR("Failed to load config from: %s", config_path);
        return 1;
    }

    if (!log_level) {
        if (config.log_level == "debug") tx::set_log_level(tx::LogLevel::Debug);
        else if (config.log_level == "warn") tx::set_log_level(tx::LogLevel::Warn);
        else if (config.log_level == "error") tx::set_log_level(tx::LogLevel::Error);
    }

    tx::ServerApp app;

    if (!app.init(config)) {
        TX_ERROR("Failed to initialize server");
        return 1;
    }

    // Use libuv signal watchers
    uv_signal_t sigint, sigterm;
    uv_signal_init(app.loop(), &sigint);
    uv_signal_init(app.loop(), &sigterm);
    uv_signal_start(&sigint, [](uv_signal_t* handle, int signum) {
        TX_INFO("Caught signal %d, shutting down...", signum);
        static_cast<tx::ServerApp*>(handle->data)->stop();
        uv_signal_stop(handle);
    }, SIGINT);
    uv_signal_start(&sigterm, [](uv_signal_t* handle, int signum) {
        TX_INFO("Caught signal %d, shutting down...", signum);
        static_cast<tx::ServerApp*>(handle->data)->stop();
        uv_signal_stop(handle);
    }, SIGTERM);
    sigint.data = &app;
    sigterm.data = &app;
    uv_unref(reinterpret_cast<uv_handle_t*>(&sigint));
    uv_unref(reinterpret_cast<uv_handle_t*>(&sigterm));

    TX_INFO("TX Server running. Press Ctrl+C to stop.");
    int ret = app.run();

    uv_signal_stop(&sigint);
    uv_signal_stop(&sigterm);
    uv_close(reinterpret_cast<uv_handle_t*>(&sigint), nullptr);
    uv_close(reinterpret_cast<uv_handle_t*>(&sigterm), nullptr);
    uv_run(app.loop(), UV_RUN_NOWAIT);

    TX_INFO("TX Server stopped.");
    return ret;
}
