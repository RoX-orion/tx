#pragma once

#include "config.h"
#include "tx/net/tcp_server.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <functional>
#include <vector>
#include <uv.h>

namespace tx {

class PlatformTunDevice {
public:
    enum class WriteResult {
        Written,
        WouldBlock,
        Error,
    };

    struct CommandResult {
        int exit_code = -1;
        std::string output;
    };
    using CommandRunner = std::function<CommandResult(const std::vector<std::string>&)>;

    virtual ~PlatformTunDevice() = default;

    static std::unique_ptr<PlatformTunDevice> create();
    static void set_command_runner_for_testing(CommandRunner runner);
    static void reset_command_runner_for_testing();

    virtual bool open(const ClientConfig& config, std::string& error) = 0;
    virtual void close() = 0;
    virtual int fd() const { return -1; }
    virtual const std::string& name() const = 0;
    virtual OutboundSocketPolicy outbound_socket_policy() const {
        return OutboundSocketPolicy();
    }
    virtual std::ptrdiff_t read_packet(uint8_t* data, size_t len, std::string& error) = 0;
    virtual WriteResult write_packet(const uint8_t* data, size_t len,
                                     std::string& error) = 0;
    virtual bool start_async_reader(uv_loop_t*, std::function<void()>, std::string& error) {
        error = "asynchronous TUN reader is not supported";
        return false;
    }
};

} // namespace tx
