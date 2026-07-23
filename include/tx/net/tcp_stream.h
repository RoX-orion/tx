#pragma once

#include "tx/net/buffer.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace tx {

// Transport-neutral stream used by the proxy flow. Implementations may be a
// kernel/libuv socket or an lwIP PCB terminating a TUN-side TCP connection.
class TcpStream {
public:
    using DataCallback = std::function<void(Buffer&)>;
    using EventCallback = std::function<void()>;
    using ErrorCallback = std::function<void(int)>;

    virtual ~TcpStream() = default;
    virtual bool write(const uint8_t* data, size_t len) = 0;
    virtual bool write(Buffer& data) = 0;
    bool send(const uint8_t* data, size_t len) { return write(data, len); }
    bool send(Buffer& data) { return write(data); }
    virtual void pause_read() = 0;
    virtual void resume_read() = 0;
    virtual void shutdown_write() = 0;
    virtual void close() = 0;
    virtual void reset() = 0;
    virtual size_t pending_write_bytes() const = 0;
    virtual bool is_closed() const = 0;
    virtual bool is_read_eof() const = 0;
    virtual bool is_write_shutdown() const = 0;
};

using TcpStreamPtr = std::shared_ptr<TcpStream>;

} // namespace tx
