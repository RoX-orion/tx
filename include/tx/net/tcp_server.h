#pragma once

#include <uv.h>
#include <string>
#include <functional>
#include <memory>
#include <unordered_map>
#include "tx/net/buffer.h"
#include "tx/net/tcp_stream.h"
#include "tx/common/types.h"

namespace tx {

class TcpSession;

using SessionPtr     = std::shared_ptr<TcpSession>;
using AcceptCallback = std::function<void(SessionPtr session)>;
using ReadCallback   = std::function<void(SessionPtr session, Buffer& data)>;
using CloseCallbackS = std::function<void(SessionPtr session)>;
using WriteDrainCallback = std::function<void(SessionPtr session)>;
using EofCallback = std::function<void(SessionPtr session)>;
using SessionErrorCallback = std::function<void(SessionPtr session, int error)>;
using SocketProtectCallback = std::function<bool(int fd)>;

// A single TCP connection session
class TcpSession : public TcpStream, public std::enable_shared_from_this<TcpSession> {
public:
    explicit TcpSession(uv_loop_t* loop,
                        SocketProtectCallback socket_protector = SocketProtectCallback());
    ~TcpSession();

    // Initialize from an accepted handle
    // Returns false when libuv rejected the accepted connection. The session
    // still closes its initialized handle asynchronously in that case.
    bool init(uv_tcp_t* server_handle);

    // Connect to remote
    using ConnectCb = std::function<void(bool success)>;
    void connect(const std::string& host, uint16_t port, ConnectCb cb);
    void connect(const std::string& host, uint16_t port, uint64_t timeout_ms,
                 ConnectCb cb);

    // Send data
    bool send(const uint8_t* data, size_t len);
    bool send(Buffer& buf);
    bool write(const uint8_t* data, size_t len) override { return send(data, len); }
    bool write(Buffer& data) override { return send(data); }

    // Start/stop reading
    void start_read(ReadCallback cb);
    void stop_read();
    void pause_read() override { stop_read(); }
    void resume_read() override;
    bool is_reading() const { return reading_; }

    // Close
    void shutdown_write() override;
    void close() override;
    void reset() override { close(); }
    bool is_closed() const override { return closed_; }
    bool is_read_eof() const override { return read_eof_; }
    bool is_write_shutdown() const override { return write_shutdown_; }

    // Callbacks
    void set_close_callback(CloseCallbackS cb) { close_cb_ = std::move(cb); }
    void set_write_drain_callback(WriteDrainCallback cb) { write_drain_cb_ = std::move(cb); }
    void set_eof_callback(EofCallback cb) { eof_cb_ = std::move(cb); }
    void set_error_callback(SessionErrorCallback cb) { error_cb_ = std::move(cb); }

    // Access underlying handle
    uv_tcp_t* handle() { return &tcp_; }
    uv_loop_t* loop() { return loop_; }

    // Remote address
    const std::string& remote_addr() const { return remote_addr_; }
    uint16_t remote_port() const { return remote_port_; }
    bool local_addr(std::string& host, uint16_t& port) const;
    size_t pending_write_bytes() const override { return pending_write_bytes_; }

    static void set_outbound_mark(uint32_t mark);
    static void set_outbound_interfaces(uint32_t ipv4_index, uint32_t ipv6_index);
    static uint32_t outbound_interface(int family);

private:
    static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void on_write(uv_write_t* req, int status);
    static void on_close(uv_handle_t* handle);
    static void on_connect(uv_connect_t* req, int status);
    static void on_connect_timeout(uv_timer_t* timer);
    static void on_shutdown(uv_shutdown_t* req, int status);
    static void on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

    uv_loop_t*   loop_;
    uv_tcp_t     tcp_;
    bool         closed_;
    bool         reading_;
    bool         read_eof_;
    bool         write_shutdown_;
    bool         shutdown_pending_;
    ReadCallback read_cb_;
    CloseCallbackS close_cb_;
    WriteDrainCallback write_drain_cb_;
    EofCallback eof_cb_;
    SessionErrorCallback error_cb_;
    SessionPtr   self_ref_;   // Keeps this object alive until uv_close finishes.
    Buffer       read_buf_;
    std::string  remote_addr_;
    uint16_t     remote_port_;
    size_t       pending_write_bytes_;
    size_t       write_high_watermark_;
    size_t       write_low_watermark_;
    bool         paused_for_write_;
    SocketProtectCallback socket_protector_;
    uint64_t     socket_sequence_;

    struct WriteReq {
        uv_write_t req;
        uv_buf_t   buf;
        char*      data;
        size_t     len;
        SessionPtr session;
    };
    static void on_write_free(uv_write_t* req, int status);
};

// TCP server
class TcpServer {
public:
    TcpServer(uv_loop_t* loop);
    ~TcpServer();

    bool listen(const std::string& host, uint16_t port);
    bool listen_transparent(const std::string& host, uint16_t port);
    void stop();

    void set_accept_callback(AcceptCallback cb) { accept_cb_ = std::move(cb); }

    uv_loop_t* loop() const { return loop_; }

private:
    static void on_connection(uv_stream_t* server, int status);

    uv_loop_t*     loop_;
    uv_tcp_t       tcp_;
    bool           listening_;
    bool           transparent_;
    bool           stopped_;
    AcceptCallback accept_cb_;
};

} // namespace tx
