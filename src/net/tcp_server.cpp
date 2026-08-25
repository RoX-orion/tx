#include "tx/net/tcp_server.h"
#include "tx/common/log.h"
#include <cstring>
#include <cerrno>
#include <atomic>
#include <utility>

#if defined(TX_PLATFORM_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tx {

namespace {

std::atomic<uint64_t> g_socket_sequence{0};

#if defined(TX_PLATFORM_LINUX)
bool set_outbound_mark(int fd, uint32_t mark) {
    if (mark == 0) return true;

    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        TX_WARN("SO_MARK 0x%x failed: %s", mark, std::strerror(errno));
        return false;
    }
    return true;
}
#endif

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
bool ensure_outbound_socket(uv_tcp_t* tcp, int family,
                            const SocketProtectCallback& socket_protector,
                            const OutboundSocketPolicy& socket_policy) {
    if (socket_policy.mark == 0 && !socket_protector) return true;

    uv_os_fd_t fd;
    if (uv_fileno(reinterpret_cast<const uv_handle_t*>(tcp), &fd) == 0) {
        int socket_fd = static_cast<int>(fd);
        if (socket_protector && !socket_protector(socket_fd)) {
            TX_ERROR("Socket protector rejected TCP fd %d", socket_fd);
            return false;
        }
#if defined(TX_PLATFORM_LINUX)
        return set_outbound_mark(socket_fd, socket_policy.mark);
#else
        return true;
#endif
    }

    int sock = ::socket(family, SOCK_STREAM, 0);
    if (sock < 0) {
        TX_WARN("Failed to create outbound TCP socket: %s", std::strerror(errno));
        return false;
    }

    if (socket_protector && !socket_protector(sock)) {
        TX_ERROR("Socket protector rejected TCP fd %d", sock);
        ::close(sock);
        return false;
    }
#if defined(TX_PLATFORM_LINUX)
    if (!set_outbound_mark(sock, socket_policy.mark)) {
        ::close(sock);
        return false;
    }
#endif

    int r = uv_tcp_open(tcp, static_cast<uv_os_sock_t>(sock));
    if (r != 0) {
        TX_WARN("uv_tcp_open for outbound socket failed: %s", uv_strerror(r));
        ::close(sock);
        return false;
    }
    return true;
}
#if defined(TX_PLATFORM_LINUX)
bool open_transparent_socket(uv_tcp_t* tcp, int family) {
    int fd = ::socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        TX_ERROR("socket() for transparent listen failed: %s", std::strerror(errno));
        return false;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        TX_ERROR("SO_REUSEADDR failed: %s", std::strerror(errno));
        ::close(fd);
        return false;
    }
    if (family == AF_INET &&
        setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0) {
        TX_ERROR("IP_TRANSPARENT failed: %s", std::strerror(errno));
        ::close(fd);
        return false;
    }

    int r = uv_tcp_open(tcp, static_cast<uv_os_sock_t>(fd));
    if (r != 0) {
        TX_ERROR("uv_tcp_open for transparent listen failed: %s", uv_strerror(r));
        ::close(fd);
        return false;
    }
    return true;
}
#endif
#elif defined(TX_PLATFORM_WINDOWS)
bool ensure_outbound_socket(uv_tcp_t* tcp, int family,
                            const SocketProtectCallback& socket_protector,
                            const OutboundSocketPolicy& socket_policy) {
    if (socket_protector) return false;
    uint32_t index = family == AF_INET6 ? socket_policy.ipv6_interface
                                        : socket_policy.ipv4_interface;
    if (!index) return true;
    SOCKET socket_fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd == INVALID_SOCKET) return false;
    DWORD network_index = htonl(index);
    int level = family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
    int option = family == AF_INET6 ? IPV6_UNICAST_IF : IP_UNICAST_IF;
    if (setsockopt(socket_fd, level, option,
                   reinterpret_cast<const char*>(&network_index),
                   sizeof(network_index)) != 0 ||
        uv_tcp_open(tcp, socket_fd) != 0) {
        closesocket(socket_fd);
        return false;
    }
    return true;
}
#else
bool ensure_outbound_socket(uv_tcp_t*, int,
                            const SocketProtectCallback& socket_protector,
                            const OutboundSocketPolicy&) {
    if (socket_protector) {
        TX_ERROR("Socket protection is not supported on this platform");
        return false;
    }
    return true;
}
#endif

} // namespace

// DNS resolution context for TcpSession::connect
struct DnsResolveCtx {
    TcpSession::ConnectCb cb;
    SessionPtr            session;
    uint16_t              port;
    uint64_t              timeout_ms;
};

struct ConnectCtx {
    TcpSession::ConnectCb cb;
    SessionPtr            session;
    uv_timer_t*           timer;
    bool                  completed;
    uint64_t              started_ns;
    uint64_t              socket_sequence;
    std::string           address;
};

// ==================== TcpSession ====================

TcpSession::TcpSession(uv_loop_t* loop, SocketProtectCallback socket_protector,
                       OutboundSocketPolicy socket_policy)
    : loop_(loop), closed_(false), reading_(false), read_eof_(false),
      write_shutdown_(false), shutdown_pending_(false),
      close_after_flush_(false), remote_port_(0),
      pending_write_bytes_(0),
      write_high_watermark_(4 * 1024 * 1024),
      write_low_watermark_(1024 * 1024),
      write_hard_limit_(TcpSession::kDefaultWriteHardLimit),
      paused_for_write_(false),
      socket_protector_(std::move(socket_protector)),
      socket_policy_(socket_policy),
      socket_sequence_(0) {
    uv_tcp_init(loop_, &tcp_);
    tcp_.data = this;
}

TcpSession::~TcpSession() {
    if (!closed_) {
        TX_WARN("TcpSession destroyed before close completed");
    }
}

bool TcpSession::init(uv_tcp_t* server_handle) {
    tcp_.data = this;

    uv_stream_t* server_stream = reinterpret_cast<uv_stream_t*>(server_handle);
    if (uv_accept(server_stream, reinterpret_cast<uv_stream_t*>(&tcp_)) != 0) {
        TX_ERROR("uv_accept failed");
        close();
        return false;
    }

    // Extract remote address
    struct sockaddr_storage addr;
    int namelen = sizeof(addr);
    if (uv_tcp_getpeername(&tcp_, reinterpret_cast<struct sockaddr*>(&addr), &namelen) == 0) {
        char ipbuf[INET6_ADDRSTRLEN];
        if (addr.ss_family == AF_INET) {
            auto* a4 = reinterpret_cast<struct sockaddr_in*>(&addr);
            inet_ntop(AF_INET, &a4->sin_addr, ipbuf, sizeof(ipbuf));
            remote_port_ = ntohs(a4->sin_port);
        } else {
            auto* a6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
            inet_ntop(AF_INET6, &a6->sin6_addr, ipbuf, sizeof(ipbuf));
            remote_port_ = ntohs(a6->sin6_port);
        }
        remote_addr_ = ipbuf;
    }

    TX_DEBUG("Session accepted from %s:%u", remote_addr_.c_str(), remote_port_);
    return true;
}

void TcpSession::connect(const std::string& host, uint16_t port, ConnectCb cb) {
    connect(host, port, 0, std::move(cb));
}

void TcpSession::connect(const std::string& host, uint16_t port, uint64_t timeout_ms,
                         ConnectCb cb) {
    auto* req = new uv_connect_t;
    tcp_.data = this;

    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr* sa = nullptr;

    if (uv_ip4_addr(host.c_str(), port, &addr4) == 0) {
        sa = reinterpret_cast<struct sockaddr*>(&addr4);
    } else if (uv_ip6_addr(host.c_str(), port, &addr6) == 0) {
        sa = reinterpret_cast<struct sockaddr*>(&addr6);
    }

    if (sa) {
        socket_sequence_ = g_socket_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
        remote_addr_ = host;
        remote_port_ = port;
        TX_DEBUG("TCP socket #%llu prepare family=%s target=%s:%u",
                 static_cast<unsigned long long>(socket_sequence_),
                 sa->sa_family == AF_INET6 ? "IPv6" : "IPv4", host.c_str(), port);
        if (!ensure_outbound_socket(&tcp_, sa->sa_family, socket_protector_,
                                    socket_policy_)) {
            TX_ERROR("TCP socket #%llu prepare failed for %s:%u",
                     static_cast<unsigned long long>(socket_sequence_), host.c_str(), port);
            cb(false);
            close();
            delete req;
            return;
        }

        // Direct IP connect
        auto* ctx = new ConnectCtx{std::move(cb), shared_from_this(), nullptr, false,
                                   uv_hrtime(), socket_sequence_,
                                   host + ":" + std::to_string(port)};
        req->data = ctx;
        int r = uv_tcp_connect(req, &tcp_, sa, on_connect);
        if (r != 0) {
            TX_ERROR("TCP socket #%llu connect error for %s:%u: %s",
                     static_cast<unsigned long long>(socket_sequence_), host.c_str(), port,
                     uv_strerror(r));
            ctx->completed = true;
            ctx->cb(false);
            if (!ctx->session->is_closed()) {
                ctx->session->close();
            }
            delete ctx;
            delete req;
        } else if (timeout_ms > 0) {
            ctx->timer = new uv_timer_t;
            ctx->timer->data = ctx;
            int timer_status = uv_timer_init(loop_, ctx->timer);
            if (timer_status != 0) {
                TX_WARN("TCP socket #%llu could not start connect timer: %s",
                        static_cast<unsigned long long>(socket_sequence_),
                        uv_strerror(timer_status));
                delete ctx->timer;
                ctx->timer = nullptr;
            } else {
                timer_status = uv_timer_start(ctx->timer, on_connect_timeout,
                                              timeout_ms, 0);
                if (timer_status != 0) {
                    TX_WARN("TCP socket #%llu could not start connect timer: %s",
                            static_cast<unsigned long long>(socket_sequence_),
                            uv_strerror(timer_status));
                    uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer),
                             [](uv_handle_t* handle) {
                                 delete reinterpret_cast<uv_timer_t*>(handle);
                             });
                    ctx->timer = nullptr;
                }
            }
        }
        return;
    }

#if defined(TX_PLATFORM_ANDROID)
    // Android callers must resolve through android_getaddrinfofornetwork() and
    // pass a numeric candidate. Falling back to uv_getaddrinfo here could bind
    // resolution to the VPN itself and create a routing loop.
    TX_ERROR("Android outbound requires a network-bound resolver for %s", host.c_str());
    cb(false);
    close();
    delete req;
    return;
#endif

    // DNS resolution needed
    auto* resolve_ctx = new DnsResolveCtx{std::move(cb), shared_from_this(), port,
                                          timeout_ms};
    auto* dns_req = new uv_getaddrinfo_t;
    dns_req->data = resolve_ctx;
    delete req;

    TX_DEBUG("TCP resolving %s:%u before connect", host.c_str(), port);

    int r = uv_getaddrinfo(loop_, dns_req, on_resolved,
                            host.c_str(), nullptr, nullptr);
    if (r != 0) {
        TX_ERROR("uv_getaddrinfo failed for %s: %s", host.c_str(), uv_strerror(r));
        resolve_ctx->cb(false);
        if (!resolve_ctx->session->is_closed()) {
            resolve_ctx->session->close();
        }
        delete resolve_ctx;
        delete dns_req;
    }
}

bool TcpSession::local_addr(std::string& host, uint16_t& port) const {
    sockaddr_storage addr;
    int len = sizeof(addr);
    if (uv_tcp_getsockname(const_cast<uv_tcp_t*>(&tcp_),
                           reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        return false;
    }

    char ipbuf[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(&addr);
        if (!inet_ntop(AF_INET, &a4->sin_addr, ipbuf, sizeof(ipbuf))) {
            return false;
        }
        port = ntohs(a4->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (!inet_ntop(AF_INET6, &a6->sin6_addr, ipbuf, sizeof(ipbuf))) {
            return false;
        }
        port = ntohs(a6->sin6_port);
    } else {
        return false;
    }

    host = ipbuf;
    return true;
}

bool TcpSession::send(const uint8_t* data, size_t len) {
    if (closed_ || write_shutdown_ || shutdown_pending_ || !data || len == 0) return false;
    if (len > write_hard_limit_ ||
        pending_write_bytes_ > write_hard_limit_ - len) {
        TX_WARN("TCP write hard limit reached: pending=%zu requested=%zu limit=%zu",
                pending_write_bytes_, len, write_hard_limit_);
        return false;
    }

    WriteReq* wr = nullptr;
    try {
        wr = new WriteReq{};
        wr->data = new char[len];
        memcpy(wr->data, data, len);
        wr->buf = uv_buf_init(wr->data, static_cast<unsigned int>(len));
        wr->len = len;
        wr->session = shared_from_this();
        wr->req.data = wr;
    } catch (...) {
        if (wr) {
            delete[] wr->data;
            delete wr;
        }
        TX_WARN("TCP write allocation failed for %zu bytes", len);
        return false;
    }

    int r = uv_write(&wr->req, reinterpret_cast<uv_stream_t*>(&tcp_),
                      &wr->buf, 1, on_write_free);
    if (r != 0) {
        TX_DEBUG("uv_write failed: %s", uv_strerror(r));
        delete[] wr->data;
        delete wr;
        return false;
    }

    pending_write_bytes_ += len;
    return true;
}

bool TcpSession::send(Buffer& buf) {
    if (closed_ || buf.empty()) return false;
    if (!send(buf.data(), buf.readable())) {
        return false;
    }
    buf.clear();
    return true;
}

bool TcpSession::send(Buffer&& buf) {
    if (closed_ || write_shutdown_ || shutdown_pending_ || buf.empty()) return false;
    const size_t len = buf.readable();
    if (len > write_hard_limit_ || pending_write_bytes_ > write_hard_limit_ - len) {
        TX_WARN("TCP write hard limit reached: pending=%zu requested=%zu limit=%zu",
                pending_write_bytes_, len, write_hard_limit_);
        return false;
    }

    WriteReq* wr = nullptr;
    try {
        wr = new WriteReq{};
        wr->data = nullptr;
        wr->owned_buffer.reset(new Buffer(std::move(buf)));
        wr->buf = uv_buf_init(
            reinterpret_cast<char*>(const_cast<uint8_t*>(wr->owned_buffer->data())),
            static_cast<unsigned int>(len));
        wr->len = len;
        wr->session = shared_from_this();
        wr->req.data = wr;
    } catch (...) {
        delete wr;
        TX_WARN("TCP owned write allocation failed for %zu bytes", len);
        return false;
    }

    const int status = uv_write(&wr->req, reinterpret_cast<uv_stream_t*>(&tcp_),
                                &wr->buf, 1, on_write_free);
    if (status != 0) {
        TX_DEBUG("uv_write failed: %s", uv_strerror(status));
        delete wr;
        return false;
    }
    pending_write_bytes_ += len;
    return true;
}

void TcpSession::start_read(ReadCallback cb) {
    if (closed_ || read_eof_) return;
    read_cb_ = std::move(cb);
    paused_for_write_ = false;
    if (reading_) return;
    tcp_.data = this;
    int r = uv_read_start(reinterpret_cast<uv_stream_t*>(&tcp_), on_alloc, on_read);
    if (r != 0) {
        TX_DEBUG("uv_read_start failed: %s", uv_strerror(r));
        read_cb_ = nullptr;
        return;
    }
    reading_ = true;
}

void TcpSession::stop_read() {
    if (closed_ || !reading_) return;
    reading_ = false;
    uv_read_stop(reinterpret_cast<uv_stream_t*>(&tcp_));
}

void TcpSession::resume_read() {
    if (closed_ || read_eof_ || reading_ || !read_cb_) return;
    int r = uv_read_start(reinterpret_cast<uv_stream_t*>(&tcp_), on_alloc, on_read);
    if (r == 0 || r == UV_EALREADY) reading_ = true;
}

void TcpSession::close() {
    if (closed_) return;
    closed_ = true;
    reading_ = false;
    paused_for_write_ = false;
    read_cb_ = nullptr;
    write_drain_cb_ = nullptr;
    eof_cb_ = nullptr;
    error_cb_ = nullptr;
    try {
        self_ref_ = shared_from_this();
    } catch (const std::bad_weak_ptr&) {
        // TcpSession is expected to be owned by shared_ptr. If it is not,
        // keep the old behavior rather than throwing during shutdown.
    }
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&tcp_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&tcp_), on_close);
    }
}

void TcpSession::shutdown_write() {
    if (closed_ || write_shutdown_ || shutdown_pending_) return;
    auto* req = new uv_shutdown_t;
    req->data = new SessionPtr(shared_from_this());
    shutdown_pending_ = true;
    int r = uv_shutdown(req, reinterpret_cast<uv_stream_t*>(&tcp_), on_shutdown);
    if (r != 0) {
        shutdown_pending_ = false;
        delete static_cast<SessionPtr*>(req->data);
        delete req;
        if (r != UV_ENOTCONN) {
            TX_DEBUG("uv_shutdown failed: %s", uv_strerror(r));
        }
        close();
    }
}

void TcpSession::close_after_flush() {
    if (closed_) return;
    close_after_flush_ = true;
    stop_read();
    read_cb_ = nullptr;
    eof_cb_ = nullptr;
    shutdown_write();
}

void TcpSession::on_alloc(uv_handle_t*, size_t, uv_buf_t* buf) {
    // We use our own pre-allocated buffer
    static thread_local char slab[65536];
    buf->base = slab;
    buf->len = sizeof(slab);
}

void TcpSession::on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    auto* self = static_cast<TcpSession*>(stream->data);
    SessionPtr keep_alive;
    try {
        keep_alive = self->shared_from_this();
    } catch (const std::bad_weak_ptr&) {
        return;
    }
    if (self->closed_) return;

    if (nread > 0) {
        Buffer tmp(static_cast<size_t>(nread));
        tmp.append(reinterpret_cast<uint8_t*>(buf->base), static_cast<size_t>(nread));
        // The callback is allowed to replace/clear itself (the tunnel
        // handshake does exactly that when it switches to framed reads).
        // Keep a copy alive until the invocation returns; invoking the
        // std::function member directly while it is reassigned is undefined
        // behavior and used to cause intermittent use-after-free crashes.
        auto cb = self->read_cb_;
        if (cb) {
            cb(keep_alive, tmp);
        }
    } else if (nread == UV_EOF) {
        self->reading_ = false;
        self->read_eof_ = true;
        uv_read_stop(stream);
        auto cb = self->eof_cb_;
        if (cb) {
            cb(keep_alive);
        } else {
            self->close();
        }
        if (!self->closed_ && self->write_shutdown_) self->close();
    } else if (nread < 0) {
        TX_DEBUG("Read error: %s", uv_strerror(static_cast<int>(nread)));
        auto cb = self->error_cb_;
        if (cb) {
            cb(keep_alive, static_cast<int>(nread));
        }
        self->close();
    }
}

void TcpSession::on_shutdown(uv_shutdown_t* req, int status) {
    auto* holder = static_cast<SessionPtr*>(req->data);
    SessionPtr session = *holder;
    delete holder;
    delete req;
    if (!session) return;
    session->shutdown_pending_ = false;
    if (status == 0) {
        session->write_shutdown_ = true;
        // Once both directions have completed, all writes queued before
        // uv_shutdown have drained and the handle can be closed safely.
        if ((session->read_eof_ || session->close_after_flush_) &&
            !session->closed_) session->close();
    } else if (status != UV_ECANCELED) {
        TX_DEBUG("TCP shutdown error: %s", uv_strerror(status));
        if (!session->closed_) session->close();
    }
}

void TcpSession::on_write_free(uv_write_t* req, int status) {
    auto* wr = static_cast<WriteReq*>(req->data);
    auto session = wr->session;
    auto* self = session.get();
    if (self) {
        if (self->pending_write_bytes_ >= wr->len) {
            self->pending_write_bytes_ -= wr->len;
        } else {
            self->pending_write_bytes_ = 0;
        }
    }

    if (self && !self->closed_ &&
        self->pending_write_bytes_ <= self->write_low_watermark_ &&
        self->write_drain_cb_) {
        auto cb = self->write_drain_cb_;
        cb(self->shared_from_this());
    }

    if (status < 0 && status != UV_ECANCELED) {
        TX_DEBUG("Write error: %s", uv_strerror(status));
    }
    delete[] wr->data;
    delete wr;
}

void TcpSession::on_close(uv_handle_t* handle) {
    auto* self = static_cast<TcpSession*>(handle->data);
    SessionPtr keep_alive = std::move(self->self_ref_);
    self->closed_ = true;
    self->reading_ = false;
    self->paused_for_write_ = false;
    // Clear callbacks to prevent dangling references
    auto cb = std::move(self->close_cb_);
    self->read_cb_ = nullptr;
    self->write_drain_cb_ = nullptr;
    self->eof_cb_ = nullptr;
    self->error_cb_ = nullptr;
    if (cb) {
        cb(self->shared_from_this());
    }
}

void TcpSession::on_connect(uv_connect_t* req, int status) {
    auto* ctx = static_cast<ConnectCtx*>(req->data);
    if (ctx->timer) {
        uv_timer_stop(ctx->timer);
        ctx->timer->data = nullptr;
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(ctx->timer))) {
            uv_close(reinterpret_cast<uv_handle_t*>(ctx->timer), [](uv_handle_t* handle) {
                delete reinterpret_cast<uv_timer_t*>(handle);
            });
        }
        ctx->timer = nullptr;
    }
    if (ctx->completed) {
        delete ctx;
        delete req;
        return;
    }
    ctx->completed = true;
    bool success = (status == 0);
    double elapsed_ms = static_cast<double>(uv_hrtime() - ctx->started_ns) / 1000000.0;
    if (!success) {
        TX_ERROR("TCP socket #%llu connect error for %s after %.1f ms: %s",
                 static_cast<unsigned long long>(ctx->socket_sequence),
                 ctx->address.c_str(), elapsed_ms, uv_strerror(status));
    } else {
        TX_DEBUG("TCP socket #%llu connected to %s in %.1f ms",
                 static_cast<unsigned long long>(ctx->socket_sequence),
                 ctx->address.c_str(), elapsed_ms);
    }
    ctx->cb(success);
    if (!success && !ctx->session->is_closed()) {
        ctx->session->close();
    }
    delete ctx;
    delete req;
}

void TcpSession::on_connect_timeout(uv_timer_t* timer) {
    auto* ctx = static_cast<ConnectCtx*>(timer->data);
    if (!ctx || ctx->completed) return;
    ctx->completed = true;
    double elapsed_ms = static_cast<double>(uv_hrtime() - ctx->started_ns) / 1000000.0;
    TX_ERROR("TCP socket #%llu connect timeout for %s after %.1f ms",
             static_cast<unsigned long long>(ctx->socket_sequence),
             ctx->address.c_str(), elapsed_ms);
    uv_timer_stop(timer);
    if (!ctx->session->is_closed()) ctx->session->close();
    ctx->cb(false);
}

void TcpSession::on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    auto* ctx = static_cast<DnsResolveCtx*>(req->data);

    TX_DEBUG("TCP resolution completed status=%d for port %u", status, ctx ? ctx->port : 0);

    if (ctx->session->is_closed()) {
        ctx->cb(false);
        if (res) uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    if (status < 0 || !res) {
        TX_ERROR("DNS resolution failed: %s", status < 0 ? uv_strerror(status) : "no results");
        ctx->cb(false);
        if (!ctx->session->is_closed()) {
            ctx->session->close();
        }
        if (res) uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    // Prefer IPv4 when both families are returned. Many hosts can resolve
    // IPv6 even when the server does not have working IPv6 egress.
    struct addrinfo* selected = nullptr;
    for (auto* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            selected = ai;
            break;
        }
        if (!selected && ai->ai_family == AF_INET6) {
            selected = ai;
        }
    }

    if (!selected) {
        TX_ERROR("DNS resolution returned no TCP address");
        ctx->cb(false);
        if (!ctx->session->is_closed()) {
            ctx->session->close();
        }
        uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    memcpy(&storage, selected->ai_addr, selected->ai_addrlen);
    struct sockaddr* sa = reinterpret_cast<struct sockaddr*>(&storage);

    if (sa->sa_family == AF_INET) {
        reinterpret_cast<struct sockaddr_in*>(sa)->sin_port = htons(ctx->port);
    } else if (sa->sa_family == AF_INET6) {
        reinterpret_cast<struct sockaddr_in6*>(sa)->sin6_port = htons(ctx->port);
    }

    // Connect using resolved address
    if (!ensure_outbound_socket(&ctx->session->tcp_, sa->sa_family,
                                ctx->session->socket_protector_,
                                ctx->session->socket_policy_)) {
        ctx->cb(false);
        if (!ctx->session->is_closed()) {
            ctx->session->close();
        }
        uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    auto* connect_req = new uv_connect_t;
    ctx->session->socket_sequence_ =
        g_socket_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    ctx->session->remote_addr_ = ctx->session->remote_addr_.empty()
        ? std::string("resolved-address") : ctx->session->remote_addr_;
    auto* connect_ctx = new ConnectCtx{std::move(ctx->cb), ctx->session, nullptr, false,
                                       uv_hrtime(), ctx->session->socket_sequence_,
                                       ctx->session->remote_addr_ + ":" +
                                           std::to_string(ctx->port)};
    connect_req->data = connect_ctx;

    int r = uv_tcp_connect(connect_req, &ctx->session->tcp_, sa, on_connect);
    if (r != 0) {
        TX_ERROR("uv_tcp_connect after DNS failed: %s", uv_strerror(r));
        auto* connect_ctx = static_cast<ConnectCtx*>(connect_req->data);
        connect_ctx->cb(false);
        if (!connect_ctx->session->is_closed()) {
            connect_ctx->session->close();
        }
        delete connect_ctx;
        delete connect_req;
    } else if (ctx->timeout_ms > 0) {
        connect_ctx->timer = new uv_timer_t;
        connect_ctx->timer->data = connect_ctx;
        int timer_status = uv_timer_init(ctx->session->loop_, connect_ctx->timer);
        bool timer_initialized = timer_status == 0;
        if (timer_status == 0) {
            timer_status = uv_timer_start(connect_ctx->timer, on_connect_timeout,
                                          ctx->timeout_ms, 0);
        }
        if (timer_status != 0) {
            if (timer_initialized) {
                uv_close(reinterpret_cast<uv_handle_t*>(connect_ctx->timer),
                         [](uv_handle_t* handle) {
                             delete reinterpret_cast<uv_timer_t*>(handle);
                         });
            } else {
                delete connect_ctx->timer;
            }
            connect_ctx->timer = nullptr;
        }
    }

    uv_freeaddrinfo(res);
    delete ctx;
    delete req;
}

// ==================== TcpServer ====================

TcpServer::TcpServer(uv_loop_t* loop)
    : loop_(loop), listening_(false), transparent_(false), stopped_(false) {
    uv_tcp_init(loop_, &tcp_);
    tcp_.data = this;
}

TcpServer::~TcpServer() {
    stop();
}

bool TcpServer::listen(const std::string& host, uint16_t port) {
    if (stopped_ || uv_is_closing(reinterpret_cast<uv_handle_t*>(&tcp_))) {
        TX_ERROR("Cannot listen on a stopped TCP server");
        return false;
    }
    transparent_ = false;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr* sa;

    if (uv_ip4_addr(host.c_str(), port, &addr4) == 0) {
        sa = reinterpret_cast<struct sockaddr*>(&addr4);
    } else if (uv_ip6_addr(host.c_str(), port, &addr6) == 0) {
        sa = reinterpret_cast<struct sockaddr*>(&addr6);
    } else {
        TX_ERROR("Invalid listen address: %s:%u", host.c_str(), port);
        return false;
    }

    int r = uv_tcp_bind(&tcp_, sa, 0);
    if (r != 0) {
        TX_ERROR("uv_tcp_bind failed: %s", uv_strerror(r));
        return false;
    }

    r = uv_listen(reinterpret_cast<uv_stream_t*>(&tcp_), 128, on_connection);
    if (r != 0) {
        TX_ERROR("uv_listen failed: %s", uv_strerror(r));
        return false;
    }

    listening_ = true;
    TX_INFO("Listening on %s:%u", host.c_str(), port);
    return true;
}

bool TcpServer::listen_transparent(const std::string& host, uint16_t port) {
    if (stopped_ || uv_is_closing(reinterpret_cast<uv_handle_t*>(&tcp_))) {
        TX_ERROR("Cannot listen on a stopped TCP server");
        return false;
    }
    transparent_ = true;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr* sa;

    if (uv_ip4_addr(host.c_str(), port, &addr4) == 0) {
        sa = reinterpret_cast<struct sockaddr*>(&addr4);
    } else if (uv_ip6_addr(host.c_str(), port, &addr6) == 0) {
        sa = reinterpret_cast<struct sockaddr*>(&addr6);
    } else {
        TX_ERROR("Invalid listen address: %s:%u", host.c_str(), port);
        return false;
    }

#if defined(TX_PLATFORM_LINUX)
    if (!open_transparent_socket(&tcp_, sa->sa_family)) {
        return false;
    }
#else
    if (transparent_) {
        TX_ERROR("Transparent TCP listen is only supported on Linux");
        return false;
    }
#endif

    int r = uv_tcp_bind(&tcp_, sa, 0);
    if (r != 0) {
        TX_ERROR("uv_tcp_bind failed: %s", uv_strerror(r));
        return false;
    }

    r = uv_listen(reinterpret_cast<uv_stream_t*>(&tcp_), 128, on_connection);
    if (r != 0) {
        TX_ERROR("uv_listen failed: %s", uv_strerror(r));
        return false;
    }

    listening_ = true;
    TX_INFO("Listening on %s:%u", host.c_str(), port);
    return true;
}

void TcpServer::stop() {
    if (stopped_) return;
    stopped_ = true;
    listening_ = false;
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&tcp_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&tcp_), nullptr);
    }
}

void TcpServer::on_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        TX_ERROR("Connection error: %s", uv_strerror(status));
        return;
    }

    auto* self = static_cast<TcpServer*>(server->data);
    if (!self || self->stopped_ || !self->accept_cb_) return;

    auto session = std::make_shared<TcpSession>(self->loop_);
    if (!session->init(reinterpret_cast<uv_tcp_t*>(&self->tcp_))) return;
    self->accept_cb_(session);
}

} // namespace tx
