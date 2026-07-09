#include "tx/net/tcp_server.h"
#include "tx/common/log.h"
#include <cstring>
#include <arpa/inet.h>
#include <cerrno>

#if defined(TX_PLATFORM_LINUX)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tx {

namespace {

uint32_t g_tcp_outbound_mark = 0;

#if defined(TX_PLATFORM_LINUX)
bool set_outbound_mark(int fd) {
    if (g_tcp_outbound_mark == 0) return true;

    uint32_t mark = g_tcp_outbound_mark;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        TX_WARN("SO_MARK 0x%x failed: %s", mark, std::strerror(errno));
        return false;
    }
    return true;
}

bool ensure_outbound_socket(uv_tcp_t* tcp, int family) {
    if (g_tcp_outbound_mark == 0) return true;

    uv_os_fd_t fd;
    if (uv_fileno(reinterpret_cast<const uv_handle_t*>(tcp), &fd) == 0) {
        return set_outbound_mark(static_cast<int>(fd));
    }

    int sock = ::socket(family, SOCK_STREAM, 0);
    if (sock < 0) {
        TX_WARN("socket() for SO_MARK failed: %s", std::strerror(errno));
        return false;
    }

    if (!set_outbound_mark(sock)) {
        ::close(sock);
        return false;
    }

    int r = uv_tcp_open(tcp, static_cast<uv_os_sock_t>(sock));
    if (r != 0) {
        TX_WARN("uv_tcp_open for marked socket failed: %s", uv_strerror(r));
        ::close(sock);
        return false;
    }
    return true;
}

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
#else
bool ensure_outbound_socket(uv_tcp_t*, int) { return true; }
#endif

} // namespace

// DNS resolution context for TcpSession::connect
struct DnsResolveCtx {
    TcpSession::ConnectCb cb;
    SessionPtr            session;
    uint16_t              port;
};

struct ConnectCtx {
    TcpSession::ConnectCb cb;
    SessionPtr            session;
};

// ==================== TcpSession ====================

TcpSession::TcpSession(uv_loop_t* loop)
    : loop_(loop), closed_(false), reading_(false), remote_port_(0),
      pending_write_bytes_(0),
      write_high_watermark_(4 * 1024 * 1024),
      write_low_watermark_(1024 * 1024),
      paused_for_write_(false) {
    uv_tcp_init(loop_, &tcp_);
    tcp_.data = this;
}

TcpSession::~TcpSession() {
    if (!closed_) {
        TX_WARN("TcpSession destroyed before close completed");
    }
}

void TcpSession::init(uv_tcp_t* server_handle) {
    tcp_.data = this;

    uv_stream_t* server_stream = reinterpret_cast<uv_stream_t*>(server_handle);
    if (uv_accept(server_stream, reinterpret_cast<uv_stream_t*>(&tcp_)) != 0) {
        TX_ERROR("uv_accept failed");
        closed_ = true;
        return;
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
}

void TcpSession::connect(const std::string& host, uint16_t port, ConnectCb cb) {
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
        if (!ensure_outbound_socket(&tcp_, sa->sa_family)) {
            cb(false);
            close();
            delete req;
            return;
        }

        // Direct IP connect
        req->data = new ConnectCtx{std::move(cb), shared_from_this()};
        int r = uv_tcp_connect(req, &tcp_, sa, on_connect);
        if (r != 0) {
            TX_ERROR("uv_tcp_connect failed: %s", uv_strerror(r));
            auto* ctx = static_cast<ConnectCtx*>(req->data);
            ctx->cb(false);
            if (!ctx->session->is_closed()) {
                ctx->session->close();
            }
            delete ctx;
            delete req;
        }
        return;
    }

    // DNS resolution needed
    auto* resolve_ctx = new DnsResolveCtx{std::move(cb), shared_from_this(), port};
    auto* dns_req = new uv_getaddrinfo_t;
    dns_req->data = resolve_ctx;
    delete req;

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

void TcpSession::set_outbound_mark(uint32_t mark) {
    g_tcp_outbound_mark = mark;
}

bool TcpSession::send(const uint8_t* data, size_t len) {
    if (closed_ || len == 0) return false;

    auto* wr = new WriteReq;
    wr->data = new char[len];
    memcpy(wr->data, data, len);
    wr->buf = uv_buf_init(wr->data, static_cast<unsigned int>(len));
    wr->len = len;
    wr->session = shared_from_this();
    wr->req.data = wr;

    int r = uv_write(&wr->req, reinterpret_cast<uv_stream_t*>(&tcp_),
                      &wr->buf, 1, on_write_free);
    if (r != 0) {
        TX_DEBUG("uv_write failed: %s", uv_strerror(r));
        delete[] wr->data;
        delete wr;
        return false;
    }

    pending_write_bytes_ += len;
    if (pending_write_bytes_ > write_high_watermark_ && reading_) {
        paused_for_write_ = true;
        uv_read_stop(reinterpret_cast<uv_stream_t*>(&tcp_));
        reading_ = false;
        TX_DEBUG("Write backlog high (%zu bytes), pausing reads", pending_write_bytes_);
    }

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

void TcpSession::start_read(ReadCallback cb) {
    if (closed_) return;
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

void TcpSession::close() {
    if (closed_) return;
    closed_ = true;
    reading_ = false;
    paused_for_write_ = false;
    read_cb_ = nullptr;
    write_drain_cb_ = nullptr;
    try {
        self_ref_ = shared_from_this();
    } catch (const std::bad_weak_ptr&) {
        // TcpSession is expected to be owned by shared_ptr. If it is not,
        // keep the old behavior rather than throwing during shutdown.
    }
    uv_close(reinterpret_cast<uv_handle_t*>(&tcp_), on_close);
}

void TcpSession::on_alloc(uv_handle_t*, size_t, uv_buf_t* buf) {
    // We use our own pre-allocated buffer
    static thread_local char slab[65536];
    buf->base = slab;
    buf->len = sizeof(slab);
}

void TcpSession::on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    auto* self = static_cast<TcpSession*>(stream->data);
    // Guard: session may already be closing — shared_from_this() would throw
    if (self->closed_) return;

    if (nread > 0) {
        Buffer tmp(static_cast<size_t>(nread));
        tmp.append(reinterpret_cast<uint8_t*>(buf->base), static_cast<size_t>(nread));
        if (self->read_cb_) {
            self->read_cb_(self->shared_from_this(), tmp);
        }
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            TX_DEBUG("Read error: %s", uv_strerror(static_cast<int>(nread)));
        }
        self->close();
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

    if (self && !self->closed_ && self->paused_for_write_ &&
        self->pending_write_bytes_ <= self->write_low_watermark_ &&
        self->read_cb_) {
        self->paused_for_write_ = false;
        int r = uv_read_start(reinterpret_cast<uv_stream_t*>(&self->tcp_),
                              on_alloc, on_read);
        if (r == 0) {
            self->reading_ = true;
        } else if (r != UV_EALREADY) {
            TX_DEBUG("uv_read_start after write drain failed: %s", uv_strerror(r));
        }
    }

    if (self && !self->closed_ &&
        self->pending_write_bytes_ <= self->write_low_watermark_ &&
        self->write_drain_cb_) {
        self->write_drain_cb_(self->shared_from_this());
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
    if (cb) {
        cb(self->shared_from_this());
    }
}

void TcpSession::on_connect(uv_connect_t* req, int status) {
    auto* ctx = static_cast<ConnectCtx*>(req->data);
    bool success = (status == 0);
    if (!success) {
        TX_ERROR("Connect failed: %s", uv_strerror(status));
    }
    ctx->cb(success);
    if (!success && !ctx->session->is_closed()) {
        ctx->session->close();
    }
    delete ctx;
    delete req;
}

void TcpSession::on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    auto* ctx = static_cast<DnsResolveCtx*>(req->data);

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
    if (!ensure_outbound_socket(&ctx->session->tcp_, sa->sa_family)) {
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
    connect_req->data = new ConnectCtx{std::move(ctx->cb), ctx->session};

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
    }

    uv_freeaddrinfo(res);
    delete ctx;
    delete req;
}

// ==================== TcpServer ====================

TcpServer::TcpServer(uv_loop_t* loop)
    : loop_(loop), listening_(false), transparent_(false) {
    uv_tcp_init(loop_, &tcp_);
    tcp_.data = this;
}

TcpServer::~TcpServer() {
    stop();
}

bool TcpServer::listen(const std::string& host, uint16_t port) {
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
    if (listening_) {
        listening_ = false;
        uv_close(reinterpret_cast<uv_handle_t*>(&tcp_), nullptr);
    }
}

void TcpServer::on_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        TX_ERROR("Connection error: %s", uv_strerror(status));
        return;
    }

    auto* self = static_cast<TcpServer*>(server->data);
    if (!self->accept_cb_) return;

    auto session = std::make_shared<TcpSession>(self->loop_);
    session->init(reinterpret_cast<uv_tcp_t*>(&self->tcp_));
    self->accept_cb_(session);
}

} // namespace tx
