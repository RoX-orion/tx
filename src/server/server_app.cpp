#include "server_app.h"
#include "tx/common/log.h"
#include "tx/net/udp_flow_timeout.h"

#include "tx/common/network.h"
#include <cstring>
#include <cstdlib>
#include <stdexcept>

namespace tx {

namespace {

constexpr size_t kTunnelPauseWriteBacklog = 4 * 1024 * 1024;
constexpr size_t kTunnelResumeWriteBacklog = 1024 * 1024;
constexpr size_t kMaxTunnelWriteBacklog = 16 * 1024 * 1024;
constexpr size_t kMaxPendingTargetData = 4 * 1024 * 1024;
constexpr size_t kMaxUdpResolutionPendingPackets = 1024;
constexpr size_t kMaxUdpResolutionPendingBytes = 512 * 1024;

std::unique_ptr<uv_loop_t> create_server_loop() {
    std::unique_ptr<uv_loop_t> loop(new uv_loop_t);
    const int status = uv_loop_init(loop.get());
    if (status != 0) {
        throw std::runtime_error(std::string("Failed to initialize server libuv loop: ") +
                                 uv_strerror(status));
    }
    return loop;
}

void close_remaining_handle(uv_handle_t* handle, void*) {
    if (!uv_is_closing(handle)) uv_close(handle, nullptr);
}

void drain_and_close_loop(uv_loop_t* loop) {
    if (!loop) return;
    while (uv_loop_alive(loop)) uv_run(loop, UV_RUN_DEFAULT);
    int status = uv_loop_close(loop);
    if (status == 0) return;

    TX_WARN("Server loop still had handles during shutdown: %s", uv_strerror(status));
    uv_walk(loop, close_remaining_handle, nullptr);
    while (uv_loop_alive(loop)) uv_run(loop, UV_RUN_DEFAULT);
    status = uv_loop_close(loop);
    if (status != 0) {
        TX_ERROR("Failed to close server libuv loop: %s", uv_strerror(status));
    }
}

struct UdpSendReq {
    uv_udp_send_t req;
    uv_buf_t buf;
    char* data;
};

TargetAddr sockaddr_to_target(const sockaddr* addr) {
    TargetAddr target;
    char host[INET6_ADDRSTRLEN] = {0};
    if (addr->sa_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &a4->sin_addr, host, sizeof(host));
        target.type = AddrType::IPv4;
        target.host = host;
        target.port = ntohs(a4->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &a6->sin6_addr, host, sizeof(host));
        target.type = AddrType::IPv6;
        target.host = host;
        target.port = ntohs(a6->sin6_port);
    }
    return target;
}

bool target_to_sockaddr(const TargetAddr& target, sockaddr_storage& out) {
    memset(&out, 0, sizeof(out));
    if (target.type == AddrType::IPv4) {
        auto* a4 = reinterpret_cast<sockaddr_in*>(&out);
        return uv_ip4_addr(target.host.c_str(), target.port, a4) == 0;
    }
    if (target.type == AddrType::IPv6) {
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&out);
        return uv_ip6_addr(target.host.c_str(), target.port, a6) == 0;
    }
    return false;
}

bool same_sockaddr(const sockaddr_storage& left, const sockaddr_storage& right) {
    if (left.ss_family != right.ss_family) return false;
    if (left.ss_family == AF_INET) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(&left);
        const auto* b = reinterpret_cast<const sockaddr_in*>(&right);
        return a->sin_port == b->sin_port &&
               std::memcmp(&a->sin_addr, &b->sin_addr, sizeof(a->sin_addr)) == 0;
    }
    if (left.ss_family == AF_INET6) {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(&left);
        const auto* b = reinterpret_cast<const sockaddr_in6*>(&right);
        return a->sin6_port == b->sin6_port &&
               a->sin6_scope_id == b->sin6_scope_id &&
               std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
    }
    return false;
}

} // namespace

ServerApp::ServerApp()
    : owned_loop_(create_server_loop()),
      loop_(owned_loop_.get()),
      loop_closed_(false),
      server_(loop_),
      udp_cleanup_timer_started_(false),
      stop_async_initialized_(false),
      ready_to_run_(false),
      stop_requested_(false),
      stopping_(false) {}

ServerApp::~ServerApp() {
    stop();
    if (!loop_closed_) {
        drain_and_close_loop(loop_);
        loop_closed_ = true;
    }
}

bool ServerApp::init(const ServerConfig& config) {
    if (!stop_async_initialized_) {
        const int status = uv_async_init(loop_, &stop_async_, ServerApp::on_stop_async);
        if (status != 0) {
            TX_ERROR("Failed to initialize server stop handle: %s", uv_strerror(status));
            return false;
        }
        stop_async_.data = this;
        stop_async_initialized_ = true;
    }
    config_ = config;

    server_.set_accept_callback([this](SessionPtr s) { on_tunnel_accept(s); });
    if (!server_.listen(config.listen_host, config.listen_port)) {
        TX_ERROR("Failed to listen on %s:%u",
                 config.listen_host.c_str(), config.listen_port);
        return false;
    }
    if (!start_udp_cleanup_timer()) {
        server_.stop();
        return false;
    }

    TX_INFO("TX Server started on %s:%u (UDP timeout: %llu seconds)",
            config.listen_host.c_str(), config.listen_port,
            static_cast<unsigned long long>(config_.udp_idle_timeout_ms / 1000));
    ready_to_run_ = true;
    return true;
}

int ServerApp::run() {
    return uv_run(loop_, UV_RUN_DEFAULT);
}

void ServerApp::stop() {
    if (stop_requested_.exchange(true, std::memory_order_acq_rel)) return;

    if (ready_to_run_ && stop_async_initialized_) {
        uv_async_send(&stop_async_);
        return;
    }

    // Initialization failures never enter uv_run(), so perform the same
    // cleanup synchronously on the constructing thread.
    stop_on_loop();
    uv_run(loop_, UV_RUN_NOWAIT);
}

void ServerApp::on_stop_async(uv_async_t* handle) {
    auto* app = static_cast<ServerApp*>(handle->data);
    if (app) app->stop_on_loop();
}

void ServerApp::stop_on_loop() {
    if (stopping_) return;
    stopping_ = true;

    stop_udp_cleanup_timer();
    server_.stop();

    std::vector<TunnelClientPtr> clients;
    clients.reserve(clients_.size());
    for (const auto& kv : clients_) clients.push_back(kv.second);
    for (const auto& client : clients) {
        if (client->session && !client->session->is_closed()) {
            client->session->close();
        } else {
            on_tunnel_close(client);
        }
    }
    if (stop_async_initialized_ &&
        !uv_is_closing(reinterpret_cast<uv_handle_t*>(&stop_async_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&stop_async_), nullptr);
    }
}

bool ServerApp::start_udp_cleanup_timer() {
    if (udp_cleanup_timer_started_) return true;

    int r = uv_timer_init(loop_, &udp_cleanup_timer_);
    if (r != 0) {
        TX_ERROR("Failed to initialize UDP cleanup timer: %s", uv_strerror(r));
        return false;
    }
    udp_cleanup_timer_.data = this;

    uint64_t interval = udp_flow_cleanup_interval(config_.udp_idle_timeout_ms);
    r = uv_timer_start(&udp_cleanup_timer_, ServerApp::on_udp_cleanup_timer,
                       interval, interval);
    if (r != 0) {
        TX_ERROR("Failed to start UDP cleanup timer: %s", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(&udp_cleanup_timer_), nullptr);
        return false;
    }
    udp_cleanup_timer_started_ = true;
    return true;
}

void ServerApp::stop_udp_cleanup_timer() {
    if (!udp_cleanup_timer_started_) return;
    udp_cleanup_timer_started_ = false;
    uv_timer_stop(&udp_cleanup_timer_);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&udp_cleanup_timer_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&udp_cleanup_timer_), nullptr);
    }
}

bool ServerApp::consume_client_rate(TunnelClientPtr client, size_t bytes) {
    if (!client || client->closed || bytes == 0) return !client || !client->closed;
    const uint64_t now = uv_now(loop_);
    if (client->rate_window_started_ms == 0 ||
        now - client->rate_window_started_ms >= 1000) {
        client->rate_window_started_ms = now;
        client->rate_window_bytes = 0;
    }
    if (bytes > config_.max_client_rate_bytes_per_sec -
                    std::min(client->rate_window_bytes,
                             config_.max_client_rate_bytes_per_sec)) {
        TX_WARN("Closing tunnel client that exceeded the configured %llu B/s input rate",
                static_cast<unsigned long long>(config_.max_client_rate_bytes_per_sec));
        if (client->session && !client->session->is_closed()) client->session->close();
        return false;
    }
    client->rate_window_bytes += bytes;
    return true;
}

void ServerApp::start_handshake_timer(TunnelClientPtr client) {
    if (!client || client->handshake_timer) return;
    auto* timer = new uv_timer_t;
    auto* ctx = new HandshakeTimerCtx{this, client};
    timer->data = ctx;
    const int initialized = uv_timer_init(loop_, timer);
    if (initialized != 0 ||
        (initialized == 0 && uv_timer_start(timer, ServerApp::on_handshake_timer,
                                             config_.handshake_timeout_ms, 0) != 0)) {
        if (initialized == 0) {
            uv_close(reinterpret_cast<uv_handle_t*>(timer), ServerApp::on_handshake_timer_closed);
        } else {
            delete ctx;
            delete timer;
        }
        TX_WARN("Could not start tunnel handshake timeout timer");
        return;
    }
    client->handshake_timer = timer;
}

void ServerApp::stop_handshake_timer(TunnelClientPtr client) {
    if (!client || !client->handshake_timer) return;
    uv_timer_t* timer = client->handshake_timer;
    client->handshake_timer = nullptr;
    uv_timer_stop(timer);
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ServerApp::on_handshake_timer_closed);
    }
}

void ServerApp::on_handshake_timer(uv_timer_t* timer) {
    auto* ctx = static_cast<HandshakeTimerCtx*>(timer->data);
    if (!ctx || !ctx->app || !ctx->client || ctx->client->closed ||
        ctx->client->handshake_timer != timer) return;
    ctx->client->handshake_timer = nullptr;
    TX_WARN("Closing tunnel client after handshake timeout");
    if (ctx->client->session && !ctx->client->session->is_closed()) {
        ctx->client->session->close();
    }
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ServerApp::on_handshake_timer_closed);
    }
}

void ServerApp::on_handshake_timer_closed(uv_handle_t* handle) {
    auto* ctx = static_cast<HandshakeTimerCtx*>(handle->data);
    delete ctx;
    delete reinterpret_cast<uv_timer_t*>(handle);
}

void ServerApp::cleanup_idle_udp_outbounds(uint64_t now_ms) {
    size_t cleaned = 0;
    for (auto& client_entry : clients_) {
        auto& client = client_entry.second;
        for (auto it = client->udp_outbounds.begin();
             it != client->udp_outbounds.end();) {
            if (!udp_flow_is_idle(now_ms, it->second.last_activity_ms,
                                  config_.udp_idle_timeout_ms)) {
                ++it;
                continue;
            }

            SessionId sid = it->first;
            tunnel_send_disconnect(client, sid);
            close_udp_outbound(it->second);
            it = client->udp_outbounds.erase(it);
            ++cleaned;
        }
    }
    if (cleaned > 0) {
        TX_DEBUG("Cleaned up %zu idle UDP outbounds", cleaned);
    }
}

void ServerApp::on_udp_cleanup_timer(uv_timer_t* timer) {
    auto* app = static_cast<ServerApp*>(timer->data);
    if (app) {
        app->cleanup_idle_udp_outbounds(uv_now(app->loop_));
    }
}

void ServerApp::on_tunnel_accept(SessionPtr session) {
    TX_INFO("Tunnel client connected from %s:%u",
            session->remote_addr().c_str(), session->remote_port());

    if (clients_.size() >= config_.max_clients) {
        TX_WARN("Rejecting tunnel client: configured client limit reached");
        session->close();
        return;
    }
    const uint64_t now = uv_now(loop_);
    if (new_client_window_started_ms_ == 0 || now - new_client_window_started_ms_ >= 1000) {
        new_client_window_started_ms_ = now;
        new_client_window_count_ = 0;
    }
    if (new_client_window_count_ >= config_.max_new_clients_per_second) {
        TX_WARN("Rejecting tunnel client: new-client rate limit reached");
        session->close();
        return;
    }
    ++new_client_window_count_;
    const std::string source_ip = session->remote_addr();
    uint32_t& pending_from_ip = unauthenticated_by_ip_[source_ip];
    if (pending_from_ip >= config_.max_unauthenticated_per_ip) {
        TX_WARN("Rejecting tunnel client from %s: unauthenticated client limit reached",
                source_ip.c_str());
        session->close();
        return;
    }
    ++pending_from_ip;

    auto client = std::make_shared<TunnelClient>();
    client->session = session;
    client->source_ip = source_ip;

    clients_[session->handle()] = client;
    start_handshake_timer(client);

    session->set_close_callback([this, client](SessionPtr) {
        on_tunnel_close(client);
    });
    session->set_write_drain_callback([this, client](SessionPtr) {
        resume_outbound_reads(client);
    });

    session->start_read([this, client](SessionPtr, Buffer& data) {
        if (!consume_client_rate(client, data.readable())) {
            data.clear();
            return;
        }
        on_tunnel_handshake_read(client, data);
    });
}

void ServerApp::on_tunnel_handshake_read(TunnelClientPtr client, Buffer& data) {
    client->handshake_buf.append(data);
    data.clear();

    if (client->handshake_buf.readable() < TunnelCodec::kHandshakeSize) {
        return;
    }

    TunnelPeerHello client_hello;
    if (!TunnelCodec::parse_client_hello(config_.psk,
                                          client->handshake_buf.data(),
                                          TunnelCodec::kHandshakeSize,
                                          client_hello)) {
        if (client->session && !client->session->is_closed()) {
            client->session->close();
        }
        return;
    }

    Buffer hello;
    TunnelHandshakeState server_state;
    TunnelTrafficKeys keys;
    if (!TunnelCodec::build_server_hello(config_.psk, client_hello,
                                          hello, server_state, keys)) {
        if (client->session && !client->session->is_closed()) {
            client->session->close();
        }
        return;
    }

    client->codec = TunnelCodec(keys, false);
    stop_handshake_timer(client);
    if (!client->authenticated) {
        client->authenticated = true;
        auto pending = unauthenticated_by_ip_.find(client->source_ip);
        if (pending != unauthenticated_by_ip_.end()) {
            if (pending->second > 1) --pending->second;
            else unauthenticated_by_ip_.erase(pending);
        }
    }

    client->session->send(hello);
    client->handshake_buf.consume(TunnelCodec::kHandshakeSize);
    TX_INFO("Tunnel handshake complete for %s:%u",
            client->session->remote_addr().c_str(), client->session->remote_port());

    client->session->start_read([this, client](SessionPtr, Buffer& more) {
        if (!consume_client_rate(client, more.readable())) {
            more.clear();
            return;
        }
        client->recv_buf.append(more);
        more.clear();
        on_tunnel_read(client, client->recv_buf);
    });

    if (!client->handshake_buf.empty()) {
        client->recv_buf.append(client->handshake_buf);
        client->handshake_buf.clear();
        on_tunnel_read(client, client->recv_buf);
    }
}

void ServerApp::on_tunnel_read(TunnelClientPtr client, Buffer& data) {
    TunnelCmd cmd;
    SessionId session_id;
    TargetAddr target;
    Buffer payload;

    while (client->codec.decode(data, cmd, session_id, target, payload)) {
        switch (cmd) {
            case TunnelCmd::Connect:
                handle_connect(client, session_id, target);
                break;
            case TunnelCmd::Data:
                handle_data(client, session_id, payload);
                break;
            case TunnelCmd::UdpPacket:
                handle_udp_packet(client, session_id, target, payload);
                break;
            case TunnelCmd::Disconnect:
                handle_disconnect(client, session_id);
                break;
            case TunnelCmd::HalfClose:
                handle_half_close(client, session_id);
                break;
            case TunnelCmd::ConnectResult:
                TX_DEBUG("Unexpected CONNECT_RESULT from client for session %u", session_id);
                break;
        }
    }

    if (client->codec.has_protocol_error()) {
        TX_ERROR("Closing tunnel client because data is not valid TX tunnel protocol");
        client->codec.clear_protocol_error();
        if (client->session && !client->session->is_closed()) {
            client->session->close();
        }
    }
}

void ServerApp::handle_connect(TunnelClientPtr client, SessionId sid,
                                 const TargetAddr& target) {
    if (!client || client->closed) return;
    if (sid == 0) {
        TX_ERROR("Rejecting invalid TCP session ID 0 from tunnel client");
        if (client->session && !client->session->is_closed()) client->session->close();
        return;
    }
    if (client->outbounds.find(sid) != client->outbounds.end() ||
        client->udp_outbounds.find(sid) != client->udp_outbounds.end()) {
        TX_ERROR("Duplicate or cross-protocol session ID %u from tunnel client", sid);
        if (client->session && !client->session->is_closed()) client->session->close();
        return;
    }
    if (client->outbounds.size() >= config_.max_tcp_outbounds_per_client) {
        TX_WARN("Rejecting TCP session %u: per-client outbound limit reached", sid);
        tunnel_send_connect_result(client, sid, false);
        return;
    }
    TX_INFO("CONNECT session %u → %s:%u", sid, target.host.c_str(), target.port);

    auto remote = std::make_shared<TcpSession>(loop_);
    TunnelClient::Outbound ob;
    ob.remote_session = remote;
    ob.session_id = sid;
    ob.generation = client->next_tcp_generation++;
    ob.connected = false;
    const uint64_t generation = ob.generation;
    client->outbounds.emplace(sid, std::move(ob));

    // Use weak_ptr to avoid capturing remote in its own close callback
    std::weak_ptr<TcpSession> weak_remote = remote;

    remote->set_close_callback([this, client, sid, generation, weak_remote](SessionPtr) {
        TX_DEBUG("Remote closed for session %u", sid);
        // Only act if the outbound still exists and matches
        auto it = client->outbounds.find(sid);
        if (it != client->outbounds.end() &&
            it->second.generation == generation &&
            it->second.remote_session.get() == weak_remote.lock().get()) {
            tunnel_send_disconnect(client, sid);
            client->outbounds.erase(it);
        }
    });
    remote->set_eof_callback([this, client, sid, generation, weak_remote](SessionPtr) {
        auto it = client->outbounds.find(sid);
        if (it == client->outbounds.end() || it->second.generation != generation ||
            it->second.remote_session.get() != weak_remote.lock().get()) return;
        it->second.remote_eof = true;
        tunnel_send_half_close(client, sid);
    });
    remote->set_write_drain_callback([client, sid, generation, weak_remote](SessionPtr remote_session) {
        auto it = client->outbounds.find(sid);
        if (it == client->outbounds.end() || it->second.generation != generation ||
            it->second.remote_session.get() != weak_remote.lock().get()) return;
        if (client->inbound_paused && client->session &&
            !client->session->is_closed() &&
            remote_session->pending_write_bytes() <= kTunnelResumeWriteBacklog) {
            client->inbound_paused = false;
            client->session->resume_read();
        }
    });

    remote->connect(target.host, target.port, config_.connect_timeout_ms,
        [this, client, sid, generation, remote, target, weak_remote](bool success) {
            auto it = client->outbounds.find(sid);
            const bool current = it != client->outbounds.end() &&
                it->second.generation == generation && it->second.remote_session == remote;
            if (!current) {
                if (!remote->is_closed()) remote->close();
                return;
            }
            if (!success) {
                TX_ERROR("Failed to connect to target for session %u: %s:%u",
                         sid, target.host.c_str(), target.port);
                tunnel_send_connect_result(client, sid, false);
                client->outbounds.erase(it);
                return;
            }

            TX_INFO("Connected to target for session %u: %s:%u",
                    sid, target.host.c_str(), target.port);

            // Mark as connected and flush pending data
            it->second.connected = true;
            tunnel_send_connect_result(client, sid, true);

            if (!it->second.pending_data.empty()) {
                TX_INFO("Flushing %zu pending bytes to target for session %u",
                        it->second.pending_data.readable(), sid);
                remote->send(it->second.pending_data);
                it->second.pending_data.clear();
            }

            // HALF_CLOSE may immediately follow CONNECT while the asynchronous
            // target connect is still pending. Apply it only after queued data
            // has been handed to the connected socket.
            if (it->second.client_eof && !remote->is_closed()) {
                remote->shutdown_write();
            }

            if (!client->outbounds_paused) {
                // Start reading from remote → forward back through tunnel.
                remote->start_read([this, client, sid, generation, weak_remote](SessionPtr, Buffer& data) {
                    auto current = client->outbounds.find(sid);
                    if (current == client->outbounds.end() ||
                        current->second.generation != generation ||
                        current->second.remote_session.get() != weak_remote.lock().get()) {
                        data.clear();
                        return;
                    }
                    tunnel_send_data(client, sid, data.data(), data.readable());
                    data.clear();
                });
            }
        });
}

void ServerApp::handle_data(TunnelClientPtr client, SessionId sid, Buffer& payload) {
    auto it = client->outbounds.find(sid);
    if (it == client->outbounds.end()) {
        TX_WARN("Data for unknown session %u (%zu bytes)", sid, payload.readable());
        return;
    }

    if (it->second.connected &&
        it->second.remote_session && !it->second.remote_session->is_closed()) {
        size_t payload_len = payload.readable();
        if (it->second.remote_session->pending_write_bytes() + payload_len >
            kMaxTunnelWriteBacklog) {
            TX_ERROR("Target write backlog too large for session %u", sid);
            handle_disconnect(client, sid);
            payload.clear();
            return;
        }
        if (!it->second.remote_session->send(payload)) {
            TX_ERROR("Failed to send %zu bytes to target for session %u",
                     payload_len, sid);
            handle_disconnect(client, sid);
        } else if (!client->inbound_paused &&
                   it->second.remote_session->pending_write_bytes() >=
                       kTunnelPauseWriteBacklog) {
            client->inbound_paused = true;
            client->session->pause_read();
        }
    } else {
        // Buffer data until remote connection is established
        if (it->second.pending_data.readable() + payload.readable() > kMaxPendingTargetData) {
            TX_ERROR("Pending target data too large for session %u: %zu + %zu bytes",
                     sid, it->second.pending_data.readable(), payload.readable());
            tunnel_send_connect_result(client, sid, false);
            handle_disconnect(client, sid);
            payload.clear();
            return;
        }
        it->second.pending_data.append(payload);
    }
    payload.clear();
}

void ServerApp::handle_udp_packet(TunnelClientPtr client, SessionId sid,
                                  const TargetAddr& target, Buffer& payload) {
    if (payload.empty()) return;
    if (!client || client->closed) {
        payload.clear();
        return;
    }
    if (sid == 0) {
        TX_ERROR("Rejecting invalid UDP session ID 0 from tunnel client");
        payload.clear();
        if (client->session && !client->session->is_closed()) client->session->close();
        return;
    }
    if (client->outbounds.find(sid) != client->outbounds.end()) {
        TX_ERROR("UDP packet reuses TCP session ID %u", sid);
        payload.clear();
        if (client->session && !client->session->is_closed()) client->session->close();
        return;
    }

    auto it = client->udp_outbounds.find(sid);
    if (it == client->udp_outbounds.end()) {
        if (client->udp_outbounds.size() >= config_.max_udp_flows_per_client) {
            TX_WARN("Dropping UDP session %u: per-client flow limit reached", sid);
            tunnel_send_disconnect(client, sid);
            payload.clear();
            return;
        }
        const uint64_t generation = client->next_udp_generation++;
        TunnelClient::UdpOutbound out;
        out.session_id = sid;
        out.generation = generation;
        out.last_activity_ms = uv_now(loop_);
        it = client->udp_outbounds.emplace(sid, out).first;
    }
    it->second.last_activity_ms = uv_now(loop_);

    sockaddr_storage addr;
    if (target_to_sockaddr(target, addr)) {
        if (it->second.resolving ||
            (it->second.peer_ready && !same_sockaddr(it->second.peer, addr))) {
            TX_WARN("Dropping UDP session %u packet for changed target %s:%u",
                    sid, target.host.c_str(), target.port);
            payload.clear();
            return;
        }
        it->second.peer = addr;
        it->second.peer_len = addr.ss_family == AF_INET ? sizeof(sockaddr_in)
                                                         : sizeof(sockaddr_in6);
        it->second.peer_ready = true;
        if (!ensure_udp_outbound_socket(client, sid, it->second, addr.ss_family)) {
            payload.clear();
            return;
        }
        send_udp_datagram(udp_outbound_socket(it->second, addr.ss_family), addr,
                          payload.data(), payload.readable());
    } else if (target.type == AddrType::Domain) {
        if (it->second.peer_ready) {
            if (it->second.resolution_target.type != AddrType::Domain ||
                it->second.resolution_target.host != target.host ||
                it->second.resolution_target.port != target.port) {
                TX_WARN("Dropping UDP session %u packet for changed domain target %s:%u",
                        sid, target.host.c_str(), target.port);
                payload.clear();
                return;
            }
            uv_udp_t* udp = udp_outbound_socket(it->second, it->second.peer.ss_family);
            if (udp) send_udp_datagram(udp, it->second.peer, payload.data(), payload.readable());
            payload.clear();
            return;
        }
        if (it->second.resolving) {
            if (it->second.resolution_target.host != target.host ||
                it->second.resolution_target.port != target.port) {
                TX_WARN("Dropping UDP session %u packet for changed domain target %s:%u",
                        sid, target.host.c_str(), target.port);
            } else {
                queue_udp_resolution_packet(it->second, payload.data(), payload.readable());
            }
            payload.clear();
            return;
        }

        it->second.resolving = true;
        it->second.resolution_target = target;
        if (!queue_udp_resolution_packet(it->second, payload.data(), payload.readable())) {
            it->second.resolving = false;
            payload.clear();
            return;
        }
        auto* resolve_ctx = new UdpResolveCtx;
        resolve_ctx->app = this;
        resolve_ctx->client = client;
        resolve_ctx->sid = sid;
        resolve_ctx->generation = it->second.generation;
        resolve_ctx->target = target;
        auto* req = new uv_getaddrinfo_t;
        req->data = resolve_ctx;
        int r = uv_getaddrinfo(loop_, req, ServerApp::on_udp_resolved,
                               target.host.c_str(), nullptr, nullptr);
        if (r != 0) {
            it->second.resolving = false;
            it->second.pending_resolution_packets.clear();
            it->second.pending_resolution_bytes = 0;
            delete resolve_ctx;
            delete req;
        }
    }

    payload.clear();
}

bool ServerApp::ensure_udp_outbound_socket(TunnelClientPtr client, SessionId sid,
                                           TunnelClient::UdpOutbound& outbound,
                                           int family) {
    if (udp_outbound_socket(outbound, family)) return true;
    if (family != AF_INET && family != AF_INET6) return false;

    auto* udp = new uv_udp_t;
    const int init_status = uv_udp_init(loop_, udp);
    if (init_status != 0) {
        TX_ERROR("Failed to initialize UDP session %u: %s", sid, uv_strerror(init_status));
        delete udp;
        return false;
    }

    auto* ctx = new UdpCtx{this, client, sid, outbound.generation, family};
    udp->data = ctx;
    int bind_status = 0;
    if (family == AF_INET) {
        sockaddr_in bind_addr;
        uv_ip4_addr("0.0.0.0", 0, &bind_addr);
        bind_status = uv_udp_bind(udp, reinterpret_cast<const sockaddr*>(&bind_addr), 0);
    } else {
        sockaddr_in6 bind_addr;
        uv_ip6_addr("::", 0, &bind_addr);
        bind_status = uv_udp_bind(udp, reinterpret_cast<const sockaddr*>(&bind_addr), 0);
    }
    if (bind_status != 0 ||
        uv_udp_recv_start(udp, ServerApp::udp_alloc, ServerApp::on_udp_read) != 0) {
        if (bind_status != 0) {
            TX_ERROR("Failed to bind UDP session %u: %s", sid, uv_strerror(bind_status));
        } else {
            TX_ERROR("Failed to start UDP receive for session %u", sid);
        }
        uv_close(reinterpret_cast<uv_handle_t*>(udp), ServerApp::on_udp_closed);
        return false;
    }

    if (family == AF_INET) outbound.udp_v4 = udp;
    else outbound.udp_v6 = udp;
    return true;
}

uv_udp_t* ServerApp::udp_outbound_socket(TunnelClient::UdpOutbound& outbound,
                                         int family) const {
    if (family == AF_INET) return outbound.udp_v4;
    if (family == AF_INET6) return outbound.udp_v6;
    return nullptr;
}

void ServerApp::close_udp_outbound(TunnelClient::UdpOutbound& outbound) {
    const auto close_socket = [](uv_udp_t*& udp) {
        if (udp && !uv_is_closing(reinterpret_cast<uv_handle_t*>(udp))) {
            uv_close(reinterpret_cast<uv_handle_t*>(udp), ServerApp::on_udp_closed);
        }
        udp = nullptr;
    };
    close_socket(outbound.udp_v4);
    close_socket(outbound.udp_v6);
    outbound.pending_resolution_packets.clear();
    outbound.pending_resolution_bytes = 0;
    outbound.resolving = false;
}

bool ServerApp::queue_udp_resolution_packet(TunnelClient::UdpOutbound& outbound,
                                            const uint8_t* data, size_t len) {
    if (!data || len == 0 ||
        outbound.pending_resolution_packets.size() >= kMaxUdpResolutionPendingPackets ||
        len > kMaxUdpResolutionPendingBytes ||
        outbound.pending_resolution_bytes > kMaxUdpResolutionPendingBytes - len) {
        TX_WARN("Dropping UDP packet while resolving %s: queue limit reached",
                outbound.resolution_target.host.c_str());
        return false;
    }
    outbound.pending_resolution_packets.emplace_back(data, data + len);
    outbound.pending_resolution_bytes += len;
    return true;
}

bool ServerApp::send_udp_datagram(uv_udp_t* udp, const sockaddr_storage& target,
                                  const uint8_t* data, size_t len) {
    if (!udp || !data || len == 0) return false;
    auto* wr = new UdpSendReq;
    wr->data = new char[len];
    memcpy(wr->data, data, len);
    wr->buf = uv_buf_init(wr->data, static_cast<unsigned int>(len));
    const int status = uv_udp_send(&wr->req, udp, &wr->buf, 1,
                                   reinterpret_cast<const sockaddr*>(&target),
                                   ServerApp::on_udp_send_done);
    if (status == 0) return true;
    TX_WARN("UDP send failed: %s", uv_strerror(status));
    delete[] wr->data;
    delete wr;
    return false;
}

void ServerApp::handle_disconnect(TunnelClientPtr client, SessionId sid) {
    TX_DEBUG("DISCONNECT session %u", sid);
    auto it = client->outbounds.find(sid);
    if (it != client->outbounds.end()) {
        if (it->second.remote_session && !it->second.remote_session->is_closed()) {
            it->second.remote_session->close();
        }
        client->outbounds.erase(it);
    }
    auto udp_it = client->udp_outbounds.find(sid);
    if (udp_it != client->udp_outbounds.end()) {
        close_udp_outbound(udp_it->second);
        client->udp_outbounds.erase(udp_it);
    }
}

void ServerApp::handle_half_close(TunnelClientPtr client, SessionId sid) {
    auto it = client->outbounds.find(sid);
    if (it == client->outbounds.end()) return;
    it->second.client_eof = true;
    if (it->second.connected && it->second.remote_session &&
        !it->second.remote_session->is_closed()) {
        it->second.remote_session->shutdown_write();
    }
}

void ServerApp::tunnel_send_data(TunnelClientPtr client, SessionId sid,
                                   const uint8_t* data, size_t len) {
    if (!client->session || client->session->is_closed()) return;

    if (client->session->pending_write_bytes() > kMaxTunnelWriteBacklog) {
        TX_ERROR("Tunnel write backlog too large (%zu bytes), closing tunnel",
                 client->session->pending_write_bytes());
        client->session->close();
        return;
    }

    Buffer encoded;
    if (client->codec.encode_data_chunks(sid, data, len, encoded)) {
        if (!client->session->send(encoded)) {
            TX_ERROR("Failed to send %zu encoded bytes to tunnel for session %u",
                     encoded.readable(), sid);
        } else if (client->session->pending_write_bytes() > kTunnelPauseWriteBacklog) {
            pause_outbound_reads(client);
        }
    } else {
        TX_ERROR("Failed to encode %zu bytes for tunnel session %u", len, sid);
    }
}

void ServerApp::tunnel_send_udp_packet(TunnelClientPtr client, SessionId sid,
                                       const TargetAddr& target,
                                       const uint8_t* data, size_t len) {
    if (!client->session || client->session->is_closed()) return;

    Buffer encoded;
    if (client->codec.encode_udp_packet(sid, target, data, len, encoded)) {
        if (!client->session->send(encoded)) {
            TX_ERROR("Failed to send UDP packet to tunnel for session %u", sid);
        }
    }
}

void ServerApp::tunnel_send_disconnect(TunnelClientPtr client, SessionId sid) {
    if (!client->session || client->session->is_closed()) return;
    Buffer encoded;
    if (client->codec.encode_disconnect(sid, encoded)) {
        if (!client->session->send(encoded)) {
            TX_ERROR("Failed to send DISCONNECT for session %u", sid);
        }
    } else {
        TX_ERROR("Failed to encode DISCONNECT for session %u", sid);
    }
}

void ServerApp::tunnel_send_half_close(TunnelClientPtr client, SessionId sid) {
    if (!client->session || client->session->is_closed()) return;
    Buffer encoded;
    if (client->codec.encode_half_close(sid, encoded) &&
        !client->session->send(encoded)) {
        TX_ERROR("Failed to send HALF_CLOSE for session %u", sid);
    }
}

void ServerApp::tunnel_send_connect_result(TunnelClientPtr client, SessionId sid,
                                             bool success) {
    if (!client->session || client->session->is_closed()) return;
    Buffer encoded;
    if (client->codec.encode_connect_result(sid, success, encoded)) {
        if (success) {
            TX_DEBUG("CONNECT_RESULT session %u → success", sid);
        } else {
            TX_WARN("CONNECT_RESULT session %u → failure", sid);
        }
        if (!client->session->send(encoded)) {
            TX_ERROR("Failed to send CONNECT_RESULT for session %u", sid);
        }
    } else {
        TX_ERROR("Failed to encode CONNECT_RESULT for session %u", sid);
    }
}

void ServerApp::pause_outbound_reads(TunnelClientPtr client) {
    if (!client || client->outbounds_paused) {
        return;
    }
    client->outbounds_paused = true;

    for (auto& kv : client->outbounds) {
        auto& outbound = kv.second;
        if (outbound.remote_session && !outbound.remote_session->is_closed() &&
            outbound.remote_session->is_reading()) {
            outbound.remote_session->stop_read();
        }
    }

    TX_DEBUG("Paused outbound reads because tunnel backlog reached %zu bytes",
             client->session ? client->session->pending_write_bytes() : 0);
}

void ServerApp::resume_outbound_reads(TunnelClientPtr client) {
    if (!client || !client->session || client->session->is_closed() ||
        !client->outbounds_paused) {
        return;
    }

    if (client->session->pending_write_bytes() > kTunnelResumeWriteBacklog) {
        return;
    }

    client->outbounds_paused = false;

    for (auto& kv : client->outbounds) {
        auto sid = kv.first;
        auto& outbound = kv.second;
        if (!outbound.connected || !outbound.remote_session ||
            outbound.remote_session->is_closed()) {
            continue;
        }

        const uint64_t generation = outbound.generation;
        std::weak_ptr<TcpSession> weak_remote = outbound.remote_session;
        outbound.remote_session->start_read([this, client, sid, generation, weak_remote]
                                            (SessionPtr, Buffer& data) {
            auto current = client->outbounds.find(sid);
            if (current == client->outbounds.end() ||
                current->second.generation != generation ||
                current->second.remote_session.get() != weak_remote.lock().get()) {
                data.clear();
                return;
            }
            tunnel_send_data(client, sid, data.data(), data.readable());
            data.clear();
        });
    }

    TX_DEBUG("Resumed outbound reads after tunnel backlog drained to %zu bytes",
             client->session->pending_write_bytes());
}

void ServerApp::udp_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    auto* data = static_cast<char*>(malloc(suggested_size));
    *buf = uv_buf_init(data, static_cast<unsigned int>(suggested_size));
}

void ServerApp::on_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                            const struct sockaddr* addr, unsigned flags) {
    std::unique_ptr<char, decltype(&free)> storage(buf->base, free);
    if (nread <= 0 || !addr) return;

    auto* ctx = static_cast<UdpCtx*>(handle->data);
    if (!ctx || !ctx->app || !ctx->client || ctx->client->closed) return;

    auto it = ctx->client->udp_outbounds.find(ctx->sid);
    if (it == ctx->client->udp_outbounds.end() ||
        it->second.generation != ctx->generation ||
        !it->second.peer_ready ||
        ctx->app->udp_outbound_socket(it->second, ctx->family) != handle) {
        return;
    }
    sockaddr_storage source_addr{};
    if (addr->sa_family == AF_INET) {
        memcpy(&source_addr, addr, sizeof(sockaddr_in));
    } else if (addr->sa_family == AF_INET6) {
        memcpy(&source_addr, addr, sizeof(sockaddr_in6));
    } else {
        return;
    }
    if (!same_sockaddr(it->second.peer, source_addr)) {
        TX_DEBUG("Ignoring UDP response for session %u from an unexpected peer", ctx->sid);
        return;
    }
    it->second.last_activity_ms = uv_now(ctx->app->loop_);

    TargetAddr source = sockaddr_to_target(addr);
    ctx->app->tunnel_send_udp_packet(ctx->client, ctx->sid, source,
                                     reinterpret_cast<const uint8_t*>(buf->base),
                                     static_cast<size_t>(nread));
}

void ServerApp::on_udp_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    auto* ctx = static_cast<UdpResolveCtx*>(req->data);
    if (status == 0 && res && ctx && ctx->app && ctx->client && !ctx->client->closed) {
        auto it = ctx->client->udp_outbounds.find(ctx->sid);
        if (it != ctx->client->udp_outbounds.end() &&
            it->second.generation == ctx->generation && it->second.resolving &&
            it->second.resolution_target.host == ctx->target.host &&
            it->second.resolution_target.port == ctx->target.port) {
            it->second.last_activity_ms = uv_now(ctx->app->loop_);
            const struct addrinfo* selected = nullptr;
            for (auto* ai = res; ai; ai = ai->ai_next) {
                if (ai->ai_family == AF_INET) {
                    selected = ai;
                    break;
                }
                if (!selected && ai->ai_family == AF_INET6) {
                    selected = ai;
                }
            }

            sockaddr_storage addr;
            memset(&addr, 0, sizeof(addr));
            if (selected && selected->ai_family == AF_INET) {
                auto* a4 = reinterpret_cast<sockaddr_in*>(&addr);
                memcpy(a4, selected->ai_addr, sizeof(sockaddr_in));
                a4->sin_port = htons(ctx->target.port);
            } else if (selected && selected->ai_family == AF_INET6) {
                auto* a6 = reinterpret_cast<sockaddr_in6*>(&addr);
                memcpy(a6, selected->ai_addr, sizeof(sockaddr_in6));
                a6->sin6_port = htons(ctx->target.port);
            } else {
                it->second.resolving = false;
                it->second.pending_resolution_packets.clear();
                it->second.pending_resolution_bytes = 0;
                if (res) uv_freeaddrinfo(res);
                delete ctx;
                delete req;
                return;
            }

            if (!ctx->app->ensure_udp_outbound_socket(ctx->client, ctx->sid,
                                                       it->second, addr.ss_family)) {
                it->second.resolving = false;
                it->second.pending_resolution_packets.clear();
                it->second.pending_resolution_bytes = 0;
                if (res) uv_freeaddrinfo(res);
                delete ctx;
                delete req;
                return;
            }

            it->second.peer = addr;
            it->second.peer_len = addr.ss_family == AF_INET ? sizeof(sockaddr_in)
                                                             : sizeof(sockaddr_in6);
            it->second.peer_ready = true;
            it->second.resolving = false;
            uv_udp_t* udp = ctx->app->udp_outbound_socket(it->second, addr.ss_family);
            std::deque<std::vector<uint8_t>> pending;
            pending.swap(it->second.pending_resolution_packets);
            it->second.pending_resolution_bytes = 0;
            for (const auto& packet : pending) {
                ctx->app->send_udp_datagram(udp, addr, packet.data(), packet.size());
            }
        }
    } else if (ctx && ctx->client && !ctx->client->closed) {
        auto it = ctx->client->udp_outbounds.find(ctx->sid);
        if (it != ctx->client->udp_outbounds.end() &&
            it->second.generation == ctx->generation && it->second.resolving &&
            it->second.resolution_target.host == ctx->target.host &&
            it->second.resolution_target.port == ctx->target.port) {
            it->second.resolving = false;
            it->second.pending_resolution_packets.clear();
            it->second.pending_resolution_bytes = 0;
            TX_WARN("UDP DNS lookup failed for %s", ctx->target.host.c_str());
        }
    }

    if (res) uv_freeaddrinfo(res);
    delete ctx;
    delete req;
}

void ServerApp::on_udp_send_done(uv_udp_send_t* req, int status) {
    auto* wr = reinterpret_cast<UdpSendReq*>(req);
    delete[] wr->data;
    delete wr;
}

void ServerApp::on_udp_closed(uv_handle_t* handle) {
    delete static_cast<UdpCtx*>(handle->data);
    delete reinterpret_cast<uv_udp_t*>(handle);
}

void ServerApp::on_tunnel_close(TunnelClientPtr client) {
    if (!client || client->closed) return;
    client->closed = true;
    stop_handshake_timer(client);
    if (!client->authenticated) {
        auto pending = unauthenticated_by_ip_.find(client->source_ip);
        if (pending != unauthenticated_by_ip_.end()) {
            if (pending->second > 1) --pending->second;
            else unauthenticated_by_ip_.erase(pending);
        }
    }
    TX_INFO("Tunnel client disconnected");

    // Copy outbounds to avoid iterator invalidation
    // Remote close callbacks may modify client->outbounds
    auto outbounds_copy = std::move(client->outbounds);
    client->outbounds.clear();

    for (auto& kv : outbounds_copy) {
        if (kv.second.remote_session && !kv.second.remote_session->is_closed()) {
            // Clear close callback to prevent it from accessing stale state
            kv.second.remote_session->set_close_callback(nullptr);
            kv.second.remote_session->close();
        }
    }

    auto udp_outbounds_copy = std::move(client->udp_outbounds);
    client->udp_outbounds.clear();
    for (auto& kv : udp_outbounds_copy) {
        close_udp_outbound(kv.second);
    }

    clients_.erase(client->session->handle());
}

} // namespace tx
