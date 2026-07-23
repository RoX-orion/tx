#include "server_app.h"
#include "tx/common/log.h"
#include "tx/net/udp_flow_timeout.h"

#include "tx/common/network.h"
#include <cstring>
#include <cstdlib>

namespace tx {

namespace {

constexpr size_t kTunnelPauseWriteBacklog = 4 * 1024 * 1024;
constexpr size_t kTunnelResumeWriteBacklog = 1024 * 1024;
constexpr size_t kMaxTunnelWriteBacklog = 16 * 1024 * 1024;
constexpr size_t kMaxPendingTargetData = 4 * 1024 * 1024;

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

} // namespace

ServerApp::ServerApp()
    : loop_(uv_default_loop()),
      server_(loop_),
      udp_cleanup_timer_started_(false) {}

ServerApp::~ServerApp() {
    stop();
}

bool ServerApp::init(const ServerConfig& config) {
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
    return true;
}

int ServerApp::run() {
    return uv_run(loop_, UV_RUN_DEFAULT);
}

void ServerApp::stop() {
    stop_udp_cleanup_timer();
    server_.stop();
    for (auto& kv : clients_) {
        if (kv.second->session && !kv.second->session->is_closed()) {
            kv.second->session->close();
        }
    }
    clients_.clear();
    uv_stop(loop_);
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
            if (it->second.udp &&
                !uv_is_closing(reinterpret_cast<uv_handle_t*>(it->second.udp))) {
                uv_close(reinterpret_cast<uv_handle_t*>(it->second.udp),
                         ServerApp::on_udp_closed);
            }
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

    auto client = std::make_shared<TunnelClient>();
    client->session = session;

    clients_[session->handle()] = client;

    session->set_close_callback([this, client](SessionPtr) {
        on_tunnel_close(client);
    });
    session->set_write_drain_callback([this, client](SessionPtr) {
        resume_outbound_reads(client);
    });

    session->start_read([this, client](SessionPtr, Buffer& data) {
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

    client->session->send(hello);
    client->handshake_buf.consume(TunnelCodec::kHandshakeSize);
    TX_INFO("Tunnel handshake complete for %s:%u",
            client->session->remote_addr().c_str(), client->session->remote_port());

    client->session->start_read([this, client](SessionPtr, Buffer& more) {
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
    TX_INFO("CONNECT session %u → %s:%u", sid, target.host.c_str(), target.port);

    auto remote = std::make_shared<TcpSession>(loop_);
    TunnelClient::Outbound ob;
    ob.remote_session = remote;
    ob.session_id = sid;
    ob.connected = false;
    client->outbounds[sid] = ob;

    // Use weak_ptr to avoid capturing remote in its own close callback
    std::weak_ptr<TcpSession> weak_remote = remote;

    remote->set_close_callback([this, client, sid, weak_remote](SessionPtr) {
        TX_DEBUG("Remote closed for session %u", sid);
        // Only act if the outbound still exists and matches
        auto it = client->outbounds.find(sid);
        if (it != client->outbounds.end() &&
            it->second.remote_session.get() == weak_remote.lock().get()) {
            tunnel_send_disconnect(client, sid);
            client->outbounds.erase(it);
        }
    });
    remote->set_eof_callback([this, client, sid](SessionPtr) {
        auto it = client->outbounds.find(sid);
        if (it == client->outbounds.end()) return;
        it->second.remote_eof = true;
        tunnel_send_half_close(client, sid);
    });
    remote->set_write_drain_callback([client](SessionPtr remote_session) {
        if (client->inbound_paused && client->session &&
            !client->session->is_closed() &&
            remote_session->pending_write_bytes() <= kTunnelResumeWriteBacklog) {
            client->inbound_paused = false;
            client->session->resume_read();
        }
    });

    remote->connect(target.host, target.port,
        [this, client, sid, remote, target](bool success) {
            if (!success) {
                TX_ERROR("Failed to connect to target for session %u: %s:%u",
                         sid, target.host.c_str(), target.port);
                tunnel_send_connect_result(client, sid, false);
                client->outbounds.erase(sid);
                return;
            }

            TX_INFO("Connected to target for session %u: %s:%u",
                    sid, target.host.c_str(), target.port);

            auto it = client->outbounds.find(sid);
            if (it == client->outbounds.end()) {
                TX_WARN("Outbound disappeared before target connected for session %u", sid);
                if (remote && !remote->is_closed()) {
                    remote->close();
                }
                return;
            }

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
                remote->start_read([this, client, sid](SessionPtr, Buffer& data) {
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

    auto it = client->udp_outbounds.find(sid);
    if (it == client->udp_outbounds.end()) {
        auto* udp = new uv_udp_t;
        if (uv_udp_init(loop_, udp) != 0) {
            delete udp;
            payload.clear();
            return;
        }
        const uint64_t generation = client->next_udp_generation++;
        auto* ctx = new UdpCtx{this, client, sid, generation};
        udp->data = ctx;

        sockaddr_in bind_addr;
        uv_ip4_addr("0.0.0.0", 0, &bind_addr);
        if (uv_udp_bind(udp, reinterpret_cast<const sockaddr*>(&bind_addr), 0) != 0 ||
            uv_udp_recv_start(udp, ServerApp::udp_alloc, ServerApp::on_udp_read) != 0) {
            uv_close(reinterpret_cast<uv_handle_t*>(udp), ServerApp::on_udp_closed);
            payload.clear();
            return;
        }

        TunnelClient::UdpOutbound out;
        out.udp = udp;
        out.session_id = sid;
        out.generation = generation;
        out.last_activity_ms = uv_now(loop_);
        it = client->udp_outbounds.emplace(sid, out).first;
    }
    it->second.last_activity_ms = uv_now(loop_);

    sockaddr_storage addr;
    if (target_to_sockaddr(target, addr)) {
        auto* wr = new UdpSendReq;
        wr->data = new char[payload.readable()];
        memcpy(wr->data, payload.data(), payload.readable());
        wr->buf = uv_buf_init(wr->data, static_cast<unsigned int>(payload.readable()));
        int r = uv_udp_send(&wr->req, it->second.udp, &wr->buf, 1,
                            reinterpret_cast<const sockaddr*>(&addr),
                            ServerApp::on_udp_send_done);
        if (r != 0) {
            delete[] wr->data;
            delete wr;
        }
    } else if (target.type == AddrType::Domain) {
        auto* resolve_ctx = new UdpResolveCtx;
        resolve_ctx->app = this;
        resolve_ctx->client = client;
        resolve_ctx->sid = sid;
        resolve_ctx->generation = it->second.generation;
        resolve_ctx->target = target;
        resolve_ctx->payload.assign(payload.data(), payload.data() + payload.readable());
        auto* req = new uv_getaddrinfo_t;
        req->data = resolve_ctx;
        int r = uv_getaddrinfo(loop_, req, ServerApp::on_udp_resolved,
                               target.host.c_str(), nullptr, nullptr);
        if (r != 0) {
            delete resolve_ctx;
            delete req;
        }
    }

    payload.clear();
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
        if (udp_it->second.udp &&
            !uv_is_closing(reinterpret_cast<uv_handle_t*>(udp_it->second.udp))) {
            uv_close(reinterpret_cast<uv_handle_t*>(udp_it->second.udp),
                     ServerApp::on_udp_closed);
        }
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

        outbound.remote_session->start_read([this, client, sid](SessionPtr, Buffer& data) {
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
    if (!ctx || !ctx->app) return;

    auto it = ctx->client->udp_outbounds.find(ctx->sid);
    if (it == ctx->client->udp_outbounds.end() ||
        it->second.generation != ctx->generation) {
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
    if (status == 0 && res && ctx && ctx->client) {
        auto it = ctx->client->udp_outbounds.find(ctx->sid);
        if (it != ctx->client->udp_outbounds.end() &&
            it->second.generation == ctx->generation) {
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
                if (res) uv_freeaddrinfo(res);
                delete ctx;
                delete req;
                return;
            }

            auto* wr = new UdpSendReq;
            wr->data = new char[ctx->payload.size()];
            memcpy(wr->data, ctx->payload.data(), ctx->payload.size());
            wr->buf = uv_buf_init(wr->data, static_cast<unsigned int>(ctx->payload.size()));
            int r = uv_udp_send(&wr->req, it->second.udp, &wr->buf, 1,
                                reinterpret_cast<const sockaddr*>(&addr),
                                ServerApp::on_udp_send_done);
            if (r != 0) {
                delete[] wr->data;
                delete wr;
            }
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
        if (kv.second.udp &&
            !uv_is_closing(reinterpret_cast<uv_handle_t*>(kv.second.udp))) {
            uv_close(reinterpret_cast<uv_handle_t*>(kv.second.udp),
                     ServerApp::on_udp_closed);
        }
    }

    clients_.erase(client->session->handle());
}

} // namespace tx
