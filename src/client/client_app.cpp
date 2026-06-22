#include "client_app.h"
#include "tx/common/log.h"
#include "tx/crypto/key_derive.h"

#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <random>

namespace tx {

namespace {

bool sockaddr_to_ipaddr(const sockaddr* addr, uint16_t port, IpAddr& out) {
    if (!addr) return false;

    if (addr->sa_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        out = IpAddr::from_ipv4(
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[0],
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[1],
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[2],
            reinterpret_cast<const uint8_t*>(&a4->sin_addr)[3],
            port);
        return true;
    }

    if (addr->sa_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        out = IpAddr::from_ipv6(reinterpret_cast<const uint8_t*>(&a6->sin6_addr), port);
        return true;
    }

    return false;
}

} // namespace

struct ClientApp::RouteDnsCtx {
    ClientApp* app;
    ProxyConnPtr conn;
};

ClientApp::ClientApp()
    : loop_(uv_default_loop()),
      http_server_(loop_),
      socks5_server_(loop_),
      tunnel_codec_(nullptr),
      tunnel_connected_(false),
      tunnel_connecting_(false),
      next_session_id_(1) {}

ClientApp::~ClientApp() {
    stop();
}

bool ClientApp::init(const ClientConfig& config) {
    config_ = config;

    // Initialize crypto — deterministic key from password (must match server)
    tunnel_master_key_ = KeyDeriver::derive_deterministic(config.password);
    auto aes = std::make_shared<AesGcm>(tunnel_master_key_.data(), tunnel_master_key_.size());
    tunnel_codec_ = TunnelCodec(aes);

    // Load router
    if (!router_.load(config.router)) {
        TX_WARN("Router load failed, all traffic will be proxied");
    }

    // Start HTTP proxy listener
    http_server_.set_accept_callback([this](SessionPtr s) { on_http_accept(s); });
    if (!http_server_.listen(config.http_host, config.http_port)) {
        TX_ERROR("Failed to start HTTP proxy on %s:%u",
                 config.http_host.c_str(), config.http_port);
        return false;
    }

    // Start SOCKS5 proxy listener
    socks5_server_.set_accept_callback([this](SessionPtr s) { on_socks5_accept(s); });
    if (!socks5_server_.listen(config.socks5_host, config.socks5_port)) {
        TX_ERROR("Failed to start SOCKS5 proxy on %s:%u",
                 config.socks5_host.c_str(), config.socks5_port);
        return false;
    }

    TX_INFO("TX Client started");
    TX_INFO("  HTTP   proxy: %s:%u", config.http_host.c_str(), config.http_port);
    TX_INFO("  SOCKS5 proxy: %s:%u", config.socks5_host.c_str(), config.socks5_port);
    TX_INFO("  Server:       %s:%u", config.server_host.c_str(), config.server_port);
    return true;
}

int ClientApp::run() {
    return uv_run(loop_, UV_RUN_DEFAULT);
}

void ClientApp::stop() {
    http_server_.stop();
    socks5_server_.stop();
    if (tunnel_session_) tunnel_session_->close();
    uv_stop(loop_);
}

void ClientApp::on_http_accept(SessionPtr session) {
    auto conn = std::make_shared<ProxyConn>();
    conn->local_session = session;
    conn->socks5 = nullptr;
    conn->http = std::make_unique<HttpProxyHandler>();
    conn->route = RouteAction::Proxy;
    conn->connected = false;
    conn->connect_result_sent = false;
    conn->target_dispatched = false;
    conn->session_id = next_session_id_++;

    conn->http->set_target_callback([this, conn](const TargetAddr& target) {
        conn->target = target;
    });

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        // Accumulate into persistent buffer
        conn->proto_buf.append(data);
        data.clear();

        if (conn->http->state() == HttpProxyHandler::State::Connected && conn->connected) {
            // Fully connected — forward all buffered data
            if (!conn->proto_buf.empty()) {
                if (conn->route == RouteAction::Direct && conn->direct_session) {
                    conn->direct_session->send(conn->proto_buf);
                } else {
                    tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
                    conn->proto_buf.clear();
                }
            }
        } else if (conn->http->state() == HttpProxyHandler::State::Connected) {
            // CONNECT parsed but tunnel not ready yet — buffer data
            // proto_buf already accumulated, will be sent in connect_via_tunnel/connect_direct
        } else {
            // Parse HTTP CONNECT headers
            size_t consumed = conn->http->feed(conn->proto_buf.data(), conn->proto_buf.readable());
            conn->proto_buf.consume(consumed);
            if (conn->http->state() == HttpProxyHandler::State::Connected &&
                conn->http->mode() == HttpProxyHandler::Mode::Plain) {
                conn->proto_buf.clear();
                conn->proto_buf.append(conn->http->initial_payload());
            }
            if (conn->http->state() == HttpProxyHandler::State::Error) {
                Buffer resp;
                conn->http->build_error_response(400, resp);
                conn->local_session->send(resp);
                conn->local_session->close();
                return;
            }
            if (conn->http->state() == HttpProxyHandler::State::Connected &&
                !conn->target_dispatched) {
                conn->target_dispatched = true;
                on_target_resolved(conn);
            }
        }
    });
}

void ClientApp::on_socks5_accept(SessionPtr session) {
    auto conn = std::make_shared<ProxyConn>();
    conn->local_session = session;
    conn->socks5 = std::make_unique<Socks5Handler>();
    conn->http = nullptr;
    conn->route = RouteAction::Proxy;
    conn->connected = false;
    conn->connect_result_sent = false;
    conn->target_dispatched = false;
    conn->session_id = next_session_id_++;

    conn->socks5->set_target_callback([this, conn](const TargetAddr& target) {
        conn->target = target;
    });

    session->set_close_callback([this, conn](SessionPtr) {
        on_proxy_close(conn);
    });

    session->start_read([this, conn](SessionPtr, Buffer& data) {
        // Accumulate into persistent buffer
        conn->proto_buf.append(data);
        data.clear();

        if (conn->socks5->state() == Socks5State::Connected && conn->connected) {
            // Fully connected — forward all buffered data
            if (!conn->proto_buf.empty()) {
                if (conn->route == RouteAction::Direct && conn->direct_session) {
                    conn->direct_session->send(conn->proto_buf);
                } else {
                    tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
                    conn->proto_buf.clear();
                }
            }
        } else if (conn->socks5->state() == Socks5State::Connected) {
            // CONNECT parsed but tunnel not ready yet — buffer data
        } else {
            // Loop to process handshake + CONNECT in one TCP segment
            while (!conn->proto_buf.empty()) {
                size_t consumed = conn->socks5->feed(conn->proto_buf.data(),
                                                      conn->proto_buf.readable());
                if (consumed == 0) break; // need more data
                conn->proto_buf.consume(consumed);

                if (conn->socks5->state() == Socks5State::Error) {
                    Buffer resp;
                    conn->socks5->build_connect_response(false, resp);
                    conn->local_session->send(resp);
                    conn->local_session->close();
                    return;
                }

                // After handshake → send NO AUTH response
                if (conn->socks5->state() == Socks5State::Request) {
                    Buffer resp;
                    uint8_t auth_resp[] = {0x05, 0x00};
                    resp.append(auth_resp, 2);
                    conn->local_session->send(resp);
                }

                if (conn->socks5->state() == Socks5State::Connected &&
                    !conn->target_dispatched) {
                    conn->target_dispatched = true;
                    on_target_resolved(conn);
                }
            }
        }
    });
}

void ClientApp::on_target_resolved(ProxyConnPtr conn) {
    TX_INFO("Target resolved: %s:%u", conn->target.host.c_str(), conn->target.port);

    // Route decision
    resolve_and_route(conn);
}

void ClientApp::resolve_and_route(ProxyConnPtr conn) {
    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    RouteAction action = router_.decide_by_host(conn->target.host);

    if (action == RouteAction::Direct) {
        conn->route = RouteAction::Direct;
        TX_INFO("[Direct] %s:%u (geosite)",
                conn->target.host.c_str(), conn->target.port);
        connect_direct(conn);
        return;
    }

    if (conn->target.type == AddrType::Domain) {
        resolve_domain_and_route(conn);
        return;
    }

    IpAddr ip = IpAddr::from_string(conn->target.host, conn->target.port);
    conn->route = router_.decide_by_ip(ip);

    if (conn->route == RouteAction::Direct) {
        TX_INFO("[Direct] %s:%u (geoip)",
                conn->target.host.c_str(), conn->target.port);
        connect_direct(conn);
    } else {
        TX_INFO("[Proxy] %s:%u (geoip/default)",
                conn->target.host.c_str(), conn->target.port);
        connect_via_tunnel(conn);
    }
}

void ClientApp::resolve_domain_and_route(ProxyConnPtr conn) {
    auto* req = new uv_getaddrinfo_t;
    auto* ctx = new RouteDnsCtx{this, conn};
    req->data = ctx;

    int r = uv_getaddrinfo(loop_, req, ClientApp::on_route_dns_resolved,
                           conn->target.host.c_str(), nullptr, nullptr);
    if (r != 0) {
        TX_WARN("[Proxy] %s:%u DNS route lookup failed: %s",
                conn->target.host.c_str(), conn->target.port, uv_strerror(r));
        conn->route = RouteAction::Proxy;
        connect_via_tunnel(conn);
        delete ctx;
        delete req;
    }
}

void ClientApp::on_route_dns_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    auto* ctx = static_cast<RouteDnsCtx*>(req->data);
    auto conn = ctx->conn;
    ClientApp* app = ctx->app;

    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        if (res) uv_freeaddrinfo(res);
        delete ctx;
        delete req;
        return;
    }

    IpAddr selected;
    bool have_ip = false;

    if (status == 0 && res) {
        for (auto* ai = res; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                have_ip = sockaddr_to_ipaddr(ai->ai_addr, conn->target.port, selected);
                break;
            }
            if (!have_ip && ai->ai_family == AF_INET6) {
                have_ip = sockaddr_to_ipaddr(ai->ai_addr, conn->target.port, selected);
            }
        }
    }

    if (have_ip && app->router_.decide_by_ip(selected) == RouteAction::Direct) {
        conn->route = RouteAction::Direct;
        TX_INFO("[Direct] %s:%u resolved to %s (geoip)",
                conn->target.host.c_str(), conn->target.port,
                selected.to_string().c_str());
        app->connect_direct(conn);
    } else {
        conn->route = RouteAction::Proxy;
        if (status < 0 || !res) {
            TX_WARN("[Proxy] %s:%u DNS route lookup failed: %s",
                    conn->target.host.c_str(), conn->target.port,
                    status < 0 ? uv_strerror(status) : "no results");
        } else {
            TX_INFO("[Proxy] %s:%u (geoip/default)",
                    conn->target.host.c_str(), conn->target.port);
        }
        app->connect_via_tunnel(conn);
    }

    if (res) uv_freeaddrinfo(res);
    delete ctx;
    delete req;
}

void ClientApp::connect_direct(ProxyConnPtr conn) {
    TX_INFO("[Direct] Connecting to %s:%u", conn->target.host.c_str(), conn->target.port);

    auto direct = std::make_shared<TcpSession>(loop_);
    conn->direct_session = direct;

    direct->set_close_callback([this, conn](SessionPtr) {
        if (conn->local_session && !conn->local_session->is_closed()) {
            conn->local_session->close();
        }
    });

    direct->connect(conn->target.host, conn->target.port,
        [this, conn, direct](bool success) {
            if (!success) {
                TX_ERROR("Direct connect failed to %s:%u",
                         conn->target.host.c_str(), conn->target.port);
                if (conn->socks5) {
                    Buffer resp;
                    conn->socks5->build_connect_response(false, resp);
                    conn->local_session->send(resp);
                } else if (conn->http) {
                    Buffer resp;
                    conn->http->build_error_response(502, resp);
                    conn->local_session->send(resp);
                }
                return;
            }

            conn->connected = true;

            // Send success response to local client
            if (conn->socks5) {
                Buffer resp;
                conn->socks5->build_connect_response(true, resp);
                conn->local_session->send(resp);
            } else if (conn->http &&
                       conn->http->mode() == HttpProxyHandler::Mode::Connect) {
                Buffer resp;
                conn->http->build_connect_response(resp);
                conn->local_session->send(resp);
            }

            // Flush any data buffered while waiting for connection
            if (!conn->proto_buf.empty()) {
                direct->send(conn->proto_buf);
                conn->proto_buf.clear();
            }

            // Start reading from direct connection
            direct->start_read([this, conn](SessionPtr, Buffer& data) {
                if (conn->local_session && !conn->local_session->is_closed()) {
                    conn->local_session->send(data);
                }
            });
        });
}

void ClientApp::connect_via_tunnel(ProxyConnPtr conn) {
    TX_INFO("[Proxy] Connecting via tunnel to %s:%u",
            conn->target.host.c_str(), conn->target.port);

    connections_[conn->session_id] = conn;

    if (tunnel_connected_) {
        activate_tunnel_connection(conn);
        return;
    }

    pending_tunnel_conns_.push_back(conn);

    if (!ensure_tunnel()) {
        TX_ERROR("Failed to establish tunnel");
        fail_pending_tunnel_connections();
    }
}

bool ClientApp::ensure_tunnel() {
    if (tunnel_session_ && tunnel_connected_) return true;
    if (tunnel_session_ && tunnel_connecting_) return true;

    tunnel_session_ = std::make_shared<TcpSession>(loop_);
    tunnel_connected_ = false;
    tunnel_connecting_ = true;
    tunnel_recv_buf_.clear();

    tunnel_session_->set_close_callback([this](SessionPtr session) {
        TX_WARN("Tunnel disconnected");
        if (tunnel_session_ == session) {
            tunnel_connected_ = false;
            tunnel_connecting_ = false;
            tunnel_session_.reset();
            fail_all_tunnel_connections();
        }
    });

    tunnel_session_->connect(config_.server_host, config_.server_port,
        [this](bool success) {
            if (success) {
                tunnel_handshake_buf_.clear();
                tunnel_client_nonce_.clear();
                TX_INFO("Tunnel connected to %s:%u",
                        config_.server_host.c_str(), config_.server_port);

                tunnel_session_->start_read([this](SessionPtr, Buffer& data) {
                    on_tunnel_handshake_read(data);
                });

                Buffer hello;
                if (!TunnelCodec::build_client_hello(tunnel_master_key_, hello,
                                                      tunnel_client_nonce_)) {
                    TX_ERROR("Failed to build tunnel handshake");
                    fail_pending_tunnel_connections();
                    if (tunnel_session_ && !tunnel_session_->is_closed()) {
                        tunnel_session_->close();
                    }
                    return;
                }
                tunnel_session_->send(hello);
            } else {
                tunnel_connecting_ = false;
                tunnel_connected_ = false;
                TX_ERROR("Tunnel connect failed to %s:%u",
                         config_.server_host.c_str(), config_.server_port);
                fail_pending_tunnel_connections();
                if (tunnel_session_ && !tunnel_session_->is_closed()) {
                    tunnel_session_->close();
                }
            }
        });

    return true;
}

void ClientApp::on_tunnel_handshake_read(Buffer& data) {
    tunnel_handshake_buf_.append(data);
    data.clear();

    if (tunnel_handshake_buf_.readable() < TunnelCodec::kHandshakeSize) {
        return;
    }

    std::vector<uint8_t> server_nonce;
    if (!TunnelCodec::parse_server_hello(tunnel_master_key_, tunnel_client_nonce_,
                                          tunnel_handshake_buf_.data(),
                                          TunnelCodec::kHandshakeSize,
                                          server_nonce)) {
        TX_ERROR("Tunnel handshake failed");
        fail_pending_tunnel_connections();
        if (tunnel_session_ && !tunnel_session_->is_closed()) {
            tunnel_session_->close();
        }
        return;
    }

    tunnel_handshake_buf_.consume(TunnelCodec::kHandshakeSize);
    finish_tunnel_handshake(server_nonce);

    if (!tunnel_handshake_buf_.empty()) {
        tunnel_recv_buf_.append(tunnel_handshake_buf_);
        tunnel_handshake_buf_.clear();
        on_tunnel_read(tunnel_recv_buf_);
    }
}

void ClientApp::finish_tunnel_handshake(const std::vector<uint8_t>& server_nonce) {
    auto session_key = TunnelCodec::derive_session_key(tunnel_master_key_,
                                                       tunnel_client_nonce_,
                                                       server_nonce);
    auto aes = std::make_shared<AesGcm>(session_key.data(), session_key.size());
    tunnel_codec_ = TunnelCodec(aes);
    tunnel_client_nonce_.clear();

    tunnel_connecting_ = false;
    tunnel_connected_ = true;
    TX_INFO("Tunnel handshake complete");

    tunnel_session_->start_read([this](SessionPtr, Buffer& data) {
        tunnel_recv_buf_.append(data);
        data.clear();
        on_tunnel_read(tunnel_recv_buf_);
    });

    auto pending = pending_tunnel_conns_;
    pending_tunnel_conns_.clear();
    for (auto& conn : pending) {
        activate_tunnel_connection(conn);
    }

    if (!tunnel_send_buf_.empty()) {
        tunnel_session_->send(tunnel_send_buf_);
    }
}

void ClientApp::activate_tunnel_connection(ProxyConnPtr conn) {
    if (!conn || conn->connected ||
        !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    if (connections_.find(conn->session_id) == connections_.end()) {
        return;
    }

    tunnel_send_connect(conn);
    conn->connected = true;
}

void ClientApp::complete_tunnel_connection(ProxyConnPtr conn) {
    if (!conn || conn->connect_result_sent ||
        !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    conn->connect_result_sent = true;
    TX_INFO("[Proxy] CONNECT established for session %u: %s:%u",
            conn->session_id, conn->target.host.c_str(), conn->target.port);

    if (conn->socks5) {
        Buffer resp;
        conn->socks5->build_connect_response(true, resp);
        conn->local_session->send(resp);
    } else if (conn->http &&
               conn->http->mode() == HttpProxyHandler::Mode::Connect) {
        Buffer resp;
        conn->http->build_connect_response(resp);
        conn->local_session->send(resp);
    }

    if (!conn->pending_data.empty()) {
        tunnel_send(conn, conn->pending_data.data(), conn->pending_data.readable());
        conn->pending_data.clear();
    }

    if (!conn->proto_buf.empty()) {
        tunnel_send(conn, conn->proto_buf.data(), conn->proto_buf.readable());
        conn->proto_buf.clear();
    }
}

void ClientApp::fail_tunnel_connection(ProxyConnPtr conn) {
    if (!conn) return;

    connections_.erase(conn->session_id);

    if (!conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    if (!conn->connect_result_sent) {
        if (conn->socks5) {
            Buffer resp;
            conn->socks5->build_connect_response(false, resp);
            conn->local_session->send(resp);
        } else if (conn->http) {
            Buffer resp;
            conn->http->build_error_response(502, resp);
            conn->local_session->send(resp);
        }
        return;
    }

    conn->local_session->close();
}

void ClientApp::fail_pending_tunnel_connections() {
    auto pending = pending_tunnel_conns_;
    pending_tunnel_conns_.clear();
    tunnel_send_buf_.clear();

    for (auto& conn : pending) {
        if (!conn || conn->connected) continue;
        fail_tunnel_connection(conn);
    }
}

void ClientApp::fail_all_tunnel_connections() {
    fail_pending_tunnel_connections();

    auto active = std::move(connections_);
    connections_.clear();

    for (auto& kv : active) {
        fail_tunnel_connection(kv.second);
    }
}

void ClientApp::tunnel_send_connect(ProxyConnPtr conn) {
    Buffer encoded;
    if (tunnel_codec_.encode(TunnelCmd::Connect, conn->session_id,
                              conn->target, nullptr, 0, encoded)) {
        if (tunnel_connected_ && tunnel_session_) {
            tunnel_session_->send(encoded);
        } else {
            tunnel_send_buf_.append(encoded);
        }
    }
}

void ClientApp::tunnel_send(ProxyConnPtr conn, const uint8_t* data, size_t len) {
    Buffer encoded;
    if (!tunnel_codec_.encode_data_chunks(conn->session_id, data, len, encoded)) {
        return;
    }

    if (tunnel_connected_ && tunnel_session_) {
        tunnel_session_->send(encoded);
    } else {
        tunnel_send_buf_.append(encoded);
    }
}

void ClientApp::tunnel_send_disconnect(ProxyConnPtr conn) {
    Buffer encoded;
    if (tunnel_codec_.encode_disconnect(conn->session_id, encoded)) {
        if (tunnel_connected_ && tunnel_session_) {
            tunnel_session_->send(encoded);
        }
    }
}

void ClientApp::on_tunnel_read(Buffer& data) {
    TunnelCmd cmd;
    SessionId session_id;
    TargetAddr target;
    Buffer payload;

    while (tunnel_codec_.decode(data, cmd, session_id, target, payload)) {
        auto it = connections_.find(session_id);
        if (it == connections_.end()) {
            TX_DEBUG("Tunnel data for unknown session %u", session_id);
            continue;
        }

        auto& conn = it->second;

        switch (cmd) {
            case TunnelCmd::Data:
                if (!payload.empty() && conn->local_session &&
                    !conn->local_session->is_closed()) {
                    conn->local_session->send(payload);
                }
                break;

            case TunnelCmd::ConnectResult:
                TX_INFO("[Proxy] CONNECT_RESULT session %u: %s",
                        session_id,
                        (!payload.empty() && payload.data()[0] == 1) ? "success" : "failure");
                if (!payload.empty() && payload.data()[0] == 1) {
                    complete_tunnel_connection(conn);
                } else {
                    TX_DEBUG("Tunnel connect failed for session %u", session_id);
                    fail_tunnel_connection(conn);
                }
                break;

            case TunnelCmd::Disconnect:
                TX_DEBUG("Tunnel disconnect for session %u", session_id);
                fail_tunnel_connection(conn);
                break;

            default:
                break;
        }
    }

    if (tunnel_codec_.has_protocol_error()) {
        TX_ERROR("Closing tunnel because remote data is not valid TX tunnel protocol");
        tunnel_codec_.clear_protocol_error();
        fail_pending_tunnel_connections();
        auto connections = std::move(connections_);
        connections_.clear();
        for (auto& kv : connections) {
            fail_tunnel_connection(kv.second);
        }
        if (tunnel_session_ && !tunnel_session_->is_closed()) {
            tunnel_session_->close();
        }
    }
}

void ClientApp::on_proxy_close(ProxyConnPtr conn) {
    TX_DEBUG("Proxy connection closed, session %u", conn->session_id);

    if (conn->direct_session && !conn->direct_session->is_closed()) {
        conn->direct_session->close();
    }

    if (conn->route == RouteAction::Proxy) {
        tunnel_send_disconnect(conn);
        connections_.erase(conn->session_id);
    }
}

} // namespace tx
