#include "client_app.h"
#include "tx/common/log.h"
#include "tx/crypto/key_derive.h"

#include <cstring>
#include <random>

namespace tx {

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
    auto key = KeyDeriver::derive_deterministic(config.password);
    auto aes = std::make_shared<AesGcm>(key.data(), key.size());
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
        // GeoSite matched → direct
        conn->route = RouteAction::Direct;
        connect_direct(conn);
        return;
    }

    // Avoid local DNS for domain names. For proxied domains the server should
    // resolve the target from its network; local DNS can fail or be polluted.
    if (conn->target.type == AddrType::Domain) {
        conn->route = RouteAction::Proxy;
        connect_via_tunnel(conn);
        return;
    }

    IpAddr ip = IpAddr::from_string(conn->target.host, conn->target.port);
    conn->route = router_.decide_by_ip(ip);

    if (conn->route == RouteAction::Direct) {
        connect_direct(conn);
    } else {
        connect_via_tunnel(conn);
    }
}

void ClientApp::connect_direct(ProxyConnPtr conn) {
    TX_INFO("Direct connect: %s:%u", conn->target.host.c_str(), conn->target.port);

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
            } else if (conn->http) {
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
    TX_INFO("Proxy via tunnel: %s:%u", conn->target.host.c_str(), conn->target.port);

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

    tunnel_session_->set_close_callback([this](SessionPtr session) {
        TX_WARN("Tunnel disconnected");
        if (tunnel_session_ == session) {
            tunnel_connected_ = false;
            tunnel_connecting_ = false;
            tunnel_session_.reset();
        }
    });

    tunnel_session_->connect(config_.server_host, config_.server_port,
        [this](bool success) {
            if (success) {
                tunnel_connecting_ = false;
                tunnel_connected_ = true;
                TX_INFO("Tunnel connected to %s:%u",
                        config_.server_host.c_str(), config_.server_port);

                tunnel_session_->start_read([this](SessionPtr, Buffer& data) {
                    on_tunnel_read(data);
                });

                auto pending = pending_tunnel_conns_;
                pending_tunnel_conns_.clear();
                for (auto& conn : pending) {
                    activate_tunnel_connection(conn);
                }

                // Flush any buffered data
                if (!tunnel_send_buf_.empty()) {
                    tunnel_session_->send(tunnel_send_buf_);
                }
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

    if (conn->socks5) {
        Buffer resp;
        conn->socks5->build_connect_response(true, resp);
        conn->local_session->send(resp);
    } else if (conn->http) {
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

void ClientApp::fail_pending_tunnel_connections() {
    auto pending = pending_tunnel_conns_;
    pending_tunnel_conns_.clear();
    tunnel_send_buf_.clear();

    for (auto& conn : pending) {
        if (!conn || conn->connected) continue;

        connections_.erase(conn->session_id);
        if (!conn->local_session || conn->local_session->is_closed()) continue;

        if (conn->socks5) {
            Buffer resp;
            conn->socks5->build_connect_response(false, resp);
            conn->local_session->send(resp);
        } else if (conn->http) {
            Buffer resp;
            conn->http->build_error_response(502, resp);
            conn->local_session->send(resp);
        }
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
    if (tunnel_codec_.encode_data(conn->session_id, data, len, encoded)) {
        if (tunnel_connected_ && tunnel_session_) {
            tunnel_session_->send(encoded);
        } else {
            tunnel_send_buf_.append(encoded);
        }
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

            case TunnelCmd::Disconnect:
                TX_DEBUG("Tunnel disconnect for session %u", session_id);
                if (conn->local_session && !conn->local_session->is_closed()) {
                    conn->local_session->close();
                }
                connections_.erase(it);
                break;

            default:
                break;
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
