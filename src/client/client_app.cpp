#include "client_app.h"
#include "tx/common/log.h"

#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <random>

namespace tx {

namespace {

constexpr uint64_t kTunnelHandshakeTimeoutMs = 8000;
constexpr uint64_t kTunnelConnectResultTimeoutMs = 15000;

bool is_ip_literal(const std::string& host) {
    struct in_addr v4;
    struct in6_addr v6;
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

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

struct ClientApp::TunnelTimerCtx {
    ClientApp* app;
    ProxyConnPtr conn;
    std::string phase;
};

ClientApp::ClientApp()
    : loop_(uv_default_loop()),
      http_server_(loop_),
      socks5_server_(loop_),
      next_session_id_(1) {}

ClientApp::~ClientApp() {
    stop();
}

bool ClientApp::init(const ClientConfig& config) {
    config_ = config;

    tunnel_psk_ = config.psk;

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
    for (auto& kv : connections_) {
        auto& conn = kv.second;
        close_tunnel_session(conn);
        if (conn->direct_session && !conn->direct_session->is_closed()) {
            conn->direct_session->set_close_callback(nullptr);
            conn->direct_session->close();
        }
        if (conn->local_session && !conn->local_session->is_closed()) {
            conn->local_session->set_close_callback(nullptr);
            conn->local_session->close();
        }
    }
    connections_.clear();
    uv_stop(loop_);
}

ClientTrafficStats ClientApp::traffic_stats() const {
    ClientTrafficStats stats;
    stats.direct_upload_bytes = direct_upload_bytes_.load(std::memory_order_relaxed);
    stats.direct_download_bytes = direct_download_bytes_.load(std::memory_order_relaxed);
    stats.proxy_upload_bytes = proxy_upload_bytes_.load(std::memory_order_relaxed);
    stats.proxy_download_bytes = proxy_download_bytes_.load(std::memory_order_relaxed);
    return stats;
}

void ClientApp::record_traffic(RouteAction route, bool upload, size_t bytes) {
    if (bytes == 0) return;
    if (route == RouteAction::Direct) {
        if (upload) {
            direct_upload_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        } else {
            direct_download_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        }
    } else {
        if (upload) {
            proxy_upload_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        } else {
            proxy_download_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        }
    }
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
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    conn->tunnel_timer = nullptr;
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
                    size_t bytes = conn->proto_buf.readable();
                    conn->direct_session->send(conn->proto_buf);
                    record_traffic(RouteAction::Direct, true, bytes);
                    conn->proto_buf.clear();
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
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    conn->tunnel_timer = nullptr;
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
                    size_t bytes = conn->proto_buf.readable();
                    conn->direct_session->send(conn->proto_buf);
                    record_traffic(RouteAction::Direct, true, bytes);
                    conn->proto_buf.clear();
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
    if (conn->target.type == AddrType::Domain && ip.is_lan() && !is_ip_literal(conn->target.host)) {
        TX_WARN("[Proxy] %s:%u resolved to private/local address %s, forcing proxy",
                conn->target.host.c_str(), conn->target.port, ip.to_string().c_str());
        conn->route = RouteAction::Proxy;
        connect_via_tunnel(conn);
        return;
    }

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

    bool private_domain_result = have_ip && selected.is_lan() && conn->target.type == AddrType::Domain;

    if (private_domain_result) {
        conn->route = RouteAction::Proxy;
        TX_WARN("[Proxy] %s:%u resolved to private/local address %s, forcing proxy",
                conn->target.host.c_str(), conn->target.port,
                selected.to_string().c_str());
        app->connect_via_tunnel(conn);
    } else if (have_ip && app->router_.decide_by_ip(selected) == RouteAction::Direct) {
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
                size_t bytes = conn->proto_buf.readable();
                direct->send(conn->proto_buf);
                record_traffic(RouteAction::Direct, true, bytes);
                conn->proto_buf.clear();
            }

            // Start reading from direct connection
            direct->start_read([this, conn](SessionPtr, Buffer& data) {
                if (conn->local_session && !conn->local_session->is_closed()) {
                    record_traffic(RouteAction::Direct, false, data.readable());
                    conn->local_session->send(data);
                }
            });
        });
}

void ClientApp::connect_via_tunnel(ProxyConnPtr conn) {
    TX_INFO("[Proxy] Connecting via tunnel to %s:%u",
            conn->target.host.c_str(), conn->target.port);

    connections_[conn->session_id] = conn;

    if (!start_tunnel(conn)) {
        TX_ERROR("Failed to establish tunnel");
        fail_tunnel_connection(conn);
    }
}

bool ClientApp::start_tunnel(ProxyConnPtr conn) {
    if (!conn || !conn->local_session || conn->local_session->is_closed()) {
        return false;
    }
    if (conn->tunnel_session && (conn->tunnel_connected || conn->tunnel_connecting)) {
        return true;
    }

    auto tunnel = std::make_shared<TcpSession>(loop_);
    conn->tunnel_session = tunnel;
    conn->tunnel_connected = false;
    conn->tunnel_connecting = true;
    conn->tunnel_handshake_buf.clear();
    conn->tunnel_recv_buf.clear();
    TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
    start_tunnel_timer(conn, kTunnelHandshakeTimeoutMs, "handshake");

    tunnel->set_close_callback([this, conn, tunnel](SessionPtr) {
        TX_WARN("Tunnel disconnected for session %u", conn->session_id);
        if (conn->tunnel_session == tunnel) {
            conn->tunnel_connected = false;
            conn->tunnel_connecting = false;
            conn->tunnel_session.reset();
            fail_tunnel_connection(conn);
        }
    });

    tunnel->connect(config_.server_host, config_.server_port,
        [this, conn, tunnel](bool success) {
            if (!conn || conn->tunnel_session != tunnel ||
                !conn->local_session || conn->local_session->is_closed()) {
                if (tunnel && !tunnel->is_closed()) {
                    tunnel->close();
                }
                return;
            }

            if (success) {
                conn->tunnel_handshake_buf.clear();
                TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
                TX_INFO("Tunnel connected to %s:%u for session %u",
                        config_.server_host.c_str(), config_.server_port,
                        conn->session_id);

                tunnel->start_read([this, conn](SessionPtr, Buffer& data) {
                    on_tunnel_handshake_read(conn, data);
                });

                Buffer hello;
                if (!TunnelCodec::build_client_hello(tunnel_psk_, config_.cipher, hello,
                                                      conn->tunnel_handshake_state)) {
                    TX_ERROR("Failed to build tunnel handshake for session %u",
                             conn->session_id);
                    fail_tunnel_connection(conn);
                    return;
                }
                tunnel->send(hello);
            } else {
                conn->tunnel_connecting = false;
                conn->tunnel_connected = false;
                TX_ERROR("Tunnel connect failed to %s:%u for session %u",
                         config_.server_host.c_str(), config_.server_port,
                         conn->session_id);
                fail_tunnel_connection(conn);
            }
        });

    return true;
}

void ClientApp::on_tunnel_handshake_read(ProxyConnPtr conn, Buffer& data) {
    if (!conn) {
        data.clear();
        return;
    }

    conn->tunnel_handshake_buf.append(data);
    data.clear();

    if (conn->tunnel_handshake_buf.readable() < TunnelCodec::kHandshakeSize) {
        return;
    }

    TunnelTrafficKeys keys;
    if (!TunnelCodec::parse_server_hello(tunnel_psk_, conn->tunnel_handshake_state,
                                          conn->tunnel_handshake_buf.data(),
                                          TunnelCodec::kHandshakeSize,
                                          keys)) {
        fail_tunnel_connection(conn);
        return;
    }

    conn->tunnel_handshake_buf.consume(TunnelCodec::kHandshakeSize);
    finish_tunnel_handshake(conn, keys);

    if (!conn->tunnel_handshake_buf.empty()) {
        conn->tunnel_recv_buf.append(conn->tunnel_handshake_buf);
        conn->tunnel_handshake_buf.clear();
        on_tunnel_read(conn, conn->tunnel_recv_buf);
    }
}

void ClientApp::finish_tunnel_handshake(ProxyConnPtr conn,
                                        const TunnelTrafficKeys& keys) {
    if (!conn || !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        return;
    }

    conn->tunnel_codec = TunnelCodec(keys, true);
    TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
    stop_tunnel_timer(conn);

    conn->tunnel_connecting = false;
    conn->tunnel_connected = true;
    TX_INFO("Tunnel handshake complete for session %u", conn->session_id);

    conn->tunnel_session->start_read([this, conn](SessionPtr, Buffer& data) {
        conn->tunnel_recv_buf.append(data);
        data.clear();
        on_tunnel_read(conn, conn->tunnel_recv_buf);
    });

    activate_tunnel_connection(conn);
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
    start_tunnel_timer(conn, kTunnelConnectResultTimeoutMs, "connect-result");
}

void ClientApp::complete_tunnel_connection(ProxyConnPtr conn) {
    if (!conn || conn->connect_result_sent ||
        !conn->local_session || conn->local_session->is_closed()) {
        return;
    }

    conn->connect_result_sent = true;
    stop_tunnel_timer(conn);
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
    conn->connected = false;
    close_tunnel_session(conn);

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

void ClientApp::close_tunnel_session(ProxyConnPtr conn) {
    if (!conn) return;

    auto tunnel = conn->tunnel_session;
    conn->tunnel_session.reset();
    conn->tunnel_connected = false;
    conn->tunnel_connecting = false;
    TunnelCodec::cleanse_handshake_state(conn->tunnel_handshake_state);
    conn->tunnel_handshake_buf.clear();
    conn->tunnel_recv_buf.clear();
    stop_tunnel_timer(conn);

    if (tunnel && !tunnel->is_closed()) {
        tunnel->set_close_callback(nullptr);
        tunnel->close();
    }
}

void ClientApp::start_tunnel_timer(ProxyConnPtr conn, uint64_t timeout_ms, const char* phase) {
    if (!conn) return;

    stop_tunnel_timer(conn);

    auto* timer = new uv_timer_t;
    auto* ctx = new TunnelTimerCtx{this, conn, phase ? phase : "unknown"};
    timer->data = ctx;

    if (uv_timer_init(loop_, timer) != 0) {
        delete ctx;
        delete timer;
        return;
    }

    conn->tunnel_timer = timer;
    int r = uv_timer_start(timer, ClientApp::on_tunnel_timer, timeout_ms, 0);
    if (r != 0) {
        conn->tunnel_timer = nullptr;
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_tunnel_timer_closed);
    }
}

void ClientApp::stop_tunnel_timer(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_timer) return;

    auto* timer = conn->tunnel_timer;
    conn->tunnel_timer = nullptr;

    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_timer_stop(timer);
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_tunnel_timer_closed);
    }
}

void ClientApp::on_tunnel_timer(uv_timer_t* timer) {
    auto* ctx = static_cast<TunnelTimerCtx*>(timer->data);
    if (!ctx || !ctx->app) return;

    auto conn = ctx->conn;
    std::string phase = ctx->phase;
    if (!conn || conn->tunnel_timer != timer) {
        return;
    }

    conn->tunnel_timer = nullptr;
    TX_ERROR("Tunnel %s timeout for session %u: %s:%u",
             phase.c_str(), conn->session_id,
             conn->target.host.c_str(), conn->target.port);
    ctx->app->fail_tunnel_connection(conn);

    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
        uv_close(reinterpret_cast<uv_handle_t*>(timer), ClientApp::on_tunnel_timer_closed);
    }
}

void ClientApp::on_tunnel_timer_closed(uv_handle_t* handle) {
    auto* ctx = static_cast<TunnelTimerCtx*>(handle->data);
    delete ctx;
    delete reinterpret_cast<uv_timer_t*>(handle);
}

void ClientApp::tunnel_send_connect(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        fail_tunnel_connection(conn);
        return;
    }

    Buffer encoded;
    if (conn->tunnel_codec.encode(TunnelCmd::Connect, conn->session_id,
                                  conn->target, nullptr, 0, encoded)) {
        conn->tunnel_session->send(encoded);
    }
}

void ClientApp::tunnel_send(ProxyConnPtr conn, const uint8_t* data, size_t len) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        fail_tunnel_connection(conn);
        return;
    }

    Buffer encoded;
    if (!conn->tunnel_codec.encode_data_chunks(conn->session_id, data, len, encoded)) {
        return;
    }

    conn->tunnel_session->send(encoded);
    record_traffic(RouteAction::Proxy, true, len);
}

void ClientApp::tunnel_send_disconnect(ProxyConnPtr conn) {
    if (!conn || !conn->tunnel_connected ||
        !conn->tunnel_session || conn->tunnel_session->is_closed()) {
        return;
    }

    Buffer encoded;
    if (conn->tunnel_codec.encode_disconnect(conn->session_id, encoded)) {
        conn->tunnel_session->send(encoded);
    }
}

void ClientApp::on_tunnel_read(ProxyConnPtr conn, Buffer& data) {
    if (!conn) {
        data.clear();
        return;
    }

    TunnelCmd cmd;
    SessionId session_id;
    TargetAddr target;
    Buffer payload;

    while (conn->tunnel_codec.decode(data, cmd, session_id, target, payload)) {
        if (session_id != conn->session_id) {
            TX_WARN("Tunnel data for unexpected session %u on tunnel for session %u",
                    session_id, conn->session_id);
            continue;
        }

        switch (cmd) {
            case TunnelCmd::Data:
                if (!payload.empty() && conn->local_session &&
                    !conn->local_session->is_closed()) {
                    record_traffic(RouteAction::Proxy, false, payload.readable());
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

    if (conn->tunnel_codec.has_protocol_error()) {
        TX_ERROR("Closing tunnel because remote data is not valid TX tunnel protocol");
        conn->tunnel_codec.clear_protocol_error();
        fail_tunnel_connection(conn);
    }
}

void ClientApp::on_proxy_close(ProxyConnPtr conn) {
    if (!conn) return;

    TX_DEBUG("Proxy connection closed, session %u", conn->session_id);

    if (conn->direct_session && !conn->direct_session->is_closed()) {
        conn->direct_session->set_close_callback(nullptr);
        conn->direct_session->close();
    }

    if (conn->route == RouteAction::Proxy) {
        tunnel_send_disconnect(conn);
        connections_.erase(conn->session_id);
        close_tunnel_session(conn);
    }
}

} // namespace tx
