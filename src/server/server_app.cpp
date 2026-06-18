#include "server_app.h"
#include "tx/common/log.h"
#include "tx/crypto/key_derive.h"

namespace tx {

ServerApp::ServerApp()
    : loop_(uv_default_loop()),
      server_(loop_) {}

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

    TX_INFO("TX Server started on %s:%u",
            config.listen_host.c_str(), config.listen_port);
    return true;
}

int ServerApp::run() {
    return uv_run(loop_, UV_RUN_DEFAULT);
}

void ServerApp::stop() {
    server_.stop();
    for (auto& kv : clients_) {
        if (kv.second->session && !kv.second->session->is_closed()) {
            kv.second->session->close();
        }
    }
    clients_.clear();
    uv_stop(loop_);
}

void ServerApp::on_tunnel_accept(SessionPtr session) {
    TX_INFO("Tunnel client connected from %s:%u",
            session->remote_addr().c_str(), session->remote_port());

    auto client = std::make_shared<TunnelClient>();
    client->session = session;

    // Initialize crypto — deterministic key from password (must match client)
    auto key = KeyDeriver::derive_deterministic(config_.password);
    auto aes = std::make_shared<AesGcm>(key.data(), key.size());
    client->codec = TunnelCodec(aes);

    clients_[session->handle()] = client;

    session->set_close_callback([this, client](SessionPtr) {
        on_tunnel_close(client);
    });

    session->start_read([this, client](SessionPtr, Buffer& data) {
        client->recv_buf.append(data);
        data.clear();
        on_tunnel_read(client, client->recv_buf);
    });
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
            case TunnelCmd::Disconnect:
                handle_disconnect(client, session_id);
                break;
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

    remote->connect(target.host, target.port,
        [this, client, sid, remote, target](bool success) {
            if (!success) {
                TX_ERROR("Failed to connect to target for session %u: %s:%u",
                         sid, target.host.c_str(), target.port);
                tunnel_send_disconnect(client, sid);
                client->outbounds.erase(sid);
                return;
            }

            TX_INFO("Connected to target for session %u: %s:%u",
                    sid, target.host.c_str(), target.port);

            auto it = client->outbounds.find(sid);
            if (it == client->outbounds.end()) {
                if (remote && !remote->is_closed()) {
                    remote->close();
                }
                return;
            }

            // Mark as connected and flush pending data
            it->second.connected = true;
            if (!it->second.pending_data.empty()) {
                remote->send(it->second.pending_data);
                it->second.pending_data.clear();
            }

            // Start reading from remote → forward back through tunnel
            remote->start_read([this, client, sid](SessionPtr, Buffer& data) {
                tunnel_send_data(client, sid, data.data(), data.readable());
                data.clear();
            });
        });
}

void ServerApp::handle_data(TunnelClientPtr client, SessionId sid, Buffer& payload) {
    auto it = client->outbounds.find(sid);
    if (it == client->outbounds.end()) {
        TX_DEBUG("Data for unknown session %u", sid);
        return;
    }

    if (it->second.connected &&
        it->second.remote_session && !it->second.remote_session->is_closed()) {
        it->second.remote_session->send(payload);
    } else {
        // Buffer data until remote connection is established
        it->second.pending_data.append(payload);
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
}

void ServerApp::tunnel_send_data(TunnelClientPtr client, SessionId sid,
                                   const uint8_t* data, size_t len) {
    if (!client->session || client->session->is_closed()) return;
    Buffer encoded;
    if (client->codec.encode_data(sid, data, len, encoded)) {
        client->session->send(encoded);
    }
}

void ServerApp::tunnel_send_disconnect(TunnelClientPtr client, SessionId sid) {
    if (!client->session || client->session->is_closed()) return;
    Buffer encoded;
    if (client->codec.encode_disconnect(sid, encoded)) {
        client->session->send(encoded);
    }
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

    clients_.erase(client->session->handle());
}

} // namespace tx
