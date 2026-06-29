#pragma once

#include <uv.h>
#include <string>
#include <memory>
#include <unordered_map>
#include "tx/net/tcp_server.h"
#include "tx/net/buffer.h"
#include "tx/protocol/tunnel.h"
#include "config.h"

namespace tx {

// Server application: accepts tunnel connections from clients,
// decrypts requests, and proxies traffic to the target.
class ServerApp {
public:
    ServerApp();
    ~ServerApp();

    bool init(const ServerConfig& config);
    int run();
    void stop();

private:
    // A tunnel session from one client
    struct TunnelClient {
        SessionPtr       session;
        TunnelCodec      codec;
        Buffer           handshake_buf;
        Buffer           recv_buf;
        bool             outbounds_paused = false;

        // Outbound connections by session ID
        struct Outbound {
            SessionPtr remote_session;
            SessionId  session_id;
            Buffer     pending_data;   // buffered before remote connected
            bool       connected;      // remote fully connected?
        };
        std::unordered_map<SessionId, Outbound> outbounds;
    };
    using TunnelClientPtr = std::shared_ptr<TunnelClient>;

    void on_tunnel_accept(SessionPtr session);
    void on_tunnel_handshake_read(TunnelClientPtr client, Buffer& data);
    void on_tunnel_read(TunnelClientPtr client, Buffer& data);
    void on_tunnel_close(TunnelClientPtr client);

    // Handle decoded tunnel message
    void handle_connect(TunnelClientPtr client, SessionId sid, const TargetAddr& target);
    void handle_data(TunnelClientPtr client, SessionId sid, Buffer& payload);
    void handle_disconnect(TunnelClientPtr client, SessionId sid);

    // Send encrypted data back to client
    void tunnel_send_data(TunnelClientPtr client, SessionId sid,
                          const uint8_t* data, size_t len);
    void tunnel_send_disconnect(TunnelClientPtr client, SessionId sid);
    void tunnel_send_connect_result(TunnelClientPtr client, SessionId sid, bool success);
    void pause_outbound_reads(TunnelClientPtr client);
    void resume_outbound_reads(TunnelClientPtr client);

    uv_loop_t*         loop_;
    ServerConfig       config_;
    TcpServer          server_;

    // Active tunnel clients
    std::unordered_map<uv_tcp_t*, TunnelClientPtr> clients_;
};

} // namespace tx
