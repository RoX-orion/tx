#include "server_app.h"

#include <cassert>
#include <cstdio>
#include <functional>
#include <memory>
#include <vector>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tx {

struct ServerAppUdpTest {
    static tx::TunnelTrafficKeys fixed_keys() {
        tx::TunnelTrafficKeys keys;
        keys.client_to_server_key.assign(tx::AeadCipher::kKeyLen, 0x11);
        keys.server_to_client_key.assign(tx::AeadCipher::kKeyLen, 0x22);
        keys.client_to_server_nonce_prefix = {0xa1, 0xa2, 0xa3, 0xa4};
        keys.server_to_client_nonce_prefix = {0xb1, 0xb2, 0xb3, 0xb4};
        return keys;
    }

    static void udp_backlog_drop_keeps_sequence() {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
        ServerApp app;
        auto client = std::make_shared<ServerApp::TunnelClient>();
        const auto keys = fixed_keys();
        client->codec = tx::TunnelCodec(keys, false);

        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        client->session = std::make_shared<TcpSession>(app.loop());
        assert(uv_tcp_open(client->session->handle(), sockets[0]) == 0);
        std::vector<uint8_t> backlog(TcpSession::kDefaultWriteHardLimit - 1, 0);
        assert(client->session->send(backlog.data(), backlog.size()));

        TargetAddr target;
        target.type = AddrType::IPv4;
        target.host = "192.0.2.1";
        target.port = 53;
        const uint8_t payload[] = {1, 2, 3};
        app.tunnel_send_udp_packet(client, 401, target, payload, sizeof(payload));

        Buffer next;
        const uint8_t next_payload[] = {4, 5, 6};
        assert(client->codec.encode_udp_packet(401, target, next_payload,
                                                sizeof(next_payload), next));
        TunnelCodec peer(keys, true);
        TunnelCmd cmd;
        SessionId sid = 0;
        TargetAddr decoded_target;
        Buffer decoded_payload;
        assert(peer.decode(next, cmd, sid, decoded_target, decoded_payload));
        assert(sid == 401);

        client->session->close();
        uv_run(app.loop(), UV_RUN_DEFAULT);
        close(sockets[1]);
#endif
    }

    static Buffer packet(const uint8_t value) {
        Buffer result;
        result.append(&value, 1);
        return result;
    }

    static void domain_udp_resolves_once_and_pins_peer() {
        ServerApp app;
        auto client = std::make_shared<ServerApp::TunnelClient>();
        TargetAddr target;
        target.type = AddrType::Domain;
        target.host = "localhost";
        target.port = 443;

        Buffer first = packet(1);
        Buffer second = packet(2);
        app.handle_udp_packet(client, 1, target, first);
        app.handle_udp_packet(client, 1, target, second);

        auto it = client->udp_outbounds.find(1);
        assert(it != client->udp_outbounds.end());
        assert(it->second.resolving);
        assert(it->second.pending_resolution_packets.size() == 2);

        while (it->second.resolving) {
            uv_run(app.loop(), UV_RUN_ONCE);
            it = client->udp_outbounds.find(1);
            assert(it != client->udp_outbounds.end());
        }

        assert(it->second.peer_ready);
        assert(it->second.pending_resolution_packets.empty());
        assert(it->second.pending_resolution_bytes == 0);
        assert(it->second.udp_v4 || it->second.udp_v6);
        app.close_udp_outbound(it->second);
        uv_run(app.loop(), UV_RUN_DEFAULT);
    }

    static void cross_protocol_session_ids_close_tunnel() {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
        const auto expect_violation = [](
            const std::function<void(ServerApp&,
                                     const std::shared_ptr<ServerApp::TunnelClient>&)>& action) {
            ServerApp app;
            int sockets[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
            auto client = std::make_shared<ServerApp::TunnelClient>();
            client->session = std::make_shared<TcpSession>(app.loop());
            assert(uv_tcp_open(client->session->handle(), sockets[0]) == 0);
            action(app, client);
            assert(client->session->is_closed());
            uv_run(app.loop(), UV_RUN_DEFAULT);
            assert(close(sockets[1]) == 0);
        };

        expect_violation([](ServerApp& app,
                            const std::shared_ptr<ServerApp::TunnelClient>& client) {
            client->dns_queries.insert(7);
            TargetAddr target;
            target.type = AddrType::IPv4;
            target.host = "127.0.0.1";
            target.port = 80;
            app.handle_connect(client, 7, target);
        });
        expect_violation([](ServerApp& app,
                            const std::shared_ptr<ServerApp::TunnelClient>& client) {
            client->dns_queries.insert(8);
            TargetAddr target;
            target.type = AddrType::IPv4;
            target.host = "127.0.0.1";
            target.port = 53;
            Buffer payload;
            const uint8_t byte = 1;
            payload.append(&byte, 1);
            app.handle_udp_packet(client, 8, target, payload);
        });
        expect_violation([](ServerApp& app,
                            const std::shared_ptr<ServerApp::TunnelClient>& client) {
            ServerApp::TunnelClient::UdpOutbound udp;
            udp.session_id = 9;
            client->udp_outbounds.emplace(9, std::move(udp));
            Buffer payload;
            const uint8_t byte = 1;
            payload.append(&byte, 1);
            app.handle_data(client, 9, payload);
        });
        expect_violation([](ServerApp& app,
                            const std::shared_ptr<ServerApp::TunnelClient>& client) {
            client->dns_queries.insert(10);
            app.handle_half_close(client, 10);
        });
        expect_violation([](ServerApp& app,
                            const std::shared_ptr<ServerApp::TunnelClient>& client) {
            client->dns_queries.insert(11);
            app.handle_disconnect(client, 11);
        });
#endif
    }
};

} // namespace tx

int main() {
    tx::ServerAppUdpTest::udp_backlog_drop_keeps_sequence();
    tx::ServerAppUdpTest::domain_udp_resolves_once_and_pins_peer();
    tx::ServerAppUdpTest::cross_protocol_session_ids_close_tunnel();
    std::printf("server UDP tests passed\n");
    return 0;
}
