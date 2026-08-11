#include "client_app.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tx {

class MockTcpStream final : public TcpStream {
public:
    bool write(const uint8_t*, size_t) override { return !closed; }
    bool write(Buffer& data) override {
        if (closed || data.empty()) return false;
        data.clear();
        return true;
    }
    void pause_read() override { paused = true; }
    void resume_read() override { paused = false; ++resume_count; }
    void shutdown_write() override { write_shutdown = true; }
    void close() override { closed = true; }
    void reset() override { closed = true; ++reset_count; }
    size_t pending_write_bytes() const override { return 0; }
    bool is_closed() const override { return closed; }
    bool is_read_eof() const override { return false; }
    bool is_write_shutdown() const override { return write_shutdown; }

    bool paused = false;
    bool closed = false;
    bool write_shutdown = false;
    unsigned resume_count = 0;
    unsigned reset_count = 0;
};

struct ClientAppTcpTest {
    static void proxy_target_callback_does_not_retain_connection() {
        ClientApp app;

        auto http_conn = std::make_shared<ClientApp::ProxyConn>();
        http_conn->http = std::make_unique<HttpProxyHandler>();
        std::weak_ptr<ClientApp::ProxyConn> http_weak = http_conn;
        app.bind_proxy_target_callback(http_conn);
        http_conn.reset();
        assert(http_weak.expired());

        auto socks_conn = std::make_shared<ClientApp::ProxyConn>();
        socks_conn->socks5 = std::make_unique<Socks5Handler>();
        std::weak_ptr<ClientApp::ProxyConn> socks_weak = socks_conn;
        app.bind_proxy_target_callback(socks_conn);
        socks_conn.reset();
        assert(socks_weak.expired());
    }

    static void preconnect_buffer_is_bounded() {
        ClientApp app;
        auto conn = std::make_shared<ClientApp::ProxyConn>();
        auto stream = std::make_shared<MockTcpStream>();
        conn->local_session = stream;
        conn->target.host = "example.com";
        conn->target.port = 443;

        std::vector<uint8_t> high_watermark(TcpFlowBridge::kHighWatermark, 0x5a);
        Buffer first;
        first.append(high_watermark.data(), high_watermark.size());
        assert(app.append_lwip_tcp_data(conn, first));
        assert(first.empty());
        assert(conn->proto_buf.readable() == TcpFlowBridge::kHighWatermark);
        assert(conn->local_paused_for_connect);
        assert(stream->paused);

        auto overflow_conn = std::make_shared<ClientApp::ProxyConn>();
        auto overflow_stream = std::make_shared<MockTcpStream>();
        overflow_conn->local_session = overflow_stream;
        std::vector<uint8_t> hard_limit(TcpFlowBridge::kHardLimit, 0);
        overflow_conn->proto_buf.append(hard_limit.data(), hard_limit.size());
        uint8_t extra = 1;
        Buffer overflow;
        overflow.append(&extra, 1);
        assert(!app.append_lwip_tcp_data(overflow_conn, overflow));
        assert(overflow_stream->reset_count == 1);
        assert(overflow.empty());

        conn->local_paused_for_tunnel = false;
        app.release_local_read(conn);
        assert(!conn->local_paused_for_connect);
        assert(!stream->paused);
        assert(stream->resume_count == 1);
    }
};

struct ClientAppUdpMuxTest {
    static tx::TunnelTrafficKeys fixed_keys() {
        tx::TunnelTrafficKeys keys;
        keys.client_to_server_key.assign(tx::AeadCipher::kKeyLen, 0x11);
        keys.server_to_client_key.assign(tx::AeadCipher::kKeyLen, 0x22);
        keys.client_to_server_nonce_prefix = {0xa1, 0xa2, 0xa3, 0xa4};
        keys.server_to_client_nonce_prefix = {0xb1, 0xb2, 0xb3, 0xb4};
        return keys;
    }

    static void verify_backlog_drop_keeps_sequence(bool dns) {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
        ClientApp app;
        OutboundConfig outbound;
        outbound.tag = "tx-out";
        outbound.type = OutboundType::Tx;
        app.config_.outbounds.push_back(outbound);
        const OutboundConfig* selected = &app.config_.outbounds.front();

        const SessionId sid = dns ? 302 : 301;
        ClientApp::UdpFlow flow;
        flow.session_id = sid;
        flow.kind = dns ? ClientApp::UdpFlowKind::InternalDns
                        : ClientApp::UdpFlowKind::Tun;
        flow.outbound = selected;
        flow.udp_tunnel_key = dns ? "tx-out:udp:dns" : "tx-out:udp:data";
        auto flow_inserted = app.udp_flows_.emplace(
            dns ? "dns-flow" : "data-flow", std::move(flow));
        assert(flow_inserted.second);
        app.udp_session_keys_[sid] = flow_inserted.first->first;

        auto tunnel = std::make_shared<ClientApp::UdpTunnel>();
        tunnel->outbound = selected;
        tunnel->kind = dns ? ClientApp::UdpTunnelKind::Dns
                            : ClientApp::UdpTunnelKind::Data;
        tunnel->key = flow_inserted.first->second.udp_tunnel_key;
        tunnel->connected = true;
        const auto keys = fixed_keys();
        tunnel->codec = tx::TunnelCodec(keys, true);

        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        tunnel->tunnel_session = std::make_shared<TcpSession>(app.loop());
        assert(uv_tcp_open(tunnel->tunnel_session->handle(), sockets[0]) == 0);

        std::vector<uint8_t> backlog(8 * 1024 * 1024, 0);
        assert(tunnel->tunnel_session->send(backlog.data(), backlog.size()));

        TargetAddr target;
        target.type = AddrType::IPv4;
        target.host = "192.0.2.1";
        target.port = 53;
        const uint8_t query[12] = {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        if (dns) {
            app.send_dns_query(tunnel, sid, query, sizeof(query));
        } else {
            const uint8_t payload[] = {1, 2, 3};
            app.send_udp_packet(tunnel, sid, target, payload, sizeof(payload));
        }

        // The rejected datagram must not consume sequence zero. Encoding the
        // next frame and decoding it with a fresh peer codec catches a skipped
        // sequence even though the saturated socket cannot be drained here.
        Buffer next;
        if (dns) {
            assert(tunnel->codec.encode_dns_query(sid, query, sizeof(query), next));
        } else {
            const uint8_t payload[] = {4, 5, 6};
            assert(tunnel->codec.encode_udp_packet(sid, target, payload,
                                                   sizeof(payload), next));
        }
        TunnelCodec peer(keys, false);
        TunnelCmd cmd;
        SessionId decoded_sid = 0;
        TargetAddr decoded_target;
        Buffer decoded_payload;
        assert(peer.decode(next, cmd, decoded_sid, decoded_target, decoded_payload));
        assert(decoded_sid == sid);

        tunnel->tunnel_session->close();
        uv_run(app.loop(), UV_RUN_DEFAULT);
        close(sockets[1]);
#else
        (void)dns;
#endif
    }

    static void verify_udp_backlog_drop_keeps_sequence() {
        verify_backlog_drop_keeps_sequence(false);
    }

    static void verify_dns_backlog_drop_keeps_sequence() {
        verify_backlog_drop_keeps_sequence(true);
    }

    static void verify_pool_assignment() {
        ClientApp app;
        OutboundConfig outbound;
        outbound.tag = "tx-out";
        outbound.type = OutboundType::Tx;
        outbound.udp_mux_connections = 3;
        app.config_.outbounds.push_back(std::move(outbound));
        const OutboundConfig* tx_outbound = &app.config_.outbounds.front();

        ClientApp::UdpFlow first;
        first.session_id = 101;
        first.outbound = tx_outbound;
        ClientApp::UdpFlow second;
        second.session_id = 102;
        second.outbound = tx_outbound;
        ClientApp::UdpFlow third;
        third.session_id = 103;
        third.outbound = tx_outbound;
        ClientApp::UdpFlow fourth;
        fourth.session_id = 104;
        fourth.outbound = tx_outbound;

        const auto first_tunnel = app.select_udp_tunnel(first);
        const auto second_tunnel = app.select_udp_tunnel(second);
        const auto third_tunnel = app.select_udp_tunnel(third);
        const auto fourth_tunnel = app.select_udp_tunnel(fourth);
        assert(first_tunnel && second_tunnel && third_tunnel && fourth_tunnel);
        assert(first_tunnel->key == "tx-out:udp:0");
        assert(second_tunnel->key == "tx-out:udp:1");
        assert(third_tunnel->key == "tx-out:udp:2");
        assert(fourth_tunnel == first_tunnel);
        assert(app.select_udp_tunnel(first) == first_tunnel);
        assert(!first_tunnel->dedicated);
        assert(app.udp_tunnels_.size() == 3);
    }

    static void verify_dedicated_tunnel_lifetime() {
        ClientApp app;
        OutboundConfig outbound;
        outbound.tag = "tx-out";
        outbound.type = OutboundType::Tx;
        outbound.udp_mux_connections = -1;
        app.config_.outbounds.push_back(std::move(outbound));
        const OutboundConfig* tx_outbound = &app.config_.outbounds.front();

        ClientApp::UdpFlow flow;
        flow.session_id = 201;
        flow.outbound = tx_outbound;
        flow.proxied = true;
        auto inserted = app.udp_flows_.emplace("udp-flow", std::move(flow));
        assert(inserted.second);
        app.udp_session_keys_[201] = "udp-flow";

        const auto tunnel = app.select_udp_tunnel(inserted.first->second);
        assert(tunnel && tunnel->dedicated);
        assert(tunnel->owner_session_id == 201);
        assert(tunnel->key == "tx-out:udp:flow:201");
        app.remove_udp_flow("udp-flow", false);
        assert(app.udp_flows_.empty());
        assert(app.udp_tunnels_.find(tunnel->key) == app.udp_tunnels_.end());
    }
};

} // namespace tx

int main() {
    tx::ClientAppTcpTest::proxy_target_callback_does_not_retain_connection();
    tx::ClientAppTcpTest::preconnect_buffer_is_bounded();
    tx::ClientAppUdpMuxTest::verify_udp_backlog_drop_keeps_sequence();
    tx::ClientAppUdpMuxTest::verify_dns_backlog_drop_keeps_sequence();
    tx::ClientAppUdpMuxTest::verify_pool_assignment();
    tx::ClientAppUdpMuxTest::verify_dedicated_tunnel_lifetime();
    std::printf("client UDP mux tests passed\n");
    return 0;
}
