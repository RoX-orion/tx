#include "server_app.h"

#include <cassert>
#include <cstdio>
#include <memory>

namespace tx {

struct ServerAppUdpTest {
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
};

} // namespace tx

int main() {
    tx::ServerAppUdpTest::domain_udp_resolves_once_and_pins_peer();
    std::printf("server UDP tests passed\n");
    return 0;
}
