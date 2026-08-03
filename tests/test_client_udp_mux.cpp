#include "client_app.h"

#include <cassert>
#include <cstdio>
#include <utility>

namespace tx {

struct ClientAppUdpMuxTest {
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
    tx::ClientAppUdpMuxTest::verify_pool_assignment();
    tx::ClientAppUdpMuxTest::verify_dedicated_tunnel_lifetime();
    std::printf("client UDP mux tests passed\n");
    return 0;
}
