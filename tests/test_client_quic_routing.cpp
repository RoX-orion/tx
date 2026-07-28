#include "client_app.h"

#include <cassert>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace tx {

struct ClientAppQuicTest {
    static void configure(ClientApp& app, bool quic_sniff = true) {
        app.config_.udp_quic_sniff = quic_sniff;

        OutboundConfig block;
        block.tag = "block-out";
        block.type = OutboundType::Block;
        app.config_.outbound_index[block.tag] = 0;
        app.config_.outbounds.push_back(std::move(block));

        RouteRule sni_rule;
        sni_rule.domains.push_back("sniffed.example");
        sni_rule.outbound_tag = "block-out";
        app.config_.router.rules.push_back(std::move(sni_rule));
        RouteRule fallback;
        fallback.outbound_tag = "block-out";
        app.config_.router.rules.push_back(std::move(fallback));
        assert(app.router_.load(app.config_.router));

        std::string error;
        assert(app.fake_ip_dns_.configure("198.18.0.0/16", "fd00:198:18::/96",
                                          60, error));
    }

    static const ClientApp::UdpFlow& flow(const ClientApp& app, uint64_t flow_id) {
        const std::string key = "tun:lwip:" + std::to_string(flow_id);
        const auto it = app.udp_flows_.find(key);
        assert(it != app.udp_flows_.end());
        return it->second;
    }

    static void non_quic_falls_back_to_ip() {
        ClientApp app;
        configure(app);
        const uint8_t packet[] = {0x00};
        app.handle_lwip_udp_datagram(1, IpAddr::from_string("10.0.0.2", 10000),
                                     IpAddr::from_string("203.0.113.7", 443),
                                     packet, sizeof(packet));
        const ClientApp::UdpFlow& result = flow(app, 1);
        assert(result.route_ready);
        assert(result.route_target.type == AddrType::IPv4);
        assert(result.route_target.host == "203.0.113.7");
        assert(result.send_target.type == AddrType::IPv4);
        assert(result.send_target.host == "203.0.113.7");
        assert(result.quic_pending_packets.empty());
        assert(!result.quic_sniffer);
        assert(app.quic_sniff_active_flows_ == 0);
        assert(app.quic_sniff_pending_bytes_ == 0);
    }

    static void disabled_sniff_routes_immediately_by_ip() {
        ClientApp app;
        configure(app, false);
        const uint8_t packet[] = {0xc0, 0x00};
        app.handle_lwip_udp_datagram(2, IpAddr::from_string("10.0.0.2", 10001),
                                     IpAddr::from_string("203.0.113.8", 443),
                                     packet, sizeof(packet));
        const ClientApp::UdpFlow& result = flow(app, 2);
        assert(result.route_ready);
        assert(result.route_target.host == "203.0.113.8");
        assert(!result.quic_sniffer);
        assert(app.quic_sniff_active_flows_ == 0);
    }

    static std::string allocate_fake_ipv4(ClientApp& app, const std::string& domain) {
        std::vector<uint8_t> query = {
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        };
        size_t start = 0;
        while (start < domain.size()) {
            const size_t end = domain.find('.', start);
            const size_t label_end = end == std::string::npos ? domain.size() : end;
            assert(label_end > start && label_end - start <= 63);
            query.push_back(static_cast<uint8_t>(label_end - start));
            query.insert(query.end(), domain.begin() + start, domain.begin() + label_end);
            start = label_end + 1;
        }
        query.push_back(0);
        query.insert(query.end(), {0x00, 0x01, 0x00, 0x01});
        std::vector<uint8_t> response;
        assert(app.fake_ip_dns_.respond(query.data(), query.size(), response));
        assert(response.size() >= 4);
        return std::to_string(response[response.size() - 4]) + "." +
               std::to_string(response[response.size() - 3]) + "." +
               std::to_string(response[response.size() - 2]) + "." +
               std::to_string(response[response.size() - 1]);
    }

    static void fake_ip_keeps_domain_and_skips_sniff() {
        ClientApp app;
        configure(app);
        const std::string fake_ip = allocate_fake_ipv4(app, "cached.example");
        const uint8_t packet[] = {0xc0, 0x00};
        app.handle_lwip_udp_datagram(3, IpAddr::from_string("10.0.0.2", 10002),
                                     IpAddr::from_string(fake_ip, 443),
                                     packet, sizeof(packet));
        const ClientApp::UdpFlow& result = flow(app, 3);
        assert(result.route_ready);
        assert(result.route_target.type == AddrType::Domain);
        assert(result.route_target.host == "cached.example");
        assert(result.send_target.type == AddrType::Domain);
        assert(result.send_target.host == "cached.example");
        assert(!result.quic_sniffer);
        assert(app.quic_sniff_active_flows_ == 0);
    }

    static void domain_route_and_ip_send_target_stay_separate() {
        ClientApp app;
        configure(app);
        ClientApp::UdpFlow flow;
        flow.kind = ClientApp::UdpFlowKind::Tun;
        TargetAddr route_target;
        route_target.type = AddrType::Domain;
        route_target.host = "sniffed.example";
        route_target.port = 443;
        TargetAddr send_target;
        send_target.type = AddrType::IPv4;
        send_target.host = "203.0.113.9";
        send_target.port = 443;
        assert(app.finalize_tun_udp_route(flow, route_target, send_target));
        assert(flow.route_ready);
        assert(flow.route_target.type == AddrType::Domain);
        assert(flow.route_target.host == "sniffed.example");
        assert(flow.send_target.type == AddrType::IPv4);
        assert(flow.send_target.host == "203.0.113.9");
        assert(flow.outbound && flow.outbound->type == OutboundType::Block);
    }

    static void oversized_first_packet_falls_back_without_buffering() {
        ClientApp app;
        configure(app);
        std::vector<uint8_t> packet(16 * 1024 + 1, 0xc0);
        app.handle_lwip_udp_datagram(4, IpAddr::from_string("10.0.0.2", 10003),
                                     IpAddr::from_string("203.0.113.10", 443),
                                     packet.data(), packet.size());
        const ClientApp::UdpFlow& result = flow(app, 4);
        assert(result.route_ready);
        assert(result.route_target.host == "203.0.113.10");
        assert(result.quic_pending_packets.empty());
        assert(!result.quic_sniffer);
        assert(app.quic_sniff_active_flows_ == 0);
        assert(app.quic_sniff_pending_bytes_ == 0);
    }

    static void flow_removal_releases_quic_resources() {
        ClientApp app;
        configure(app);
        ClientApp::UdpFlow flow;
        flow.session_id = app.allocate_session_id();
        assert(flow.session_id != 0);
        flow.kind = ClientApp::UdpFlowKind::Tun;
        flow.quic_sniffer.reset(new QuicSniSniffer());
        flow.quic_pending_packets.push_back(std::vector<uint8_t>{1, 2, 3});
        flow.quic_pending_bytes = 3;
        const std::string key = "tun:lwip:5";
        app.udp_session_keys_[flow.session_id] = key;
        app.udp_flows_.emplace(key, std::move(flow));
        app.quic_sniff_active_flows_ = 1;
        app.quic_sniff_pending_bytes_ = 3;

        app.remove_udp_flow(key, false);
        assert(app.udp_flows_.empty());
        assert(app.quic_sniff_active_flows_ == 0);
        assert(app.quic_sniff_pending_bytes_ == 0);
    }
};

} // namespace tx

int main() {
    tx::ClientAppQuicTest::non_quic_falls_back_to_ip();
    tx::ClientAppQuicTest::disabled_sniff_routes_immediately_by_ip();
    tx::ClientAppQuicTest::fake_ip_keeps_domain_and_skips_sniff();
    tx::ClientAppQuicTest::domain_route_and_ip_send_target_stay_separate();
    tx::ClientAppQuicTest::oversized_first_packet_falls_back_without_buffering();
    tx::ClientAppQuicTest::flow_removal_releases_quic_resources();
    std::printf("client QUIC routing tests passed\n");
    return 0;
}
