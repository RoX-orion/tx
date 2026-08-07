#include "client_app.h"
#include "tx/common/endian.h"
#include "tx/net/tun_packet.h"

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

    static void domain_route_keeps_numeric_send_target() {
        ClientApp app;
        ClientApp::UdpFlow flow;
        flow.kind = ClientApp::UdpFlowKind::Tun;
        flow.fake_ip_target = true;
        flow.tun_src_ip = IpAddr::from_string("10.0.0.2", 10002);
        flow.tun_dst_ip = IpAddr::from_string("198.18.1.10", 443);

        TargetAddr actual;
        actual.type = AddrType::IPv4;
        actual.host = "142.250.1.2";
        actual.port = 443;
        const IpAddr source = app.tun_udp_response_source(flow, actual);
        assert(source == flow.tun_dst_ip);

        flow.fake_ip_target = false;
        assert(app.tun_udp_response_source(flow, actual) ==
               IpAddr::from_string("142.250.1.2", 443));

        flow.route_target.type = AddrType::Domain;
        flow.route_target.host = "youtubei.googleapis.com";
        flow.route_target.port = 443;
        flow.send_target.type = AddrType::IPv6;
        flow.send_target.host = "2607:f8b0:4004:c1d::5e";
        flow.send_target.port = 443;
        assert(app.tun_udp_response_source(flow, actual) ==
               IpAddr::from_string(actual.host, actual.port));
    }

    static void stale_fake_ipv6_is_not_routed_as_private() {
        ClientApp app;
        app.config_.udp_quic_sniff = false;

        OutboundConfig direct;
        direct.tag = "direct-out";
        direct.type = OutboundType::Direct;
        app.config_.outbound_index[direct.tag] = 0;
        app.config_.outbounds.push_back(std::move(direct));
        RouteRule private_rule;
        private_rule.ips.push_back("geoip:private");
        private_rule.outbound_tag = "direct-out";
        app.config_.router.rules.push_back(std::move(private_rule));
        RouteRule fallback;
        fallback.outbound_tag = "direct-out";
        app.config_.router.rules.push_back(std::move(fallback));
        assert(app.router_.load(app.config_.router));

        std::string error;
        assert(app.fake_ip_dns_.configure("198.18.0.0/16", "fd00:198:18::/96",
                                          60, error));
        const uint8_t packet[] = {0x01};
        app.handle_lwip_udp_datagram(9, IpAddr::from_string("fd00:198:18::1", 10006),
                                     IpAddr::from_string("fd00:198:18::999", 443),
                                     packet, sizeof(packet));
        assert(app.udp_flows_.empty());
    }

    static std::vector<uint8_t> dns_query(uint16_t id, uint16_t type) {
        std::vector<uint8_t> query = {
            static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id),
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm', 0x00,
            static_cast<uint8_t>(type >> 8), static_cast<uint8_t>(type), 0x00, 0x01,
        };
        return query;
    }

    static void tun_dns_flow_handles_multiple_queries() {
        ClientApp app;
        std::string error;
        assert(app.fake_ip_dns_.configure("198.18.0.0/16", "fd00:198:18::/96",
                                          60, error));
        std::vector<std::vector<uint8_t>> outputs;
        assert(app.lwip_udp_stack_.initialize(
            "198.18.0.1/30", 1500,
            [&app](uint64_t id, const IpAddr& source, const IpAddr& destination,
                   const uint8_t* payload, size_t payload_len) {
                app.handle_lwip_udp_datagram(id, source, destination, payload, payload_len);
            },
            [&outputs](const uint8_t* packet, size_t packet_len) {
                outputs.emplace_back(packet, packet + packet_len);
                return true;
            }, error));

        const IpAddr source = IpAddr::from_string("198.18.0.3", 53000);
        const IpAddr dns = IpAddr::from_string("198.18.0.2", 53);
        Buffer first;
        const auto a = dns_query(0x1234, 1);
        assert(build_udp_tun_packet(source, source.port, dns, dns.port,
                                    a.data(), a.size(), first));
        assert(app.lwip_udp_stack_.input(first.data(), first.readable()));
        Buffer second;
        const auto aaaa = dns_query(0x4321, 28);
        assert(build_udp_tun_packet(source, source.port, dns, dns.port,
                                    aaaa.data(), aaaa.size(), second));
        assert(app.lwip_udp_stack_.input(second.data(), second.readable()));
        assert(outputs.size() == 2);
        for (const auto& packet : outputs) {
            TunPacketView view;
            assert(parse_tun_packet(packet.data(), packet.size(), view));
            assert(view.protocol == TunL4Protocol::Udp);
            assert(view.src_ip == dns);
            assert(view.dst_ip == source);
            assert(view.payload_len >= 12);
            assert(load_be16(view.payload + 6) == 1);
        }
        assert(app.tun_dns_flows_.size() == 1);
        app.lwip_udp_stack_.shutdown();
    }

    static void tun_dns_flow_limit_reclaims_excess_pcbs() {
        ClientApp app;
        configure(app);
        std::vector<std::vector<uint8_t>> outputs;
        std::string error;
        assert(app.lwip_udp_stack_.initialize(
            "198.18.0.1/30", 1500,
            [&app](uint64_t id, const IpAddr& source, const IpAddr& destination,
                   const uint8_t* payload, size_t payload_len) {
                app.handle_lwip_udp_datagram(id, source, destination,
                                             payload, payload_len);
            },
            [&outputs](const uint8_t* packet, size_t packet_len) {
                outputs.emplace_back(packet, packet + packet_len);
                return true;
            }, error));

        const IpAddr dns = IpAddr::from_string("198.18.0.2", 53);
        const auto query = dns_query(0x1000, 1);
        for (uint16_t port = 53000; port < 53300; ++port) {
            const IpAddr source = IpAddr::from_string("198.18.0.3", port);
            Buffer packet;
            assert(build_udp_tun_packet(source, source.port, dns, dns.port,
                                        query.data(), query.size(), packet));
            assert(app.lwip_udp_stack_.input(packet.data(), packet.readable()));
        }
        // The fixed cap is below lwIP's MEMP_NUM_UDP_PCB=1024 pool.  The
        // excess queries receive a bounded failure and their PCBs are closed
        // immediately instead of lingering for the idle timer.
        assert(app.tun_dns_flows_.size() <= 256);
        assert(app.tun_dns_flows_.size() == 256);

        app.close_all_tun_dns_flows();
        assert(app.tun_dns_flows_.empty());
        const IpAddr source = IpAddr::from_string("198.18.0.3", 60000);
        Buffer packet;
        assert(build_udp_tun_packet(source, source.port, dns, dns.port,
                                    query.data(), query.size(), packet));
        assert(app.lwip_udp_stack_.input(packet.data(), packet.readable()));
        assert(app.tun_dns_flows_.size() == 1);
        app.lwip_udp_stack_.shutdown();
    }

    static void domain_udp_resolves_once_and_pins_peer() {
        unsigned resolve_count = 0;
        ClientApp app(
            SocketProtectCallback(),
            [&resolve_count](const std::string& host, int family) {
                assert(host == "pinned.example");
                assert(family == AF_UNSPEC);
                ++resolve_count;
                return std::vector<std::string>{"127.0.0.1", "::1"};
            });
        app.config_.udp_quic_sniff = false;

        OutboundConfig direct;
        direct.tag = "direct-out";
        direct.type = OutboundType::Direct;
        app.config_.outbound_index[direct.tag] = 0;
        app.config_.outbounds.push_back(std::move(direct));
        RouteRule fallback;
        fallback.outbound_tag = "direct-out";
        app.config_.router.rules.push_back(std::move(fallback));
        assert(app.router_.load(app.config_.router));
        app.dns_resolver_.configure({}, DnsResolver::ProtectCallback(), 0,
                                    app.host_resolver_);
        app.direct_dns_resolver_.configure({}, DnsResolver::ProtectCallback(), 0,
                                           app.host_resolver_);

        std::string error;
        assert(app.fake_ip_dns_.configure("198.18.0.0/16", "fd00:198:18::/96",
                                          60, error));
        const std::string fake_ip = allocate_fake_ipv4(app, "pinned.example");
        const uint8_t first[] = {0x01};
        const uint8_t second[] = {0x02};
        const IpAddr client = IpAddr::from_string("10.0.0.2", 10004);
        const IpAddr fake_target = IpAddr::from_string(fake_ip, 443);
        app.handle_lwip_udp_datagram(6, client, fake_target, first, sizeof(first));
        app.handle_lwip_udp_datagram(6, client, fake_target, second, sizeof(second));

        while (flow(app, 6).direct_target_resolving) {
            uv_run(app.loop(), UV_RUN_ONCE);
        }
        const ClientApp::UdpFlow& result = flow(app, 6);
        assert(resolve_count == 1);
        assert(result.send_target.type == AddrType::IPv4);
        assert(result.send_target.host == "127.0.0.1");
        assert(result.direct_resolution_packets.empty());
        assert(result.direct_resolution_bytes == 0);
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

    static void migrated_quic_short_header_inherits_cached_route() {
        ClientApp app;
        configure(app);
        const std::string server_cid("\x91\x92\x93\x94", 4);
        ClientApp::QuicRouteCacheEntry cached;
        cached.route_target.type = AddrType::Domain;
        cached.route_target.host = "sniffed.example";
        cached.route_target.port = 443;
        cached.outbound = app.find_outbound("block-out");
        cached.expires_at_ms = uv_now(app.loop()) + 60000;
        assert(cached.outbound);
        app.quic_route_cache_[server_cid] = cached;

        const uint8_t short_header[] = {0x40, 0x91, 0x92, 0x93, 0x94, 0x00};
        app.handle_lwip_udp_datagram(7, IpAddr::from_string("10.0.0.2", 10005),
                                     IpAddr::from_string("203.0.113.11", 443),
                                     short_header, sizeof(short_header));
        const ClientApp::UdpFlow& result = flow(app, 7);
        assert(result.route_ready);
        assert(result.route_target.type == AddrType::Domain);
        assert(result.route_target.host == "sniffed.example");
        assert(result.send_target.host == "203.0.113.11");
        assert(!result.quic_sniffer);
    }

    static void ambiguous_short_header_falls_back_to_ip() {
        ClientApp app;
        configure(app);
        ClientApp::UdpFlow flow;
        const uint64_t now = uv_now(app.loop());
        for (const auto& cid : {std::string("\x91\x92", 2),
                                std::string("\x91\x92\x93\x94", 4)}) {
            ClientApp::QuicRouteCacheEntry entry;
            entry.route_target.type = AddrType::Domain;
            entry.route_target.host = "sniffed.example";
            entry.route_target.port = 443;
            entry.outbound = app.find_outbound("block-out");
            entry.expires_at_ms = now + 60000;
            entry.last_used_at_ms = now;
            app.quic_route_cache_[cid] = entry;
        }
        const uint8_t short_header[] = {0x40, 0x91, 0x92, 0x93, 0x94, 0x00};
        assert(!app.inherit_tun_quic_route(flow, short_header, sizeof(short_header)));
        assert(!flow.route_ready);
    }

    static void quic_cache_hit_refreshes_expiry() {
        ClientApp app;
        configure(app);
        const std::string cid("\x91\x92\x93\x94", 4);
        ClientApp::QuicRouteCacheEntry entry;
        entry.route_target.type = AddrType::Domain;
        entry.route_target.host = "sniffed.example";
        entry.route_target.port = 443;
        entry.outbound = app.find_outbound("block-out");
        entry.expires_at_ms = uv_now(app.loop()) + 1000;
        app.quic_route_cache_[cid] = entry;
        const uint64_t before = app.quic_route_cache_[cid].expires_at_ms;

        ClientApp::UdpFlow flow;
        const uint8_t short_header[] = {0x40, 0x91, 0x92, 0x93, 0x94, 0x00};
        assert(app.inherit_tun_quic_route(flow, short_header, sizeof(short_header)));
        assert(app.quic_route_cache_[cid].last_used_at_ms != 0);
        assert(app.quic_route_cache_[cid].expires_at_ms > before);
    }

    static void network_change_keeps_live_quic_cache() {
        ClientApp app;
        configure(app);
        const std::string cid("\x91\x92\x93\x94", 4);
        ClientApp::QuicRouteCacheEntry entry;
        entry.route_target.type = AddrType::Domain;
        entry.route_target.host = "sniffed.example";
        entry.route_target.port = 443;
        entry.outbound = app.find_outbound("block-out");
        entry.expires_at_ms = uv_now(app.loop()) + 60000;
        app.quic_route_cache_[cid] = entry;
        app.network_changed_on_loop();
        assert(app.quic_route_cache_.find(cid) != app.quic_route_cache_.end());
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
    tx::ClientAppQuicTest::domain_route_keeps_numeric_send_target();
    tx::ClientAppQuicTest::stale_fake_ipv6_is_not_routed_as_private();
    tx::ClientAppQuicTest::tun_dns_flow_handles_multiple_queries();
    tx::ClientAppQuicTest::tun_dns_flow_limit_reclaims_excess_pcbs();
    tx::ClientAppQuicTest::domain_udp_resolves_once_and_pins_peer();
    tx::ClientAppQuicTest::domain_route_and_ip_send_target_stay_separate();
    tx::ClientAppQuicTest::migrated_quic_short_header_inherits_cached_route();
    tx::ClientAppQuicTest::ambiguous_short_header_falls_back_to_ip();
    tx::ClientAppQuicTest::quic_cache_hit_refreshes_expiry();
    tx::ClientAppQuicTest::network_change_keeps_live_quic_cache();
    tx::ClientAppQuicTest::oversized_first_packet_falls_back_without_buffering();
    tx::ClientAppQuicTest::flow_removal_releases_quic_resources();
    std::printf("client QUIC routing tests passed\n");
    return 0;
}
