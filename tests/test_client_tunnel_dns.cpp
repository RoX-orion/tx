#include "client_app.h"
#include "server_app.h"
#include "tx/common/endian.h"

#include <arpa/inet.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace tx {

struct ClientAppDnsTest {
    static void resolve(ClientApp& app, std::vector<uint8_t> query,
                        DnsResolver::ResolveCallback callback) {
        app.resolve_dns_via_tunnel(std::move(query), std::move(callback));
    }

    static bool dns_tunnel_is_separate(ClientApp& app, const OutboundConfig* outbound) {
        const auto data = app.get_udp_tunnel(outbound, ClientApp::UdpTunnelKind::Data);
        const auto dns = app.get_udp_tunnel(outbound, ClientApp::UdpTunnelKind::Dns);
        return data && dns && data != dns && data->key != dns->key &&
               data->kind == ClientApp::UdpTunnelKind::Data &&
               dns->kind == ClientApp::UdpTunnelKind::Dns;
    }

    static bool dns_query_is_pending(ClientApp& app) {
        for (const auto& item : app.udp_tunnels_) {
            if (item.second->kind == ClientApp::UdpTunnelKind::Dns &&
                !item.second->pending.empty() && item.second->pending.front().dns_query) {
                return true;
            }
        }
        return false;
    }
};

struct ClientAppNetworkTest {
    static bool family_available(const ClientApp& app, int family) {
        return app.android_address_family_available(family);
    }
};

struct ServerAppDnsTest {
    static void configure_query_hook(ServerApp& app, DnsResolver::QueryHook hook) {
        app.dns_resolver_.configure({}, DnsResolver::ProtectCallback(), 0,
                                    DnsResolver::HostResolveHook(), std::move(hook));
    }

    static void query_bytes_survive_cxx14_argument_evaluation() {
        ServerApp app;
        const std::vector<uint8_t> expected = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        std::vector<uint8_t> observed;
        app.dns_resolver_.configure(
            {}, DnsResolver::ProtectCallback(), 0, DnsResolver::HostResolveHook(),
            [&expected, &observed](const uint8_t* data, size_t len) {
                observed.assign(data, data + len);
                return expected;
            });

        auto client = std::make_shared<ServerApp::TunnelClient>();
        Buffer payload;
        payload.append(expected.data(), expected.size());
        app.handle_dns_query(client, 77, payload);
        assert(payload.empty());
        uv_run(app.loop(), UV_RUN_DEFAULT);
        assert(observed == expected);
        assert(client->dns_queries.empty());
        assert(client->pending_dns_queries == 0);
    }
};

} // namespace tx

namespace {

std::vector<uint8_t> make_query(const char* host, uint16_t type = 16) {
    std::vector<uint8_t> query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    const std::string name(host);
    size_t begin = 0;
    while (begin < name.size()) {
        const size_t end = name.find('.', begin);
        const size_t length = (end == std::string::npos ? name.size() : end) - begin;
        query.push_back(static_cast<uint8_t>(length));
        query.insert(query.end(), name.begin() + begin, name.begin() + begin + length);
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    query.push_back(0);
    query.push_back(static_cast<uint8_t>(type >> 8));
    query.push_back(static_cast<uint8_t>(type));
    query.push_back(0);
    query.push_back(1);
    return query;
}

std::vector<uint8_t> response_for(const std::vector<uint8_t>& query) {
    std::vector<uint8_t> response = query;
    response[2] = 0x81;
    response[3] = 0x80;
    return response;
}

tx::ClientConfig config_for(const char* domain_route,
                            tx::OutboundType route_type = tx::OutboundType::Tx,
                            uint16_t tx_port = 1) {
    tx::ClientConfig config;
    config.http_port = 0;
    config.socks5_port = 0;

    tx::OutboundConfig direct;
    direct.tag = "direct-out";
    direct.type = tx::OutboundType::Direct;
    config.outbound_index[direct.tag] = config.outbounds.size();
    config.outbounds.push_back(direct);

    tx::OutboundConfig block;
    block.tag = "block-out";
    block.type = tx::OutboundType::Block;
    config.outbound_index[block.tag] = config.outbounds.size();
    config.outbounds.push_back(block);

    tx::OutboundConfig tx_out;
    tx_out.tag = "tx-out";
    tx_out.type = tx::OutboundType::Tx;
    tx_out.server_host = "127.0.0.1";
    tx_out.server_port = tx_port;
    tx_out.psk.assign(32, 0x42);
    config.outbound_index[tx_out.tag] = config.outbounds.size();
    config.outbounds.push_back(tx_out);

    tx::RouteRule rule;
    rule.domains.push_back(domain_route);
    rule.outbound_tag = route_type == tx::OutboundType::Direct ? "direct-out" :
                        route_type == tx::OutboundType::Block ? "block-out" : "tx-out";
    config.router.rules.push_back(rule);
    tx::RouteRule fallback;
    fallback.outbound_tag = "tx-out";
    config.router.rules.push_back(fallback);
    return config;
}

uint16_t reserve_tcp_port() {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    const uint16_t port = ntohs(address.sin_port);
    close(fd);
    return port;
}

void test_block_dns_is_local() {
    tx::ClientApp app;
    assert(app.init(config_for("blocked.example", tx::OutboundType::Block)));
    std::vector<uint8_t> result;
    unsigned callbacks = 0;
    tx::ClientAppDnsTest::resolve(app, make_query("blocked.example"),
        [&](std::vector<uint8_t> response) {
            ++callbacks;
            result = std::move(response);
        });
    assert(callbacks == 1);
    assert(result.size() >= 12);
    assert((tx::load_be16(result.data() + 2) & 0x0f) == 5); // REFUSED
}

void test_direct_dns_uses_physical_hook() {
    const auto query = make_query("cn.example");
    const auto expected = response_for(query);
    tx::ClientApp app(tx::SocketProtectCallback(), tx::DnsResolver::HostResolveHook(),
                      [expected](const uint8_t*, size_t) { return expected; });
    assert(app.init(config_for("cn.example", tx::OutboundType::Direct)));
    std::vector<uint8_t> result;
    unsigned callbacks = 0;
    tx::ClientAppDnsTest::resolve(app, query,
        [&](std::vector<uint8_t> response) {
            ++callbacks;
            result = std::move(response);
            app.stop();
        });
    app.run();
    assert(callbacks == 1);
    assert(result == expected);
}

void test_tx_dns_has_no_resolver_target() {
    tx::ClientApp app;
    tx::ClientConfig config = config_for("foreign.example");
    assert(app.init(config));
    tx::ClientAppDnsTest::resolve(app, make_query("foreign.example"),
                                  [](std::vector<uint8_t>) {});
    assert(tx::ClientAppDnsTest::dns_query_is_pending(app));
    app.stop();
}

void test_android_tx_server_requires_numeric_host() {
    tx::ClientConfig config = config_for("foreign.example");
    config.outbounds[2].server_host = "tx.example.com";
    tx::ClientApp app;
    assert(!app.init(config));
}

void test_dns_tunnel_is_separate() {
    tx::ClientApp app;
    tx::OutboundConfig outbound;
    outbound.tag = "tx-out";
    outbound.type = tx::OutboundType::Tx;
    assert(tx::ClientAppDnsTest::dns_tunnel_is_separate(app, &outbound));
}

void test_dns_waits_for_server_failover() {
    const uint16_t port = reserve_tcp_port();
    const auto query = make_query("delayed.example");
    const auto expected = response_for(query);

    tx::ServerApp server;
    tx::ServerConfig server_config;
    server_config.listen_host = "127.0.0.1";
    server_config.listen_port = port;
    server_config.psk.assign(32, 0x42);
    assert(server.init(server_config));
    tx::ServerAppDnsTest::configure_query_hook(server,
        [expected](const uint8_t*, size_t) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2500));
            return expected;
        });
    std::thread server_thread([&server]() { server.run(); });

    tx::ClientApp client;
    assert(client.init(config_for("delayed.example", tx::OutboundType::Tx, port)));
    std::vector<uint8_t> result;
    unsigned callbacks = 0;
    std::atomic<bool> done(false);
    tx::ClientAppDnsTest::resolve(client, query,
        [&client, &result, &callbacks, &done](std::vector<uint8_t> response) {
            result = std::move(response);
            ++callbacks;
            done.store(true);
            client.stop();
        });
    std::thread client_thread([&client]() { client.run(); });

    for (unsigned i = 0; i < 100 && !done.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (!done.load()) client.stop();
    client_thread.join();
    server.stop();
    server_thread.join();
    assert(done.load());
    assert(callbacks == 1);
    assert(result == expected);
}

void test_android_physical_network_address_family_filter() {
    tx::ClientApp app(tx::SocketProtectCallback(), tx::DnsResolver::HostResolveHook(),
                      tx::DnsResolver::QueryHook(),
                      tx::kAndroidNetworkAddressFamilyKnown |
                          tx::kAndroidNetworkAddressFamilyIPv4);
    assert(tx::ClientAppNetworkTest::family_available(app, AF_INET));
    assert(!tx::ClientAppNetworkTest::family_available(app, AF_INET6));
    app.update_android_address_family_mask(
        tx::kAndroidNetworkAddressFamilyKnown | tx::kAndroidNetworkAddressFamilyIPv6);
    assert(!tx::ClientAppNetworkTest::family_available(app, AF_INET));
    assert(tx::ClientAppNetworkTest::family_available(app, AF_INET6));
    app.update_android_address_family_mask(0);
    assert(tx::ClientAppNetworkTest::family_available(app, AF_INET));
    assert(tx::ClientAppNetworkTest::family_available(app, AF_INET6));
}

} // namespace

int main() {
    tx::ServerAppDnsTest::query_bytes_survive_cxx14_argument_evaluation();
    test_block_dns_is_local();
    test_direct_dns_uses_physical_hook();
    test_tx_dns_has_no_resolver_target();
    test_android_tx_server_requires_numeric_host();
    test_dns_tunnel_is_separate();
    test_dns_waits_for_server_failover();
    test_android_physical_network_address_family_filter();
    std::printf("client tunnel DNS tests passed\n");
    return 0;
}
