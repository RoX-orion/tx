#include "tx/net/dns_resolver.h"
#include "tx/net/dns_network_provider.h"
#include "tx/common/endian.h"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

std::vector<uint8_t> make_query() {
    std::vector<uint8_t> query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
    };
    return query;
}

std::vector<uint8_t> make_response(const std::vector<uint8_t>& query,
                                   uint8_t low_flags = 0x80) {
    std::vector<uint8_t> response = query;
    response[2] = 0x81;
    response[3] = low_flags;
    return response;
}

std::vector<uint8_t> make_a_response(const std::vector<uint8_t>& query,
                                     uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    std::vector<uint8_t> response = make_response(query);
    tx::store_be16(response.data() + 6, 1);
    const uint8_t answer[] = {
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, a, b, c, d,
    };
    response.insert(response.end(), answer, answer + sizeof(answer));
    return response;
}

#if defined(__linux__)
bool is_loopback(const std::string& address) {
    in_addr address4{};
    if (inet_pton(AF_INET, address.c_str(), &address4) == 1)
        return (ntohl(address4.s_addr) >> 24) == 127;
    in6_addr address6{};
    return inet_pton(AF_INET6, address.c_str(), &address6) == 1 &&
           IN6_IS_ADDR_LOOPBACK(&address6);
}

void test_platform_dns_provider_policy() {
    auto ordinary = tx::create_platform_dns_network_provider(0, false);
    assert(ordinary);
    const tx::DnsNetworkSnapshot ordinary_snapshot = ordinary->snapshot();
    assert(ordinary_snapshot.available == !ordinary_snapshot.endpoints.empty());
    for (const auto& endpoint : ordinary_snapshot.endpoints) {
        assert(endpoint.port == 53);
        if (is_loopback(endpoint.address)) {
            // Local stubs must use the kernel's normal loopback route, not a
            // physical interface binding intended for TUN bypass traffic.
            assert(ordinary_snapshot.socket_binding.mark == 0);
            assert(ordinary_snapshot.socket_binding.interface_name.empty());
        }
    }

    auto physical = tx::create_platform_dns_network_provider(0, true);
    assert(physical);
    const tx::DnsNetworkSnapshot physical_snapshot = physical->snapshot();
    for (const auto& endpoint : physical_snapshot.endpoints)
        assert(!is_loopback(endpoint.address));
}

struct LocalDnsPair {
    int tcp = -1;
    int udp = -1;
    uint16_t port = 0;
};

LocalDnsPair open_local_dns_pair() {
    LocalDnsPair pair;
    pair.tcp = socket(AF_INET, SOCK_STREAM, 0);
    assert(pair.tcp >= 0);
    int one = 1;
    assert(setsockopt(pair.tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(pair.tcp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    assert(listen(pair.tcp, 4) == 0);
    socklen_t address_len = sizeof(address);
    assert(getsockname(pair.tcp, reinterpret_cast<sockaddr*>(&address),
                       &address_len) == 0);
    pair.port = ntohs(address.sin_port);

    pair.udp = socket(AF_INET, SOCK_DGRAM, 0);
    assert(pair.udp >= 0);
    address.sin_port = htons(pair.port);
    assert(bind(pair.udp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    return pair;
}

void serve_tcp_without_response(int listener, int hold_ms) {
    pollfd event{listener, POLLIN, 0};
    if (poll(&event, 1, 500) > 0) {
        int client = accept(listener, nullptr, nullptr);
        if (client >= 0) {
            if (hold_ms) std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
            close(client);
        }
    }
    close(listener);
}

std::vector<uint8_t> resolve_once(
    LocalDnsPair pair,
    const std::function<void(int, const std::vector<uint8_t>&)>& udp_server,
    int tcp_hold_ms, long long* elapsed_ms = nullptr,
    std::shared_ptr<tx::DnsNetworkProvider> network_provider = nullptr) {
    const std::vector<uint8_t> query = make_query();
    std::thread udp_thread([pair, query, udp_server]() {
        udp_server(pair.udp, query);
        close(pair.udp);
    });
    std::thread tcp_thread(serve_tcp_without_response, pair.tcp, tcp_hold_ms);

    uv_loop_t loop;
    assert(uv_loop_init(&loop) == 0);
    tx::DnsResolver resolver(&loop);
    if (network_provider) {
        resolver.configure({}, tx::DnsResolver::ProtectCallback(), 0,
                           tx::DnsResolver::HostResolveHook(),
                           tx::DnsResolver::QueryHook(),
                           tx::DnsResolver::AsyncQueryHook(), network_provider);
    } else {
        resolver.configure(
            {"127.0.0.1:" + std::to_string(pair.port)},
            tx::DnsResolver::ProtectCallback(), 0);
    }

    std::vector<uint8_t> result;
    const auto started = std::chrono::steady_clock::now();
    resolver.resolve(query.data(), query.size(),
        [&](std::vector<uint8_t> response) { result = std::move(response); });
    uv_run(&loop, UV_RUN_DEFAULT);
    if (elapsed_ms) {
        *elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
    }
    assert(uv_loop_close(&loop) == 0);
    udp_thread.join();
    tcp_thread.join();
    return result;
}

class StaticDnsNetworkProvider final : public tx::DnsNetworkProvider {
public:
    explicit StaticDnsNetworkProvider(uint16_t port) : port_(port) {}

    tx::DnsNetworkSnapshot snapshot() const override {
        tx::DnsNetworkSnapshot result;
        result.available = true;
        result.endpoints.push_back(tx::DnsEndpoint{"127.0.0.1", port_});
        return result;
    }

    void invalidate() override { ++invalidations_; }
    unsigned invalidations() const { return invalidations_; }

private:
    uint16_t port_;
    unsigned invalidations_ = 0;
};

void test_first_success_and_validation() {
    long long elapsed_ms = 0;
    auto valid = resolve_once(
        open_local_dns_pair(),
        [](int udp, const std::vector<uint8_t>& query) {
            sockaddr_storage peer{};
            socklen_t peer_len = sizeof(peer);
            uint8_t buffer[512];
            assert(recvfrom(udp, buffer, sizeof(buffer), 0,
                            reinterpret_cast<sockaddr*>(&peer), &peer_len) > 0);
            const auto response = make_response(query);
            assert(sendto(udp, response.data(), response.size(), 0,
                          reinterpret_cast<sockaddr*>(&peer), peer_len) ==
                   static_cast<ssize_t>(response.size()));
        },
        1200, &elapsed_ms);
    assert(valid == make_response(make_query()));
    assert(elapsed_ms < 700);

    const auto query = make_query();
    for (int invalid_kind = 0; invalid_kind < 3; ++invalid_kind) {
        auto invalid = resolve_once(
            open_local_dns_pair(),
            [invalid_kind](int udp, const std::vector<uint8_t>& received_query) {
                sockaddr_storage peer{};
                socklen_t peer_len = sizeof(peer);
                uint8_t buffer[512];
                assert(recvfrom(udp, buffer, sizeof(buffer), 0,
                                reinterpret_cast<sockaddr*>(&peer), &peer_len) > 0);
                auto response = make_response(received_query);
                if (invalid_kind == 0) response[1] ^= 0x01;       // transaction ID
                if (invalid_kind == 1) response[2] &= 0x7f;      // QR bit
                if (invalid_kind == 2) response[13] = 'x';       // question name
                assert(sendto(udp, response.data(), response.size(), 0,
                              reinterpret_cast<sockaddr*>(&peer), peer_len) ==
                       static_cast<ssize_t>(response.size()));
            },
            0);
        assert(invalid.empty());
    }

    auto authenticated = resolve_once(
        open_local_dns_pair(),
        [](int udp, const std::vector<uint8_t>& received_query) {
            sockaddr_storage peer{};
            socklen_t peer_len = sizeof(peer);
            uint8_t buffer[512];
            assert(recvfrom(udp, buffer, sizeof(buffer), 0,
                            reinterpret_cast<sockaddr*>(&peer), &peer_len) > 0);

            int rogue = socket(AF_INET, SOCK_DGRAM, 0);
            assert(rogue >= 0);
            auto forged = make_response(received_query, 0x83);
            assert(sendto(rogue, forged.data(), forged.size(), 0,
                          reinterpret_cast<sockaddr*>(&peer), peer_len) ==
                   static_cast<ssize_t>(forged.size()));
            close(rogue);

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            const auto expected = make_response(received_query);
            assert(sendto(udp, expected.data(), expected.size(), 0,
                          reinterpret_cast<sockaddr*>(&peer), peer_len) ==
                   static_cast<ssize_t>(expected.size()));
        },
        0);
    assert(authenticated == make_response(query));

    auto provider_pair = open_local_dns_pair();
    auto provider = std::make_shared<StaticDnsNetworkProvider>(provider_pair.port);
    auto provided = resolve_once(
        provider_pair,
        [](int udp, const std::vector<uint8_t>& received_query) {
            sockaddr_storage peer{};
            socklen_t peer_len = sizeof(peer);
            uint8_t buffer[512];
            assert(recvfrom(udp, buffer, sizeof(buffer), 0,
                            reinterpret_cast<sockaddr*>(&peer), &peer_len) > 0);
            const auto response = make_response(received_query);
            assert(sendto(udp, response.data(), response.size(), 0,
                          reinterpret_cast<sockaddr*>(&peer), peer_len) ==
                   static_cast<ssize_t>(response.size()));
        },
        0, nullptr, provider);
    assert(provided == make_response(query));
}
#endif

void test_address_filter() {
    uv_loop_t loop;
    assert(uv_loop_init(&loop) == 0);
    tx::DnsResolver resolver(&loop);
    const auto query = make_query();
    resolver.configure({}, tx::DnsResolver::ProtectCallback(), 0,
        tx::DnsResolver::HostResolveHook(),
        [&](const uint8_t* request, size_t length) {
            assert(length == query.size());
            return make_a_response(std::vector<uint8_t>(request, request + length),
                                   198, 18, 0, 6);
        },
        tx::DnsResolver::AsyncQueryHook(), nullptr,
        [](const std::string& address) { return address == "198.18.0.6"; });

    bool response_done = false;
    resolver.resolve(query.data(), query.size(), [&](std::vector<uint8_t> response) {
        assert(response.empty());
        response_done = true;
    });
    bool numeric_done = false;
    resolver.resolve_host("198.18.0.6", AF_UNSPEC,
        [&](std::vector<std::string> addresses) {
            assert(addresses.empty());
            numeric_done = true;
        });
    uv_run(&loop, UV_RUN_DEFAULT);
    assert(response_done && numeric_done);
    assert(uv_loop_close(&loop) == 0);
}

} // namespace

int main() {
    const auto wire_query = make_query();
    auto wire_response = make_response(wire_query);
    assert(tx::DnsResolver::response_matches_query(wire_query, wire_response));
    assert(!tx::DnsResolver::response_is_truncated(wire_response));
    wire_response[2] |= 0x02;
    assert(tx::DnsResolver::response_matches_query(wire_query, wire_response));
    assert(tx::DnsResolver::response_is_truncated(wire_response));
    wire_response[1] ^= 0x01;
    assert(!tx::DnsResolver::response_matches_query(wire_query, wire_response));
    auto truncated_record = make_response(wire_query);
    tx::store_be16(truncated_record.data() + 6, 1);
    assert(!tx::DnsResolver::response_matches_query(wire_query, truncated_record));

    uv_loop_t loop;
    assert(uv_loop_init(&loop) == 0);
    tx::DnsResolver resolver(&loop);
    const std::thread::id loop_thread = std::this_thread::get_id();
    bool host_worker = false;
    bool query_worker = false;
    resolver.configure({}, tx::DnsResolver::ProtectCallback(), 0,
        [&](const std::string& host, int family) {
            assert(host == "example.com");
            assert(family == AF_UNSPEC);
            host_worker = std::this_thread::get_id() != loop_thread;
            return std::vector<std::string>{"2001:db8::1", "192.0.2.1"};
        },
        [&](const uint8_t* query, size_t length) {
            assert(query && length == 12);
            query_worker = std::this_thread::get_id() != loop_thread;
            return make_response(std::vector<uint8_t>(query, query + length));
        });

    bool host_done = false;
    resolver.resolve_host("example.com", AF_UNSPEC,
        [&](std::vector<std::string> addresses) {
            assert(addresses.size() == 2);
            assert(addresses[0] == "2001:db8::1");
            assert(addresses[1] == "192.0.2.1");
            host_done = true;
        });
    bool numeric_family_done = false;
    resolver.resolve_host("127.0.0.1", AF_INET6,
        [&](std::vector<std::string> addresses) {
            assert(addresses.empty());
            numeric_family_done = true;
        });
    uint8_t query[12]{};
    bool query_done = false;
    resolver.resolve(query, sizeof(query), [&](std::vector<uint8_t> response) {
        assert(response.size() == sizeof(query));
        query_done = true;
    });
    uv_run(&loop, UV_RUN_DEFAULT);
    assert(host_done && query_done && numeric_family_done && host_worker && query_worker);

    tx::DnsResolver async_resolver(&loop);
    bool async_called = false;
    bool async_done = false;
    async_resolver.configure({}, tx::DnsResolver::ProtectCallback(), 0,
        tx::DnsResolver::HostResolveHook(), tx::DnsResolver::QueryHook(),
        [&](std::vector<uint8_t> request, tx::DnsResolver::ResolveCallback complete) {
            assert(std::this_thread::get_id() == loop_thread);
            assert(request.size() == sizeof(query));
            async_called = true;
            complete(make_response(request));
        });
    async_resolver.resolve(query, sizeof(query), [&](std::vector<uint8_t> response) {
        assert(response.size() == sizeof(query));
        async_done = true;
    });
    assert(async_called && async_done);
    assert(uv_loop_close(&loop) == 0);
#if defined(__linux__)
    test_first_success_and_validation();
    test_platform_dns_provider_policy();
#endif
    test_address_filter();
    std::printf("dns resolver hook tests passed\n");
    return 0;
}
