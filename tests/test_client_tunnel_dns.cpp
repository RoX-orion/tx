#include "client_app.h"
#include "server_app.h"
#include "tx/common/endian.h"

#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace tx {

struct ClientAppDnsTest {
    static void resolve(ClientApp& app, std::vector<uint8_t> query,
                        DnsResolver::ResolveCallback callback) {
        app.resolve_dns_via_tunnel(std::move(query), std::move(callback));
    }
};

} // namespace tx

namespace {

struct DnsSockets {
    int udp = -1;
    int tcp = -1;
    uint16_t port = 0;
};

std::vector<uint8_t> make_query(uint16_t id) {
    return std::vector<uint8_t>{
        static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id),
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
    };
}

std::vector<uint8_t> make_response(const std::vector<uint8_t>& query, bool truncated) {
    std::vector<uint8_t> response = query;
    response[2] = truncated ? 0x83 : 0x81;
    response[3] = 0x80;
    return response;
}

void set_receive_timeout(int fd, int seconds) {
    timeval timeout{seconds, 0};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
}

DnsSockets open_dns_sockets(bool with_tcp) {
    DnsSockets sockets;
    sockets.udp = socket(AF_INET, SOCK_DGRAM, 0);
    assert(sockets.udp >= 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(sockets.udp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(sockets.udp, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    sockets.port = ntohs(address.sin_port);
    set_receive_timeout(sockets.udp, 8);

    if (with_tcp) {
        sockets.tcp = socket(AF_INET, SOCK_STREAM, 0);
        assert(sockets.tcp >= 0);
        int one = 1;
        assert(setsockopt(sockets.tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        address.sin_port = htons(sockets.port);
        assert(bind(sockets.tcp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        assert(listen(sockets.tcp, 4) == 0);
        set_receive_timeout(sockets.tcp, 8);
    }
    return sockets;
}

uint16_t reserve_tcp_port() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
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

bool read_all(int fd, uint8_t* data, size_t size) {
    while (size != 0) {
        const ssize_t received = recv(fd, data, size, 0);
        if (received <= 0) return false;
        data += received;
        size -= static_cast<size_t>(received);
    }
    return true;
}

bool write_all(int fd, const uint8_t* data, size_t size) {
    while (size != 0) {
        const ssize_t sent = send(fd, data, size, 0);
        if (sent <= 0) return false;
        data += sent;
        size -= static_cast<size_t>(sent);
    }
    return true;
}

tx::ClientConfig client_config(uint16_t server_port,
                               std::vector<std::string> upstreams,
                               const std::vector<uint8_t>& psk) {
    tx::ClientConfig config;
    config.http_port = 0;
    config.socks5_port = 0;
    config.dns_upstreams = std::move(upstreams);
    config.dns_outbound_tag = "tx-out";

    tx::OutboundConfig outbound;
    outbound.tag = "tx-out";
    outbound.type = tx::OutboundType::Tx;
    outbound.server_host = "127.0.0.1";
    outbound.server_port = server_port;
    outbound.psk = psk;
    config.outbound_index[outbound.tag] = 0;
    config.outbounds.push_back(std::move(outbound));

    tx::RouteRule fallback;
    fallback.outbound_tag = "tx-out";
    config.router.rules.push_back(std::move(fallback));
    return config;
}

std::vector<uint8_t> run_query(uint16_t server_port,
                               const std::vector<uint8_t>& psk,
                               std::vector<std::string> upstreams,
                               const std::vector<uint8_t>& query,
                               long long* elapsed_ms = nullptr) {
    tx::ClientApp app;
    const tx::ClientConfig config = client_config(server_port, std::move(upstreams), psk);
    assert(app.init(config));

    std::vector<uint8_t> result;
    unsigned callbacks = 0;
    const auto started = std::chrono::steady_clock::now();
    tx::ClientAppDnsTest::resolve(app, query,
        [&](std::vector<uint8_t> response) {
            ++callbacks;
            result = std::move(response);
            app.stop();
        });
    app.run();
    assert(callbacks == 1);
    if (elapsed_ms) {
        *elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
    }
    return result;
}

void test_upstream_failover(uint16_t server_port, const std::vector<uint8_t>& psk) {
    DnsSockets blackhole = open_dns_sockets(false);
    DnsSockets answering = open_dns_sockets(false);
    const std::vector<uint8_t> query = make_query(0x1234);
    const std::vector<uint8_t> expected = make_response(query, false);

    std::thread first([blackhole]() {
        uint8_t buffer[512];
        recv(blackhole.udp, buffer, sizeof(buffer), 0);
        close(blackhole.udp);
    });
    std::thread second([answering, expected]() {
        sockaddr_storage peer{};
        socklen_t peer_len = sizeof(peer);
        uint8_t buffer[512];
        const ssize_t received = recvfrom(answering.udp, buffer, sizeof(buffer), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (received > 0) {
            sendto(answering.udp, expected.data(), expected.size(), 0,
                   reinterpret_cast<sockaddr*>(&peer), peer_len);
        }
        close(answering.udp);
    });

    long long elapsed_ms = 0;
    const auto result = run_query(
        server_port, psk,
        {"127.0.0.1:" + std::to_string(blackhole.port),
         "127.0.0.1:" + std::to_string(answering.port)},
        query, &elapsed_ms);
    first.join();
    second.join();
    assert(result == expected);
    assert(elapsed_ms >= 1500 && elapsed_ms < 6000);
}

void test_all_upstreams_fail(uint16_t server_port, const std::vector<uint8_t>& psk) {
    DnsSockets blackhole = open_dns_sockets(false);
    const std::vector<uint8_t> query = make_query(0x3456);
    std::thread server([blackhole]() {
        uint8_t buffer[512];
        recv(blackhole.udp, buffer, sizeof(buffer), 0);
        close(blackhole.udp);
    });

    long long elapsed_ms = 0;
    const auto result = run_query(
        server_port, psk,
        {"127.0.0.1:" + std::to_string(blackhole.port)},
        query, &elapsed_ms);
    server.join();
    assert(result.empty());
    assert(elapsed_ms >= 1500 && elapsed_ms < 5000);
}

void test_truncated_tcp_fallback(uint16_t server_port,
                                 const std::vector<uint8_t>& psk) {
    DnsSockets dns = open_dns_sockets(true);
    const std::vector<uint8_t> query = make_query(0x5678);
    const std::vector<uint8_t> expected = make_response(query, false);

    std::thread udp([dns, query]() {
        sockaddr_storage peer{};
        socklen_t peer_len = sizeof(peer);
        uint8_t buffer[512];
        const ssize_t received = recvfrom(dns.udp, buffer, sizeof(buffer), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (received > 0) {
            const auto truncated = make_response(query, true);
            sendto(dns.udp, truncated.data(), truncated.size(), 0,
                   reinterpret_cast<sockaddr*>(&peer), peer_len);
        }
        close(dns.udp);
    });
    std::thread tcp([dns, query, expected]() {
        int client = accept(dns.tcp, nullptr, nullptr);
        if (client >= 0) {
            set_receive_timeout(client, 8);
            uint8_t length[2];
            if (read_all(client, length, sizeof(length))) {
                const uint16_t query_len = tx::load_be16(length);
                std::vector<uint8_t> received(query_len);
                if (read_all(client, received.data(), received.size()) && received == query) {
                    tx::store_be16(length, static_cast<uint16_t>(expected.size()));
                    write_all(client, length, 1);
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    write_all(client, length + 1, 1);
                    write_all(client, expected.data(), 7);
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    write_all(client, expected.data() + 7, expected.size() - 7);
                }
            }
            close(client);
        }
        close(dns.tcp);
    });

    const auto result = run_query(
        server_port, psk,
        {"127.0.0.1:" + std::to_string(dns.port)}, query);
    udp.join();
    tcp.join();
    assert(result == expected);
}

void test_tcp_failure_uses_next_upstream(uint16_t server_port,
                                         const std::vector<uint8_t>& psk) {
    DnsSockets truncated_only = open_dns_sockets(false);
    DnsSockets answering = open_dns_sockets(false);
    const std::vector<uint8_t> query = make_query(0x789a);
    const std::vector<uint8_t> expected = make_response(query, false);

    std::thread first([truncated_only, query]() {
        sockaddr_storage peer{};
        socklen_t peer_len = sizeof(peer);
        uint8_t buffer[512];
        const ssize_t received = recvfrom(truncated_only.udp, buffer, sizeof(buffer), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (received > 0) {
            const auto truncated = make_response(query, true);
            sendto(truncated_only.udp, truncated.data(), truncated.size(), 0,
                   reinterpret_cast<sockaddr*>(&peer), peer_len);
        }
        close(truncated_only.udp);
    });
    std::thread second([answering, expected]() {
        sockaddr_storage peer{};
        socklen_t peer_len = sizeof(peer);
        uint8_t buffer[512];
        const ssize_t received = recvfrom(answering.udp, buffer, sizeof(buffer), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (received > 0) {
            sendto(answering.udp, expected.data(), expected.size(), 0,
                   reinterpret_cast<sockaddr*>(&peer), peer_len);
        }
        close(answering.udp);
    });

    const auto result = run_query(
        server_port, psk,
        {"127.0.0.1:" + std::to_string(truncated_only.port),
         "127.0.0.1:" + std::to_string(answering.port)}, query);
    first.join();
    second.join();
    assert(result == expected);
}

} // namespace

int main() {
    const uint16_t server_port = reserve_tcp_port();
    std::vector<uint8_t> psk(32);
    for (size_t i = 0; i < psk.size(); ++i) psk[i] = static_cast<uint8_t>(i);

    tx::ServerConfig server_config;
    server_config.listen_host = "127.0.0.1";
    server_config.listen_port = server_port;
    server_config.psk = psk;
    tx::ServerApp server;
    assert(server.init(server_config));
    std::thread server_thread([&server]() { server.run(); });

    test_upstream_failover(server_port, psk);
    test_all_upstreams_fail(server_port, psk);
    test_truncated_tcp_fallback(server_port, psk);
    test_tcp_failure_uses_next_upstream(server_port, psk);

    server.stop();
    server_thread.join();
    std::printf("client tunnel DNS tests passed\n");
    return 0;
}
