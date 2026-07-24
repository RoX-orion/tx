#include "tx/protocol/http_proxy.h"
#include "tx/common/log.h"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <cstdlib>

static void check(bool condition) {
    if (!condition) {
        std::abort();
    }
}

static void test_connect_request() {
    printf("  test_connect_request... ");
    tx::HttpProxyHandler handler;

    bool target_called = false;
    handler.set_target_callback([&](const tx::TargetAddr& t) {
        target_called = true;
        assert(t.type == tx::AddrType::Domain);
        assert(t.host == "example.com");
        assert(t.port == 443);
    });

    const char* request =
        "CONNECT example.com:443 HTTP/1.1\r\n"
        "Host: example.com:443\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "\r\n";

    size_t consumed = handler.feed(reinterpret_cast<const uint8_t*>(request), strlen(request));
    assert(consumed > 0);
    assert(handler.state() == tx::HttpProxyHandler::State::Connected);
    assert(target_called);

    printf("OK\n");
}

static void test_partial_request() {
    printf("  test_partial_request... ");
    tx::HttpProxyHandler handler;
    tx::Buffer buf;

    // Send partial request
    const char* part1 = "CONNECT example.com:443 HTTP/1.1\r\nHost: ";
    buf.append(reinterpret_cast<const uint8_t*>(part1), strlen(part1));
    size_t c1 = handler.feed(buf.data(), buf.readable());
    assert(c1 == 0); // Not complete yet
    assert(handler.state() == tx::HttpProxyHandler::State::Request);

    // Send rest
    const char* part2 = "example.com:443\r\n\r\n";
    buf.append(reinterpret_cast<const uint8_t*>(part2), strlen(part2));
    size_t c2 = handler.feed(buf.data(), buf.readable());
    assert(c2 > 0);
    assert(handler.state() == tx::HttpProxyHandler::State::Connected);

    printf("OK\n");
}

static void test_connect_response() {
    printf("  test_connect_response... ");
    tx::HttpProxyHandler handler;

    tx::Buffer resp;
    handler.build_connect_response(resp);

    std::string s(reinterpret_cast<const char*>(resp.data()), resp.readable());
    assert(s.find("200") != std::string::npos);

    printf("OK\n");
}

static void test_plain_http_request() {
    printf("  test_plain_http_request... ");
    tx::HttpProxyHandler handler;

    bool target_called = false;
    handler.set_target_callback([&](const tx::TargetAddr& t) {
        target_called = true;
        assert(t.type == tx::AddrType::Domain);
        assert(t.host == "example.com");
        assert(t.port == 80);
    });

    const char* request =
        "GET http://example.com/path?q=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    size_t consumed = handler.feed(reinterpret_cast<const uint8_t*>(request), strlen(request));
    check(consumed == strlen(request));
    check(handler.state() == tx::HttpProxyHandler::State::Connected);
    check(handler.mode() == tx::HttpProxyHandler::Mode::Plain);
    check(target_called);

    std::string rewritten(reinterpret_cast<const char*>(handler.initial_payload().data()),
                          handler.initial_payload().readable());
    check(rewritten.find("GET /path?q=1 HTTP/1.1\r\n") == 0);

    printf("OK\n");
}

static void test_ipv6_connect_request() {
    printf("  test_ipv6_connect_request... ");
    tx::HttpProxyHandler handler;

    bool target_called = false;
    handler.set_target_callback([&](const tx::TargetAddr& t) {
        target_called = true;
        assert(t.type == tx::AddrType::IPv6);
        assert(t.host == "2001:db8::1");
        assert(t.port == 443);
    });

    const char* request =
        "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
        "Host: [2001:db8::1]:443\r\n"
        "\r\n";

    size_t consumed = handler.feed(reinterpret_cast<const uint8_t*>(request), strlen(request));
    assert(consumed > 0);
    assert(handler.state() == tx::HttpProxyHandler::State::Connected);
    assert(target_called);

    printf("OK\n");
}

static void test_invalid_port() {
    printf("  test_invalid_port... ");
    tx::HttpProxyHandler handler;

    const char* request =
        "CONNECT example.com:0 HTTP/1.1\r\n"
        "Host: example.com:0\r\n"
        "\r\n";

    size_t consumed = handler.feed(reinterpret_cast<const uint8_t*>(request), strlen(request));
    assert(consumed > 0);
    assert(handler.state() == tx::HttpProxyHandler::State::Error);

    tx::HttpProxyHandler overflow_handler;
    const char* overflow_request =
        "CONNECT example.com:70000 HTTP/1.1\r\n"
        "Host: example.com:70000\r\n"
        "\r\n";
    assert(overflow_handler.feed(reinterpret_cast<const uint8_t*>(overflow_request),
                                 strlen(overflow_request)) > 0);
    assert(overflow_handler.state() == tx::HttpProxyHandler::State::Error);

    printf("OK\n");
}

int main() {
    printf("=== HTTP Proxy Tests ===\n");
    test_connect_request();
    test_partial_request();
    test_connect_response();
    test_plain_http_request();
    test_ipv6_connect_request();
    test_invalid_port();
    printf("All HTTP proxy tests passed!\n");
    return 0;
}
