#include "tx/protocol/socks5.h"
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

static void test_handshake() {
    printf("  test_handshake... ");
    tx::Socks5Handler handler;

    // SOCKS5 handshake: VER=5, NMETHODS=2, METHODS=[0x00, 0x02]
    uint8_t handshake[] = {0x05, 0x02, 0x00, 0x02};
    size_t consumed = handler.feed(handshake, sizeof(handshake));
    assert(consumed == 4);
    assert(handler.state() == tx::Socks5State::Request);

    printf("OK\n");
}

static void test_connect_ipv4() {
    printf("  test_connect_ipv4... ");
    tx::Socks5Handler handler;

    // Skip to Request state
    uint8_t handshake[] = {0x05, 0x01, 0x00};
    handler.feed(handshake, sizeof(handshake));
    assert(handler.state() == tx::Socks5State::Request);

    bool target_called = false;
    handler.set_target_callback([&](const tx::TargetAddr& t) {
        target_called = true;
        assert(t.type == tx::AddrType::IPv4);
        assert(t.host == "93.184.216.34");
        assert(t.port == 80);
    });

    // CONNECT to 93.184.216.34:80
    // VER=5, CMD=1(CONNECT), RSV=0, ATYP=1(IPv4), ADDR=93.184.216.34, PORT=80
    uint8_t request[] = {
        0x05, 0x01, 0x00, 0x01,
        0x5D, 0xB8, 0xD8, 0x22,  // 93.184.216.34
        0x00, 0x50                 // port 80
    };
    size_t consumed = handler.feed(request, sizeof(request));
    assert(consumed == 10);
    assert(handler.state() == tx::Socks5State::Connected);
    assert(target_called);

    printf("OK\n");
}

static void test_connect_domain() {
    printf("  test_connect_domain... ");
    tx::Socks5Handler handler;

    uint8_t handshake[] = {0x05, 0x01, 0x00};
    handler.feed(handshake, sizeof(handshake));

    bool target_called = false;
    handler.set_target_callback([&](const tx::TargetAddr& t) {
        target_called = true;
        assert(t.type == tx::AddrType::Domain);
        assert(t.host == "example.com");
        assert(t.port == 443);
    });

    // CONNECT to example.com:443
    const char* domain = "example.com";
    uint8_t request[256];
    size_t pos = 0;
    request[pos++] = 0x05; // VER
    request[pos++] = 0x01; // CMD=CONNECT
    request[pos++] = 0x00; // RSV
    request[pos++] = 0x03; // ATYP=DOMAIN
    request[pos++] = static_cast<uint8_t>(strlen(domain)); // domain length
    memcpy(request + pos, domain, strlen(domain));
    pos += strlen(domain);
    request[pos++] = 0x01; // port high byte (443 = 0x01BB)
    request[pos++] = 0xBB; // port low byte

    size_t consumed = handler.feed(request, pos);
    assert(consumed == pos);
    assert(handler.state() == tx::Socks5State::Connected);
    assert(target_called);

    printf("OK\n");
}

static void test_connect_response() {
    printf("  test_connect_response... ");
    tx::Socks5Handler handler;

    tx::Buffer resp;
    handler.build_connect_response(true, resp);
    assert(resp.readable() == 10);
    assert(resp.data()[0] == 0x05); // VER
    assert(resp.data()[1] == 0x00); // SUCCESS

    printf("OK\n");
}

static void test_no_supported_auth_method() {
    printf("  test_no_supported_auth_method... ");
    tx::Socks5Handler handler;

    uint8_t handshake[] = {0x05, 0x01, 0x02};
    size_t consumed = handler.feed(handshake, sizeof(handshake));
    check(consumed == sizeof(handshake));
    check(handler.state() == tx::Socks5State::Error);

    tx::Buffer resp;
    handler.build_connect_response(false, resp);
    check(resp.readable() == 2);
    check(resp.data()[0] == 0x05);
    check(resp.data()[1] == 0xFF);

    printf("OK\n");
}

static void test_request_error_responses() {
    const auto check_request_error = [](uint8_t command, uint8_t reserved,
                                        uint8_t atyp, uint8_t expected_reply) {
        tx::Socks5Handler handler;
        uint8_t handshake[] = {0x05, 0x01, 0x00};
        assert(handler.feed(handshake, sizeof(handshake)) == sizeof(handshake));
        uint8_t request[] = {0x05, command, reserved, atyp};
        assert(handler.feed(request, sizeof(request)) == sizeof(request));
        assert(handler.state() == tx::Socks5State::Error);
        assert(handler.failure_stage() == tx::Socks5Handler::FailureStage::Request);
        tx::Buffer response;
        handler.build_connect_response(false, response);
        assert(response.readable() == 10);
        assert(response.data()[0] == 0x05);
        assert(response.data()[1] == expected_reply);
    };
    check_request_error(0x02, 0x00, 0x01, 0x07);
    check_request_error(0x01, 0x00, 0x02, 0x08);
    check_request_error(0x01, 0x01, 0x01, 0x01);
}

int main() {
    printf("=== SOCKS5 Tests ===\n");
    test_handshake();
    test_connect_ipv4();
    test_connect_domain();
    test_connect_response();
    test_no_supported_auth_method();
    test_request_error_responses();
    printf("All SOCKS5 tests passed!\n");
    return 0;
}
