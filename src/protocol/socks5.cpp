#include "tx/protocol/socks5.h"
#include "tx/common/endian.h"
#include "tx/common/log.h"
#include <cstring>
#include <arpa/inet.h>

namespace tx {

// SOCKS5 constants
static constexpr uint8_t kSocks5Version = 0x05;
static constexpr uint8_t kMethodNoAuth  = 0x00;
static constexpr uint8_t kMethodNoAccept = 0xFF;
static constexpr uint8_t kCmdConnect    = 0x01;
static constexpr uint8_t kAtypIPv4      = 0x01;
static constexpr uint8_t kAtypDomain    = 0x03;
static constexpr uint8_t kAtypIPv6      = 0x04;
static constexpr uint8_t kRepSuccess    = 0x00;
static constexpr uint8_t kRepGeneralFail = 0x01;

Socks5Handler::Socks5Handler() : state_(Socks5State::Handshake) {}

size_t Socks5Handler::feed(const uint8_t* data, size_t len) {
    switch (state_) {
        case Socks5State::Handshake:
            return parse_handshake(data, len);
        case Socks5State::Request:
            return parse_request(data, len);
        case Socks5State::Connected:
            // Data should be forwarded directly, not consumed here
            return 0;
        default:
            return 0;
    }
}

size_t Socks5Handler::parse_handshake(const uint8_t* data, size_t len) {
    // Minimum: VER(1) + NMETHODS(1) + at least 1 method
    if (len < 3) return 0;

    if (data[0] != kSocks5Version) {
        TX_ERROR("SOCKS5 version mismatch: got %u", data[0]);
        state_ = Socks5State::Error;
        return len;
    }

    uint8_t nmethods = data[1];
    if (len < static_cast<size_t>(2 + nmethods)) return 0;

    // Check if NO AUTH is supported
    bool found_noauth = false;
    for (int i = 0; i < nmethods; i++) {
        if (data[2 + i] == kMethodNoAuth) {
            found_noauth = true;
            break;
        }
    }

    // We always reply NO AUTH for now
    (void)found_noauth;

    state_ = Socks5State::Request;
    return 2 + nmethods;
}

size_t Socks5Handler::parse_request(const uint8_t* data, size_t len) {
    // Minimum: VER(1) + CMD(1) + RSV(1) + ATYP(1) + ... + PORT(2)
    if (len < 4) return 0;

    if (data[0] != kSocks5Version) {
        TX_ERROR("SOCKS5 request version mismatch");
        state_ = Socks5State::Error;
        return len;
    }

    if (data[1] != kCmdConnect) {
        TX_ERROR("SOCKS5 unsupported command: %u (only CONNECT)", data[1]);
        state_ = Socks5State::Error;
        return len;
    }

    uint8_t atyp = data[3];
    size_t consumed = 0;

    switch (atyp) {
        case kAtypIPv4: {
            // 4 bytes IP + 2 bytes port
            if (len < 10) return 0;
            char ipbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, data + 4, ipbuf, sizeof(ipbuf));
            target_.type = AddrType::IPv4;
            target_.host = ipbuf;
            target_.port = load_be16(data + 8);
            consumed = 10;
            break;
        }
        case kAtypDomain: {
            if (len < 5) return 0;
            uint8_t domain_len = data[4];
            if (len < static_cast<size_t>(5 + domain_len + 2)) return 0;
            target_.type = AddrType::Domain;
            target_.host.assign(reinterpret_cast<const char*>(data + 5), domain_len);
            target_.port = load_be16(data + 5 + domain_len);
            consumed = 5 + domain_len + 2;
            break;
        }
        case kAtypIPv6: {
            if (len < 22) return 0;
            char ipbuf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, data + 4, ipbuf, sizeof(ipbuf));
            target_.type = AddrType::IPv6;
            target_.host = ipbuf;
            target_.port = load_be16(data + 20);
            consumed = 22;
            break;
        }
        default:
            TX_ERROR("SOCKS5 unknown address type: %u", atyp);
            state_ = Socks5State::Error;
            return len;
    }

    state_ = Socks5State::Connected;
    TX_INFO("SOCKS5 CONNECT %s:%u", target_.host.c_str(), target_.port);

    if (target_cb_) {
        target_cb_(target_);
    }

    return consumed;
}

void Socks5Handler::build_connect_response(bool success, Buffer& out) {
    // VER + REP + RSV + ATYP + BND.ADDR(4) + BND.PORT(2)
    uint8_t resp[10];
    resp[0] = kSocks5Version;
    resp[1] = success ? kRepSuccess : kRepGeneralFail;
    resp[2] = 0x00; // RSV
    resp[3] = kAtypIPv4;
    memset(resp + 4, 0, 4); // BND.ADDR = 0.0.0.0
    memset(resp + 8, 0, 2); // BND.PORT = 0
    out.append(resp, sizeof(resp));
}

} // namespace tx
