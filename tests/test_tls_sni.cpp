#include "tx/protocol/tls_sni.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

void push16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

std::vector<uint8_t> client_hello(const std::string& host) {
    std::vector<uint8_t> body(34, 0);
    body[0] = 3;
    body[1] = 3;
    body.push_back(0); // session id
    push16(body, 2);
    push16(body, 0x1301);
    body.push_back(1);
    body.push_back(0);

    std::vector<uint8_t> sni;
    push16(sni, static_cast<uint16_t>(host.size() + 3));
    sni.push_back(0);
    push16(sni, static_cast<uint16_t>(host.size()));
    sni.insert(sni.end(), host.begin(), host.end());
    std::vector<uint8_t> extensions;
    push16(extensions, 0);
    push16(extensions, static_cast<uint16_t>(sni.size()));
    extensions.insert(extensions.end(), sni.begin(), sni.end());
    push16(body, static_cast<uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(1);
    handshake.push_back(static_cast<uint8_t>(body.size() >> 16));
    handshake.push_back(static_cast<uint8_t>(body.size() >> 8));
    handshake.push_back(static_cast<uint8_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record{22, 3, 1};
    push16(record, static_cast<uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

std::vector<uint8_t> split_records(const std::vector<uint8_t>& record, size_t first_payload) {
    assert(record.size() > 5 + first_payload);
    const size_t payload_size = record.size() - 5;
    std::vector<uint8_t> split{22, 3, 1};
    push16(split, static_cast<uint16_t>(first_payload));
    split.insert(split.end(), record.begin() + 5, record.begin() + 5 + first_payload);
    split.push_back(22);
    split.push_back(3);
    split.push_back(3);
    push16(split, static_cast<uint16_t>(payload_size - first_payload));
    split.insert(split.end(), record.begin() + 5 + first_payload, record.end());
    return split;
}

} // namespace

int main() {
    const auto hello = client_hello("WWW.YouTube.COM");
    std::string host;
    assert(tx::extract_tls_sni(hello.data(), 4, host) == tx::TlsSniResult::NeedMore);
    assert(tx::extract_tls_sni(hello.data(), hello.size() - 1, host) ==
           tx::TlsSniResult::NeedMore);
    assert(tx::extract_tls_sni(hello.data(), hello.size(), host) ==
           tx::TlsSniResult::Found);
    assert(host == "www.youtube.com");

    const auto split = split_records(hello, 17);
    const size_t first_record_size = 5 + 17;
    assert(tx::extract_tls_sni(split.data(), first_record_size, host) ==
           tx::TlsSniResult::NeedMore);
    assert(tx::extract_tls_sni(split.data(), split.size(), host) ==
           tx::TlsSniResult::Found);
    assert(host == "www.youtube.com");

    const uint8_t http[] = {'G', 'E', 'T', ' ', '/'};
    assert(tx::extract_tls_sni(http, sizeof(http), host) == tx::TlsSniResult::NotFound);
    std::printf("tls_sni tests passed\n");
    return 0;
}
