#include "tx/protocol/tunnel.h"
#include "tx/crypto/aead.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#define TX_ASSERT(expr) do { assert(expr); (void)sizeof(expr); } while (0)

static std::vector<uint8_t> test_psk(uint8_t seed = 0x42) {
    std::vector<uint8_t> psk(32);
    for (size_t i = 0; i < psk.size(); ++i) {
        psk[i] = static_cast<uint8_t>(seed + i);
    }
    return psk;
}

static tx::TunnelTrafficKeys fixed_keys(tx::AeadCipherKind cipher = tx::AeadCipherKind::Aes256Gcm) {
    tx::TunnelTrafficKeys keys;
    keys.cipher = cipher;
    keys.client_to_server_key.assign(tx::AeadCipher::kKeyLen, 0x11);
    keys.server_to_client_key.assign(tx::AeadCipher::kKeyLen, 0x22);
    keys.client_to_server_nonce_prefix = {0xa1, 0xa2, 0xa3, 0xa4};
    keys.server_to_client_nonce_prefix = {0xb1, 0xb2, 0xb3, 0xb4};
    return keys;
}

static tx::TunnelCodec make_client_codec() {
    return tx::TunnelCodec(fixed_keys(), true);
}

static tx::TunnelCodec make_server_codec() {
    return tx::TunnelCodec(fixed_keys(), false);
}

static void assert_no_message(tx::TunnelCodec& codec, tx::Buffer& in) {
    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr target;
    tx::Buffer payload;
    TX_ASSERT(!codec.decode(in, cmd, session_id, target, payload));
}

static void test_handshake_round_trip() {
    printf("  test_handshake_round_trip... ");
    auto psk = test_psk();

    tx::Buffer client_hello;
    tx::TunnelHandshakeState client_state;
    TX_ASSERT(tx::TunnelCodec::build_client_hello(psk, tx::AeadCipherKind::Aes256Gcm,
                                                  client_hello, client_state));
    TX_ASSERT(client_hello.readable() == tx::TunnelCodec::kHandshakeSize);
    TX_ASSERT(client_state.nonce.size() == tx::TunnelCodec::kHandshakeNonceSize);
    TX_ASSERT(client_state.public_key.size() == tx::TunnelCodec::kHandshakePublicKeySize);

    tx::TunnelPeerHello parsed_client_hello;
    TX_ASSERT(tx::TunnelCodec::parse_client_hello(psk, client_hello.data(),
                                                  client_hello.readable(),
                                                  parsed_client_hello));
    TX_ASSERT(parsed_client_hello.nonce == client_state.nonce);
    TX_ASSERT(parsed_client_hello.public_key == client_state.public_key);

    tx::Buffer server_hello;
    tx::TunnelHandshakeState server_state;
    tx::TunnelTrafficKeys server_keys;
    TX_ASSERT(tx::TunnelCodec::build_server_hello(psk, parsed_client_hello,
                                                  server_hello, server_state, server_keys));
    TX_ASSERT(server_hello.readable() == tx::TunnelCodec::kHandshakeSize);

    tx::TunnelTrafficKeys client_keys;
    TX_ASSERT(tx::TunnelCodec::parse_server_hello(psk, client_state,
                                                  server_hello.data(),
                                                  server_hello.readable(),
                                                  client_keys));

    TX_ASSERT(client_keys.cipher == server_keys.cipher);
    TX_ASSERT(client_keys.client_to_server_key == server_keys.client_to_server_key);
    TX_ASSERT(client_keys.server_to_client_key == server_keys.server_to_client_key);
    TX_ASSERT(client_keys.client_to_server_nonce_prefix == server_keys.client_to_server_nonce_prefix);
    TX_ASSERT(client_keys.server_to_client_nonce_prefix == server_keys.server_to_client_nonce_prefix);

    printf("OK\n");
}

static void test_handshake_authentication_failure() {
    printf("  test_handshake_authentication_failure... ");
    auto psk = test_psk();
    auto wrong_psk = test_psk(0x99);

    tx::Buffer client_hello;
    tx::TunnelHandshakeState client_state;
    TX_ASSERT(tx::TunnelCodec::build_client_hello(psk, tx::AeadCipherKind::Aes256Gcm,
                                                  client_hello, client_state));

    tx::TunnelPeerHello parsed_client_hello;
    TX_ASSERT(!tx::TunnelCodec::parse_client_hello(wrong_psk, client_hello.data(),
                                                   client_hello.readable(),
                                                   parsed_client_hello));

    std::vector<uint8_t> tampered(client_hello.data(),
                                  client_hello.data() + client_hello.readable());
    TX_ASSERT(!tampered.empty());
    tampered[tampered.size() - 1] ^= 0x01;
    TX_ASSERT(!tx::TunnelCodec::parse_client_hello(psk, tampered.data(),
                                                   tampered.size(),
                                                   parsed_client_hello));

    std::vector<uint8_t> old_version(client_hello.data(),
                                     client_hello.data() + client_hello.readable());
    old_version[0] = 'T'; old_version[1] = 'X';
    old_version[2] = 'H'; old_version[3] = '2';
    TX_ASSERT(!tx::TunnelCodec::parse_client_hello(psk, old_version.data(),
                                                   old_version.size(),
                                                   parsed_client_hello));

    printf("OK\n");
}

static void test_connect_round_trip_domain() {
    printf("  test_connect_round_trip_domain... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();

    tx::TargetAddr target;
    target.type = tx::AddrType::Domain;
    target.host = "example.com";
    target.port = 443;

    const char payload[] = "initial data";
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode(tx::TunnelCmd::Connect, 42, target,
                             reinterpret_cast<const uint8_t*>(payload),
                             strlen(payload), encoded));

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr decoded_target;
    tx::Buffer decoded_payload;
    TX_ASSERT(decoder.decode(encoded, cmd, session_id, decoded_target, decoded_payload));

    TX_ASSERT(cmd == tx::TunnelCmd::Connect);
    TX_ASSERT(session_id == 42);
    TX_ASSERT(decoded_target.type == tx::AddrType::Domain);
    TX_ASSERT(decoded_target.host == "example.com");
    TX_ASSERT(decoded_target.port == 443);
    TX_ASSERT(decoded_payload.readable() == strlen(payload));
    TX_ASSERT(memcmp(decoded_payload.data(), payload, strlen(payload)) == 0);
    TX_ASSERT(encoded.empty());

    printf("OK\n");
}

static void test_connect_round_trip_ip_addresses() {
    printf("  test_connect_round_trip_ip_addresses... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();

    tx::TargetAddr ipv4;
    ipv4.type = tx::AddrType::IPv4;
    ipv4.host = "8.8.4.4";
    ipv4.port = 53;

    tx::Buffer encoded;
    TX_ASSERT(encoder.encode(tx::TunnelCmd::Connect, 7, ipv4, nullptr, 0, encoded));

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr target;
    tx::Buffer payload;
    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::Connect);
    TX_ASSERT(session_id == 7);
    TX_ASSERT(target.type == tx::AddrType::IPv4);
    TX_ASSERT(target.host == "8.8.4.4");
    TX_ASSERT(target.port == 53);
    TX_ASSERT(payload.empty());

    tx::TargetAddr ipv6;
    ipv6.type = tx::AddrType::IPv6;
    ipv6.host = "2001:4860:4860::8888";
    ipv6.port = 853;

    TX_ASSERT(encoder.encode(tx::TunnelCmd::Connect, 8, ipv6, nullptr, 0, encoded));
    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::Connect);
    TX_ASSERT(session_id == 8);
    TX_ASSERT(target.type == tx::AddrType::IPv6);
    TX_ASSERT(target.host == "2001:4860:4860::8888");
    TX_ASSERT(target.port == 853);

    printf("OK\n");
}

static void test_udp_packet_round_trip_domain() {
    printf("  test_udp_packet_round_trip_domain... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();

    tx::TargetAddr target;
    target.type = tx::AddrType::Domain;
    target.host = "video.example";
    target.port = 443;

    const uint8_t datagram[] = {0xde, 0xad, 0xbe, 0xef};
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode(tx::TunnelCmd::UdpPacket, 43, target,
                             datagram, sizeof(datagram), encoded));

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr decoded_target;
    tx::Buffer decoded_payload;
    TX_ASSERT(decoder.decode(encoded, cmd, session_id, decoded_target, decoded_payload));
    TX_ASSERT(cmd == tx::TunnelCmd::UdpPacket);
    TX_ASSERT(session_id == 43);
    TX_ASSERT(decoded_target.type == tx::AddrType::Domain);
    TX_ASSERT(decoded_target.host == "video.example");
    TX_ASSERT(decoded_target.port == 443);
    TX_ASSERT(decoded_payload.readable() == sizeof(datagram));
    TX_ASSERT(memcmp(decoded_payload.data(), datagram, sizeof(datagram)) == 0);

    printf("OK\n");
}

static void test_dns_query_round_trip_without_target() {
    printf("  test_dns_query_round_trip_without_target... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();
    const uint8_t query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode_dns_query(77, query, sizeof(query), encoded));

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr target;
    tx::Buffer payload;
    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::DnsQuery);
    TX_ASSERT(session_id == 77);
    TX_ASSERT(target.port == 0);
    TX_ASSERT(payload.readable() == sizeof(query));
    TX_ASSERT(memcmp(payload.data(), query, sizeof(query)) == 0);

    tx::Buffer response_frame;
    TX_ASSERT(encoder.encode_dns_response(77, query, sizeof(query), response_frame));
    TX_ASSERT(decoder.decode(response_frame, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::DnsResponse);
    TX_ASSERT(session_id == 77);
    TX_ASSERT(payload.readable() == sizeof(query));
    printf("OK\n");
}

static void test_data_disconnect_and_connect_result() {
    printf("  test_data_disconnect_and_connect_result... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();

    const char data[] = "hello through tunnel";
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode_data(100, reinterpret_cast<const uint8_t*>(data),
                                  strlen(data), encoded));
    TX_ASSERT(encoder.encode_connect_result(100, true, encoded));
    TX_ASSERT(encoder.encode_half_close(100, encoded));
    TX_ASSERT(encoder.encode_disconnect(100, encoded));

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr target;
    tx::Buffer payload;

    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::Data);
    TX_ASSERT(session_id == 100);
    TX_ASSERT(payload.readable() == strlen(data));
    TX_ASSERT(memcmp(payload.data(), data, strlen(data)) == 0);

    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::ConnectResult);
    TX_ASSERT(session_id == 100);
    TX_ASSERT(payload.readable() == 1);
    TX_ASSERT(payload.data()[0] == 1);

    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::HalfClose);
    TX_ASSERT(session_id == 100);
    TX_ASSERT(payload.empty());

    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::Disconnect);
    TX_ASSERT(session_id == 100);
    TX_ASSERT(payload.empty());
    TX_ASSERT(encoded.empty());

    printf("OK\n");
}

static void test_partial_frame_waits_for_more_data() {
    printf("  test_partial_frame_waits_for_more_data... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();

    const char data[] = "split frame";
    tx::Buffer full;
    TX_ASSERT(encoder.encode_data(55, reinterpret_cast<const uint8_t*>(data),
                                  strlen(data), full));

    size_t half = full.readable() / 2;
    tx::Buffer partial;
    partial.append(full.data(), half);
    assert_no_message(decoder, partial);
    TX_ASSERT(!decoder.has_protocol_error());
    TX_ASSERT(partial.readable() == half);

    partial.append(full.data() + half, full.readable() - half);

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr target;
    tx::Buffer payload;
    TX_ASSERT(decoder.decode(partial, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::Data);
    TX_ASSERT(session_id == 55);
    TX_ASSERT(payload.readable() == strlen(data));
    TX_ASSERT(memcmp(payload.data(), data, strlen(data)) == 0);

    printf("OK\n");
}

static void test_data_chunking() {
    printf("  test_data_chunking... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();

    std::vector<uint8_t> data(tx::TunnelCodec::kMaxDataPayloadSize + 123);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i & 0xff);
    }

    tx::Buffer encoded;
    TX_ASSERT(encoder.encode_data_chunks(77, data.data(), data.size(), encoded));

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr target;
    tx::Buffer payload;
    std::vector<uint8_t> decoded;
    while (decoder.decode(encoded, cmd, session_id, target, payload)) {
        TX_ASSERT(cmd == tx::TunnelCmd::Data);
        TX_ASSERT(session_id == 77);
        decoded.insert(decoded.end(), payload.data(), payload.data() + payload.readable());
    }

    TX_ASSERT(decoded == data);
    TX_ASSERT(encoded.empty());

    printf("OK\n");
}

static void test_protocol_error_for_invalid_frame_length() {
    printf("  test_protocol_error_for_invalid_frame_length... ");
    auto decoder = make_server_codec();

    uint8_t invalid_len[] = {0x00, 0x00, 0x00, 0x01};
    tx::Buffer encoded;
    encoded.append(invalid_len, sizeof(invalid_len));

    assert_no_message(decoder, encoded);
    TX_ASSERT(decoder.has_protocol_error());
    TX_ASSERT(encoded.empty());

    printf("OK\n");
}

static void test_tampered_frame_is_discarded() {
    printf("  test_tampered_frame_is_discarded... ");
    auto encoder = make_client_codec();
    auto decoder = make_server_codec();

    const char data[] = "authenticated data";
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode_data(31, reinterpret_cast<const uint8_t*>(data),
                                  strlen(data), encoded));

    std::vector<uint8_t> tampered(encoded.data(),
                                  encoded.data() + encoded.readable());
    tampered[tx::TunnelCodec::kLenPrefixSize] ^= 0x80;

    tx::Buffer tampered_buffer;
    tampered_buffer.append(tampered.data(), tampered.size());
    assert_no_message(decoder, tampered_buffer);
    TX_ASSERT(decoder.has_protocol_error());
    TX_ASSERT(tampered_buffer.empty());

    printf("OK\n");
}

static void test_chacha20_poly1305_tunnel_round_trip() {
    printf("  test_chacha20_poly1305_tunnel_round_trip... ");
    auto keys = fixed_keys(tx::AeadCipherKind::ChaCha20Poly1305);
    auto encoder = tx::TunnelCodec(keys, true);
    auto decoder = tx::TunnelCodec(keys, false);

    const char data[] = "chacha tunnel data";
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode_data(91, reinterpret_cast<const uint8_t*>(data),
                                  strlen(data), encoded));

    tx::TunnelCmd cmd;
    tx::SessionId session_id = 0;
    tx::TargetAddr target;
    tx::Buffer payload;
    TX_ASSERT(decoder.decode(encoded, cmd, session_id, target, payload));
    TX_ASSERT(cmd == tx::TunnelCmd::Data);
    TX_ASSERT(session_id == 91);
    TX_ASSERT(payload.readable() == strlen(data));
    TX_ASSERT(memcmp(payload.data(), data, strlen(data)) == 0);

    printf("OK\n");
}

static void test_encoded_frame_size_preflight() {
    printf("  test_encoded_frame_size_preflight... ");
    auto encoder = make_client_codec();
    const uint8_t payload[] = {1, 2, 3, 4, 5};

    tx::TargetAddr targets[3];
    targets[0].type = tx::AddrType::IPv4;
    targets[0].host = "192.0.2.1";
    targets[0].port = 53;
    targets[1].type = tx::AddrType::IPv6;
    targets[1].host = "2001:db8::1";
    targets[1].port = 53;
    targets[2].type = tx::AddrType::Domain;
    targets[2].host = "resolver.example";
    targets[2].port = 53;

    for (const auto& target : targets) {
        size_t expected = 0;
        TX_ASSERT(tx::TunnelCodec::encoded_frame_size(
            tx::TunnelCmd::UdpPacket, target, sizeof(payload), expected));
        tx::Buffer encoded;
        TX_ASSERT(encoder.encode_udp_packet(7, target, payload, sizeof(payload), encoded));
        TX_ASSERT(encoded.readable() == expected);
    }

    tx::TargetAddr dummy;
    size_t dns_expected = 0;
    TX_ASSERT(tx::TunnelCodec::encoded_frame_size(
        tx::TunnelCmd::DnsQuery, dummy, sizeof(payload), dns_expected));
    tx::Buffer dns;
    TX_ASSERT(encoder.encode(tx::TunnelCmd::DnsQuery, 8, dummy,
                             payload, sizeof(payload), dns));
    TX_ASSERT(dns.readable() == dns_expected);

    tx::TargetAddr long_domain = targets[2];
    long_domain.host.assign(255, 'a');
    TX_ASSERT(!tx::TunnelCodec::encoded_frame_size(
        tx::TunnelCmd::UdpPacket, long_domain,
        tx::TunnelCodec::kMaxDataPayloadSize, dns_expected));
    printf("OK\n");
}

int main() {
    printf("=== Tunnel Tests ===\n");
    test_handshake_round_trip();
    test_handshake_authentication_failure();
    test_connect_round_trip_domain();
    test_connect_round_trip_ip_addresses();
    test_udp_packet_round_trip_domain();
    test_dns_query_round_trip_without_target();
    test_data_disconnect_and_connect_result();
    test_partial_frame_waits_for_more_data();
    test_data_chunking();
    test_protocol_error_for_invalid_frame_length();
    test_tampered_frame_is_discarded();
    test_chacha20_poly1305_tunnel_round_trip();
    test_encoded_frame_size_preflight();
    printf("All tunnel tests passed!\n");
    return 0;
}
