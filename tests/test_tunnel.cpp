#include "tx/protocol/tunnel.h"
#include "tx/crypto/key_derive.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#define TX_ASSERT(expr) do { assert(expr); (void)sizeof(expr); } while (0)

static tx::TunnelCodec make_codec(const std::vector<uint8_t>& key) {
    auto aes = std::make_shared<tx::AesGcm>(key.data(), key.size());
    return tx::TunnelCodec(aes);
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
    auto master_key = tx::KeyDeriver::derive_deterministic("shared-password");

    tx::Buffer client_hello;
    std::vector<uint8_t> client_nonce;
    TX_ASSERT(tx::TunnelCodec::build_client_hello(master_key, client_hello, client_nonce));
    TX_ASSERT(client_hello.readable() == tx::TunnelCodec::kHandshakeSize);
    TX_ASSERT(client_nonce.size() == tx::TunnelCodec::kHandshakeNonceSize);

    std::vector<uint8_t> parsed_client_nonce;
    TX_ASSERT(tx::TunnelCodec::parse_client_hello(master_key, client_hello.data(),
                                                  client_hello.readable(),
                                                  parsed_client_nonce));
    TX_ASSERT(parsed_client_nonce == client_nonce);

    tx::Buffer server_hello;
    std::vector<uint8_t> server_nonce;
    TX_ASSERT(tx::TunnelCodec::build_server_hello(master_key, client_nonce,
                                                  server_hello, server_nonce));
    TX_ASSERT(server_hello.readable() == tx::TunnelCodec::kHandshakeSize);
    TX_ASSERT(server_nonce.size() == tx::TunnelCodec::kHandshakeNonceSize);

    std::vector<uint8_t> parsed_server_nonce;
    TX_ASSERT(tx::TunnelCodec::parse_server_hello(master_key, client_nonce,
                                                  server_hello.data(),
                                                  server_hello.readable(),
                                                  parsed_server_nonce));
    TX_ASSERT(parsed_server_nonce == server_nonce);

    auto client_session_key = tx::TunnelCodec::derive_session_key(master_key,
                                                                  client_nonce,
                                                                  server_nonce);
    auto server_session_key = tx::TunnelCodec::derive_session_key(master_key,
                                                                  parsed_client_nonce,
                                                                  parsed_server_nonce);
    TX_ASSERT(client_session_key == server_session_key);
    TX_ASSERT(client_session_key.size() == tx::AesGcm::kKeyLen);

    printf("OK\n");
}

static void test_handshake_authentication_failure() {
    printf("  test_handshake_authentication_failure... ");
    auto master_key = tx::KeyDeriver::derive_deterministic("shared-password");
    auto wrong_key = tx::KeyDeriver::derive_deterministic("wrong-password");

    tx::Buffer client_hello;
    std::vector<uint8_t> client_nonce;
    TX_ASSERT(tx::TunnelCodec::build_client_hello(master_key, client_hello, client_nonce));

    std::vector<uint8_t> parsed_client_nonce;
    TX_ASSERT(!tx::TunnelCodec::parse_client_hello(wrong_key, client_hello.data(),
                                                   client_hello.readable(),
                                                   parsed_client_nonce));

    std::vector<uint8_t> tampered(client_hello.data(),
                                  client_hello.data() + client_hello.readable());
    TX_ASSERT(!tampered.empty());
    tampered[tampered.size() - 1] ^= 0x01;
    TX_ASSERT(!tx::TunnelCodec::parse_client_hello(master_key, tampered.data(),
                                                   tampered.size(),
                                                   parsed_client_nonce));

    printf("OK\n");
}

static void test_connect_round_trip_domain() {
    printf("  test_connect_round_trip_domain... ");
    auto key = tx::KeyDeriver::derive_deterministic("tunnel-key");
    auto encoder = make_codec(key);
    auto decoder = make_codec(key);

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
    auto key = tx::KeyDeriver::derive_deterministic("tunnel-key");
    auto encoder = make_codec(key);
    auto decoder = make_codec(key);

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

static void test_data_disconnect_and_connect_result() {
    printf("  test_data_disconnect_and_connect_result... ");
    auto key = tx::KeyDeriver::derive_deterministic("tunnel-key");
    auto encoder = make_codec(key);
    auto decoder = make_codec(key);

    const char data[] = "hello through tunnel";
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode_data(100, reinterpret_cast<const uint8_t*>(data),
                                  strlen(data), encoded));
    TX_ASSERT(encoder.encode_connect_result(100, true, encoded));
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
    TX_ASSERT(cmd == tx::TunnelCmd::Disconnect);
    TX_ASSERT(session_id == 100);
    TX_ASSERT(payload.empty());
    TX_ASSERT(encoded.empty());

    printf("OK\n");
}

static void test_partial_frame_waits_for_more_data() {
    printf("  test_partial_frame_waits_for_more_data... ");
    auto key = tx::KeyDeriver::derive_deterministic("tunnel-key");
    auto encoder = make_codec(key);
    auto decoder = make_codec(key);

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
    auto key = tx::KeyDeriver::derive_deterministic("tunnel-key");
    auto encoder = make_codec(key);
    auto decoder = make_codec(key);

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
    auto key = tx::KeyDeriver::derive_deterministic("tunnel-key");
    auto decoder = make_codec(key);

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
    auto key = tx::KeyDeriver::derive_deterministic("tunnel-key");
    auto encoder = make_codec(key);
    auto decoder = make_codec(key);

    const char data[] = "authenticated data";
    tx::Buffer encoded;
    TX_ASSERT(encoder.encode_data(31, reinterpret_cast<const uint8_t*>(data),
                                  strlen(data), encoded));

    std::vector<uint8_t> tampered(encoded.data(),
                                  encoded.data() + encoded.readable());
    tampered[tx::TunnelCodec::kLenPrefixSize + tx::AesGcm::kNonceLen] ^= 0x80;

    tx::Buffer tampered_buffer;
    tampered_buffer.append(tampered.data(), tampered.size());
    assert_no_message(decoder, tampered_buffer);
    TX_ASSERT(!decoder.has_protocol_error());
    TX_ASSERT(tampered_buffer.empty());

    printf("OK\n");
}

int main() {
    printf("=== Tunnel Tests ===\n");
    test_handshake_round_trip();
    test_handshake_authentication_failure();
    test_connect_round_trip_domain();
    test_connect_round_trip_ip_addresses();
    test_data_disconnect_and_connect_result();
    test_partial_frame_waits_for_more_data();
    test_data_chunking();
    test_protocol_error_for_invalid_frame_length();
    test_tampered_frame_is_discarded();
    printf("All tunnel tests passed!\n");
    return 0;
}
