#include "tx/protocol/tunnel.h"
#include "tx/common/endian.h"
#include "tx/common/log.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring>
#include <arpa/inet.h>

namespace tx {

namespace {

static constexpr uint8_t kHandshakeMagic[] = {'T', 'X', 'H', 'S'};
static constexpr uint8_t kClientHello = 0x01;
static constexpr uint8_t kServerHello = 0x02;

bool hmac_sha256(const std::vector<uint8_t>& key,
                 const uint8_t* data, size_t len,
                 uint8_t out[TunnelCodec::kHandshakeMacSize]) {
    unsigned int mac_len = 0;
    unsigned char* mac = HMAC(EVP_sha256(),
                              key.data(), static_cast<int>(key.size()),
                              data, len, out, &mac_len);
    return mac == out && mac_len == TunnelCodec::kHandshakeMacSize;
}

bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

void append_handshake_mac_input(uint8_t type,
                                const std::vector<uint8_t>& client_nonce,
                                const std::vector<uint8_t>* server_nonce,
                                std::vector<uint8_t>& out) {
    out.clear();
    out.insert(out.end(), kHandshakeMagic, kHandshakeMagic + sizeof(kHandshakeMagic));
    out.push_back(type);
    out.insert(out.end(), client_nonce.begin(), client_nonce.end());
    if (server_nonce) {
        out.insert(out.end(), server_nonce->begin(), server_nonce->end());
    }
}

} // namespace

size_t TunnelCodec::build_message(TunnelCmd cmd, SessionId session_id,
                                   const TargetAddr* target,
                                   const uint8_t* payload, size_t payload_len,
                                   uint8_t* out, size_t out_len) {
    size_t pos = 0;

    // Version
    out[pos++] = kVersion;

    // Command
    out[pos++] = static_cast<uint8_t>(cmd);

    // Session ID (big-endian)
    store_be32(out + pos, session_id);
    pos += 4;

    // Target address (only for CONNECT)
    if (target && cmd == TunnelCmd::Connect) {
        out[pos++] = static_cast<uint8_t>(target->type);

        switch (target->type) {
            case AddrType::IPv4: {
                auto addr = IpAddr::from_string(target->host);
                memcpy(out + pos, addr.data.v4, 4);
                pos += 4;
                break;
            }
            case AddrType::Domain: {
                size_t host_len = target->host.size();
                if (host_len > 255) host_len = 255;
                out[pos++] = static_cast<uint8_t>(host_len);
                memcpy(out + pos, target->host.data(), host_len);
                pos += host_len;
                break;
            }
            case AddrType::IPv6: {
                auto addr = IpAddr::from_string(target->host);
                memcpy(out + pos, addr.data.v6, 16);
                pos += 16;
                break;
            }
        }

        // Port (big-endian)
        store_be16(out + pos, target->port);
        pos += 2;
    }

    // Payload
    if (payload && payload_len > 0) {
        if (payload_len > out_len - pos) {
            return 0;
        }
        memcpy(out + pos, payload, payload_len);
        pos += payload_len;
    }

    return pos;
}

bool TunnelCodec::encode(TunnelCmd cmd, SessionId session_id,
                          const TargetAddr& target,
                          const uint8_t* payload, size_t payload_len,
                          Buffer& out) {
    if (payload_len > kMaxPlaintextSize - 264) {
        TX_ERROR("Tunnel payload too large: %zu bytes", payload_len);
        return false;
    }

    uint8_t plaintext[kMaxPlaintextSize];
    size_t msg_len = build_message(cmd, session_id, &target,
                                    payload, payload_len,
                                    plaintext, sizeof(plaintext));
    if (msg_len == 0) {
        TX_ERROR("Tunnel message build failed");
        return false;
    }

    // Encrypted output: nonce + ciphertext + tag
    uint8_t encrypted[kMaxEncryptedFrameSize];
    int enc_len = aes_->encrypt(plaintext, msg_len,
                                 encrypted, sizeof(encrypted));
    if (enc_len < 0) {
        TX_ERROR("Tunnel encrypt failed");
        return false;
    }

    // Prepend length prefix (big-endian)
    uint8_t len_buf[kLenPrefixSize];
    store_be32(len_buf, static_cast<uint32_t>(enc_len));

    out.append(len_buf, kLenPrefixSize);
    out.append(encrypted, static_cast<size_t>(enc_len));
    return true;
}

bool TunnelCodec::encode_data(SessionId session_id,
                               const uint8_t* payload, size_t payload_len,
                               Buffer& out) {
    if (payload_len > kMaxPlaintextSize - kDataHeaderSize) {
        TX_ERROR("Tunnel data payload too large: %zu bytes", payload_len);
        return false;
    }

    uint8_t plaintext[kMaxPlaintextSize];
    size_t msg_len = build_message(TunnelCmd::Data, session_id, nullptr,
                                    payload, payload_len,
                                    plaintext, sizeof(plaintext));
    if (msg_len == 0) {
        TX_ERROR("Tunnel data message build failed");
        return false;
    }

    uint8_t encrypted[kMaxEncryptedFrameSize];
    int enc_len = aes_->encrypt(plaintext, msg_len,
                                 encrypted, sizeof(encrypted));
    if (enc_len < 0) return false;

    uint8_t len_buf[kLenPrefixSize];
    store_be32(len_buf, static_cast<uint32_t>(enc_len));
    out.append(len_buf, kLenPrefixSize);
    out.append(encrypted, static_cast<size_t>(enc_len));
    return true;
}

bool TunnelCodec::encode_disconnect(SessionId session_id, Buffer& out) {
    uint8_t plaintext[16];
    size_t msg_len = build_message(TunnelCmd::Disconnect, session_id, nullptr,
                                    nullptr, 0, plaintext, sizeof(plaintext));

    uint8_t encrypted[16 + AesGcm::kOverhead];
    int enc_len = aes_->encrypt(plaintext, msg_len,
                                 encrypted, sizeof(encrypted));
    if (enc_len < 0) return false;

    uint8_t len_buf[kLenPrefixSize];
    store_be32(len_buf, static_cast<uint32_t>(enc_len));
    out.append(len_buf, kLenPrefixSize);
    out.append(encrypted, static_cast<size_t>(enc_len));
    return true;
}

bool TunnelCodec::encode_connect_result(SessionId session_id, bool success, Buffer& out) {
    uint8_t result = success ? 1 : 0;
    uint8_t plaintext[16];
    size_t msg_len = build_message(TunnelCmd::ConnectResult, session_id, nullptr,
                                    &result, sizeof(result), plaintext, sizeof(plaintext));
    if (msg_len == 0) {
        TX_ERROR("Tunnel connect result message build failed");
        return false;
    }

    uint8_t encrypted[16 + AesGcm::kOverhead];
    int enc_len = aes_->encrypt(plaintext, msg_len,
                                 encrypted, sizeof(encrypted));
    if (enc_len < 0) return false;

    uint8_t len_buf[kLenPrefixSize];
    store_be32(len_buf, static_cast<uint32_t>(enc_len));
    out.append(len_buf, kLenPrefixSize);
    out.append(encrypted, static_cast<size_t>(enc_len));
    return true;
}

bool TunnelCodec::decode(Buffer& in,
                          TunnelCmd& cmd, SessionId& session_id,
                          TargetAddr& target,
                          Buffer& payload) {
    target = TargetAddr();
    payload.clear();

    // Need at least length prefix
    if (in.readable() < kLenPrefixSize) return false;

    uint32_t frame_len = load_be32(in.data());
    if (frame_len < AesGcm::kOverhead || frame_len > kMaxEncryptedFrameSize) {
        TX_ERROR("Tunnel protocol error: invalid frame length %u bytes", frame_len);
        protocol_error_ = true;
        in.clear();
        return false;
    }

    // Check if complete frame is available
    if (in.readable() < kLenPrefixSize + frame_len) return false;

    // Decrypt
    const uint8_t* enc_data = in.data() + kLenPrefixSize;
    uint8_t plaintext[kMaxPlaintextSize];
    int pt_len = aes_->decrypt(enc_data, frame_len, plaintext, sizeof(plaintext));
    if (pt_len < 0) {
        TX_ERROR("Tunnel decrypt failed, discarding frame");
        in.consume(kLenPrefixSize + frame_len);
        return false;
    }

    // Parse plaintext
    size_t pos = 0;
    if (static_cast<size_t>(pt_len) < 6) { // min: version(1)+cmd(1)+sid(4)
        TX_ERROR("Tunnel message too short: %d bytes", pt_len);
        in.consume(kLenPrefixSize + frame_len);
        return false;
    }

    uint8_t version = plaintext[pos++];
    if (version != kVersion) {
        TX_ERROR("Tunnel version mismatch: got %u, expected %u", version, kVersion);
        protocol_error_ = true;
        in.consume(kLenPrefixSize + frame_len);
        return false;
    }

    cmd = static_cast<TunnelCmd>(plaintext[pos++]);
    session_id = load_be32(plaintext + pos);
    pos += 4;

    if (cmd != TunnelCmd::Connect &&
        cmd != TunnelCmd::Data &&
        cmd != TunnelCmd::Disconnect &&
        cmd != TunnelCmd::ConnectResult) {
        TX_ERROR("Unknown tunnel command: %u", static_cast<unsigned>(cmd));
        protocol_error_ = true;
        in.consume(kLenPrefixSize + frame_len);
        return false;
    }

    // Parse address (only in CONNECT)
    if (cmd == TunnelCmd::Connect) {
        if (pos >= static_cast<size_t>(pt_len)) {
            in.consume(kLenPrefixSize + frame_len);
            return false;
        }

        target.type = static_cast<AddrType>(plaintext[pos++]);

        switch (target.type) {
            case AddrType::IPv4: {
                if (pos + 4 + 2 > static_cast<size_t>(pt_len)) {
                    in.consume(kLenPrefixSize + frame_len);
                    return false;
                }
                char ipbuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, plaintext + pos, ipbuf, sizeof(ipbuf));
                target.host = ipbuf;
                pos += 4;
                break;
            }
            case AddrType::Domain: {
                if (pos >= static_cast<size_t>(pt_len)) {
                    in.consume(kLenPrefixSize + frame_len);
                    return false;
                }
                uint8_t host_len = plaintext[pos++];
                if (pos + host_len + 2 > static_cast<size_t>(pt_len)) {
                    in.consume(kLenPrefixSize + frame_len);
                    return false;
                }
                target.host.assign(reinterpret_cast<const char*>(plaintext + pos), host_len);
                pos += host_len;
                break;
            }
            case AddrType::IPv6: {
                if (pos + 16 + 2 > static_cast<size_t>(pt_len)) {
                    in.consume(kLenPrefixSize + frame_len);
                    return false;
                }
                char ipbuf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, plaintext + pos, ipbuf, sizeof(ipbuf));
                target.host = ipbuf;
                pos += 16;
                break;
            }
            default:
                TX_ERROR("Unknown address type: %u", static_cast<unsigned>(target.type));
                protocol_error_ = true;
                in.consume(kLenPrefixSize + frame_len);
                return false;
        }

        if (pos + 2 > static_cast<size_t>(pt_len)) {
            in.consume(kLenPrefixSize + frame_len);
            return false;
        }
        target.port = load_be16(plaintext + pos);
        pos += 2;
    }

    // Remaining bytes are payload
    if (pos < static_cast<size_t>(pt_len)) {
        payload.append(plaintext + pos, static_cast<size_t>(pt_len) - pos);
    }

    in.consume(kLenPrefixSize + frame_len);
    return true;
}

bool TunnelCodec::build_client_hello(const std::vector<uint8_t>& master_key,
                                      Buffer& out,
                                      std::vector<uint8_t>& client_nonce) {
    client_nonce.assign(kHandshakeNonceSize, 0);
    if (RAND_bytes(client_nonce.data(), static_cast<int>(client_nonce.size())) != 1) {
        TX_ERROR("RAND_bytes failed for tunnel client nonce");
        return false;
    }

    std::vector<uint8_t> mac_input;
    append_handshake_mac_input(kClientHello, client_nonce, nullptr, mac_input);

    uint8_t mac[kHandshakeMacSize];
    if (!hmac_sha256(master_key, mac_input.data(), mac_input.size(), mac)) {
        TX_ERROR("Failed to build tunnel client hello MAC");
        return false;
    }

    out.append(kHandshakeMagic, sizeof(kHandshakeMagic));
    uint8_t type = kClientHello;
    out.append(&type, 1);
    out.append(client_nonce.data(), client_nonce.size());
    out.append(mac, sizeof(mac));
    return true;
}

bool TunnelCodec::parse_client_hello(const std::vector<uint8_t>& master_key,
                                      const uint8_t* data, size_t len,
                                      std::vector<uint8_t>& client_nonce) {
    if (len != kHandshakeSize || memcmp(data, kHandshakeMagic, sizeof(kHandshakeMagic)) != 0 ||
        data[sizeof(kHandshakeMagic)] != kClientHello) {
        TX_ERROR("Invalid tunnel client hello");
        return false;
    }

    const uint8_t* nonce = data + sizeof(kHandshakeMagic) + 1;
    const uint8_t* received_mac = nonce + kHandshakeNonceSize;
    client_nonce.assign(nonce, nonce + kHandshakeNonceSize);

    std::vector<uint8_t> mac_input;
    append_handshake_mac_input(kClientHello, client_nonce, nullptr, mac_input);

    uint8_t expected_mac[kHandshakeMacSize];
    if (!hmac_sha256(master_key, mac_input.data(), mac_input.size(), expected_mac)) {
        TX_ERROR("Failed to verify tunnel client hello MAC");
        return false;
    }

    if (!constant_time_equal(received_mac, expected_mac, sizeof(expected_mac))) {
        TX_ERROR("Tunnel client hello authentication failed");
        return false;
    }

    return true;
}

bool TunnelCodec::build_server_hello(const std::vector<uint8_t>& master_key,
                                      const std::vector<uint8_t>& client_nonce,
                                      Buffer& out,
                                      std::vector<uint8_t>& server_nonce) {
    if (client_nonce.size() != kHandshakeNonceSize) {
        TX_ERROR("Invalid client nonce size");
        return false;
    }

    server_nonce.assign(kHandshakeNonceSize, 0);
    if (RAND_bytes(server_nonce.data(), static_cast<int>(server_nonce.size())) != 1) {
        TX_ERROR("RAND_bytes failed for tunnel server nonce");
        return false;
    }

    std::vector<uint8_t> mac_input;
    append_handshake_mac_input(kServerHello, client_nonce, &server_nonce, mac_input);

    uint8_t mac[kHandshakeMacSize];
    if (!hmac_sha256(master_key, mac_input.data(), mac_input.size(), mac)) {
        TX_ERROR("Failed to build tunnel server hello MAC");
        return false;
    }

    out.append(kHandshakeMagic, sizeof(kHandshakeMagic));
    uint8_t type = kServerHello;
    out.append(&type, 1);
    out.append(server_nonce.data(), server_nonce.size());
    out.append(mac, sizeof(mac));
    return true;
}

bool TunnelCodec::parse_server_hello(const std::vector<uint8_t>& master_key,
                                      const std::vector<uint8_t>& client_nonce,
                                      const uint8_t* data, size_t len,
                                      std::vector<uint8_t>& server_nonce) {
    if (client_nonce.size() != kHandshakeNonceSize ||
        len != kHandshakeSize || memcmp(data, kHandshakeMagic, sizeof(kHandshakeMagic)) != 0 ||
        data[sizeof(kHandshakeMagic)] != kServerHello) {
        TX_ERROR("Invalid tunnel server hello");
        return false;
    }

    const uint8_t* nonce = data + sizeof(kHandshakeMagic) + 1;
    const uint8_t* received_mac = nonce + kHandshakeNonceSize;
    server_nonce.assign(nonce, nonce + kHandshakeNonceSize);

    std::vector<uint8_t> mac_input;
    append_handshake_mac_input(kServerHello, client_nonce, &server_nonce, mac_input);

    uint8_t expected_mac[kHandshakeMacSize];
    if (!hmac_sha256(master_key, mac_input.data(), mac_input.size(), expected_mac)) {
        TX_ERROR("Failed to verify tunnel server hello MAC");
        return false;
    }

    if (!constant_time_equal(received_mac, expected_mac, sizeof(expected_mac))) {
        TX_ERROR("Tunnel server hello authentication failed");
        return false;
    }

    return true;
}

std::vector<uint8_t> TunnelCodec::derive_session_key(const std::vector<uint8_t>& master_key,
                                                      const std::vector<uint8_t>& client_nonce,
                                                      const std::vector<uint8_t>& server_nonce) {
    std::vector<uint8_t> input;
    static const uint8_t label[] = {'t', 'x', '-', 's', 'e', 's', 's', 'i', 'o', 'n', '-', 'v', '1'};
    input.insert(input.end(), label, label + sizeof(label));
    input.insert(input.end(), client_nonce.begin(), client_nonce.end());
    input.insert(input.end(), server_nonce.begin(), server_nonce.end());

    std::vector<uint8_t> key(AesGcm::kKeyLen);
    if (!hmac_sha256(master_key, input.data(), input.size(), key.data())) {
        TX_FATAL("Failed to derive tunnel session key");
    }
    return key;
}

} // namespace tx
