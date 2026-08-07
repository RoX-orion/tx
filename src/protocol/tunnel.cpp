#include "tx/protocol/tunnel.h"
#include "tx/common/endian.h"
#include "tx/common/log.h"
#include "tx/crypto/secret.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "tx/common/network.h"
#include <algorithm>
#include <cstring>

namespace tx {

constexpr uint8_t TunnelCodec::kVersion;
constexpr size_t TunnelCodec::kLenPrefixSize;
constexpr size_t TunnelCodec::kMinFrameSize;
constexpr size_t TunnelCodec::kMaxPlaintextSize;
constexpr size_t TunnelCodec::kMaxEncryptedFrameSize;
constexpr size_t TunnelCodec::kDataHeaderSize;
constexpr size_t TunnelCodec::kMaxDataPayloadSize;
constexpr size_t TunnelCodec::kHandshakeNonceSize;
constexpr size_t TunnelCodec::kHandshakePublicKeySize;
constexpr size_t TunnelCodec::kHandshakeMacSize;
constexpr size_t TunnelCodec::kHandshakeSize;

namespace {

// v3 uses a distinct handshake marker so an older peer is rejected before keys
// are established rather than after the first encrypted frame.
static constexpr uint8_t kHandshakeMagic[] = {'T', 'X', 'V', '3'};
static constexpr uint8_t kClientHello = 0x01;
static constexpr uint8_t kServerHello = 0x02;
static constexpr size_t kNoncePrefixLen = 4;

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

void append_bytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    out.insert(out.end(), data, data + len);
}

void append_hello_fields(uint8_t type, AeadCipherKind cipher,
                         const std::vector<uint8_t>& nonce,
                         const std::vector<uint8_t>& public_key,
                         std::vector<uint8_t>& out) {
    append_bytes(out, kHandshakeMagic, sizeof(kHandshakeMagic));
    out.push_back(type);
    out.push_back(static_cast<uint8_t>(cipher));
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), public_key.begin(), public_key.end());
}

void append_server_mac_input(const TunnelPeerHello& client_hello,
                             const TunnelHandshakeState& server_state,
                             std::vector<uint8_t>& out) {
    out.clear();
    static const uint8_t label[] = {
        't', 'x', '-', 'h', 's', '-', 's', 'e', 'r', 'v', 'e', 'r', '-', 'v', '3'
    };
    append_bytes(out, label, sizeof(label));
    append_hello_fields(kClientHello, client_hello.cipher,
                        client_hello.nonce, client_hello.public_key, out);
    append_hello_fields(kServerHello, server_state.cipher,
                        server_state.nonce, server_state.public_key, out);
}

bool parse_cipher_id(uint8_t id, AeadCipherKind& cipher) {
    if (id == static_cast<uint8_t>(AeadCipherKind::Aes256Gcm)) {
        cipher = AeadCipherKind::Aes256Gcm;
        return true;
    }
    if (id == static_cast<uint8_t>(AeadCipherKind::ChaCha20Poly1305)) {
        cipher = AeadCipherKind::ChaCha20Poly1305;
        return true;
    }
    return false;
}

bool generate_x25519_keypair(std::vector<uint8_t>& private_key,
                             std::vector<uint8_t>& public_key) {
    bool ok = false;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* key = nullptr;
    if (!ctx) return false;

    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_keygen(ctx, &key) == 1 && key) {
        private_key.assign(TunnelCodec::kHandshakePublicKeySize, 0);
        public_key.assign(TunnelCodec::kHandshakePublicKeySize, 0);
        size_t priv_len = private_key.size();
        size_t pub_len = public_key.size();
        ok = EVP_PKEY_get_raw_private_key(key, private_key.data(), &priv_len) == 1 &&
             EVP_PKEY_get_raw_public_key(key, public_key.data(), &pub_len) == 1 &&
             priv_len == private_key.size() &&
             pub_len == public_key.size();
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        private_key.clear();
        public_key.clear();
    }
    return ok;
}

bool x25519_derive(const std::vector<uint8_t>& private_key,
                   const std::vector<uint8_t>& peer_public_key,
                   std::vector<uint8_t>& shared) {
    if (private_key.size() != TunnelCodec::kHandshakePublicKeySize ||
        peer_public_key.size() != TunnelCodec::kHandshakePublicKeySize) {
        return false;
    }

    bool ok = false;
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                  private_key.data(), private_key.size());
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                 peer_public_key.data(), peer_public_key.size());
    EVP_PKEY_CTX* ctx = priv ? EVP_PKEY_CTX_new(priv, nullptr) : nullptr;

    if (priv && peer && ctx &&
        EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer) == 1) {
        size_t shared_len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &shared_len) == 1 && shared_len > 0) {
            shared.assign(shared_len, 0);
            ok = EVP_PKEY_derive(ctx, shared.data(), &shared_len) == 1 &&
                 shared_len == shared.size();
        }
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    if (!ok) {
        shared.clear();
    }
    return ok;
}

bool derive_traffic_keys(const std::vector<uint8_t>& psk,
                         const std::vector<uint8_t>& shared_secret,
                         const std::vector<uint8_t>& client_nonce,
                         const std::vector<uint8_t>& server_nonce,
                         const std::vector<uint8_t>& client_public,
                         const std::vector<uint8_t>& server_public,
                         AeadCipherKind cipher,
                         TunnelTrafficKeys& keys) {
    std::vector<uint8_t> info;
    static const uint8_t label[] = {'t', 'x', '-', 't', 'r', 'a', 'f', 'f', 'i', 'c', '-', 'v', '3'};
    append_bytes(info, label, sizeof(label));
    info.push_back(static_cast<uint8_t>(cipher));
    info.insert(info.end(), client_nonce.begin(), client_nonce.end());
    info.insert(info.end(), server_nonce.begin(), server_nonce.end());
    info.insert(info.end(), client_public.begin(), client_public.end());
    info.insert(info.end(), server_public.begin(), server_public.end());

    std::vector<uint8_t> material(AeadCipher::kKeyLen * 2 + kNoncePrefixLen * 2);
    if (!Secret::hkdf_sha256(psk.data(), psk.size(),
                             shared_secret.data(), shared_secret.size(),
                             info.data(), info.size(),
                             material.data(), material.size())) {
        return false;
    }

    size_t pos = 0;
    keys.cipher = cipher;
    keys.client_to_server_key.assign(material.begin() + pos,
                                     material.begin() + pos + AeadCipher::kKeyLen);
    pos += AeadCipher::kKeyLen;
    keys.server_to_client_key.assign(material.begin() + pos,
                                     material.begin() + pos + AeadCipher::kKeyLen);
    pos += AeadCipher::kKeyLen;
    keys.client_to_server_nonce_prefix.assign(material.begin() + pos,
                                              material.begin() + pos + kNoncePrefixLen);
    pos += kNoncePrefixLen;
    keys.server_to_client_nonce_prefix.assign(material.begin() + pos,
                                              material.begin() + pos + kNoncePrefixLen);
    OPENSSL_cleanse(material.data(), material.size());
    return true;
}

} // namespace

TunnelCodec::TunnelCodec(const TunnelTrafficKeys& keys, bool client_side)
    : send_direction_(client_side ? TunnelDirection::ClientToServer
                                  : TunnelDirection::ServerToClient),
      recv_direction_(client_side ? TunnelDirection::ServerToClient
                                  : TunnelDirection::ClientToServer),
      cipher_kind_(keys.cipher) {
    const std::vector<uint8_t>& send_key =
        client_side ? keys.client_to_server_key : keys.server_to_client_key;
    const std::vector<uint8_t>& recv_key =
        client_side ? keys.server_to_client_key : keys.client_to_server_key;

    send_nonce_prefix_ = client_side ? keys.client_to_server_nonce_prefix
                                     : keys.server_to_client_nonce_prefix;
    recv_nonce_prefix_ = client_side ? keys.server_to_client_nonce_prefix
                                     : keys.client_to_server_nonce_prefix;

    send_cipher_ = std::make_shared<AeadCipher>(keys.cipher, send_key.data(), send_key.size());
    recv_cipher_ = std::make_shared<AeadCipher>(keys.cipher, recv_key.data(), recv_key.size());
}

bool TunnelCodec::encoded_frame_size(TunnelCmd cmd, const TargetAddr& target,
                                     size_t payload_len, size_t& out_size) {
    if (payload_len > kMaxPlaintextSize) return false;

    size_t message_size = kDataHeaderSize;
    if (cmd == TunnelCmd::Connect || cmd == TunnelCmd::UdpPacket) {
        size_t address_size = 0;
        switch (target.type) {
            case AddrType::IPv4:
                address_size = 1 + 4 + 2; // type + address + port
                break;
            case AddrType::IPv6:
                address_size = 1 + 16 + 2;
                break;
            case AddrType::Domain:
                address_size = 1 + 1 + std::min<size_t>(target.host.size(), 255) + 2;
                break;
            default:
                return false;
        }
        if (message_size > kMaxPlaintextSize - address_size) return false;
        message_size += address_size;
    }
    if (message_size > kMaxPlaintextSize - payload_len) return false;
    message_size += payload_len;

    out_size = kLenPrefixSize + message_size + AeadCipher::kOverhead;
    return true;
}

size_t TunnelCodec::build_message(TunnelCmd cmd, SessionId session_id,
                                   const TargetAddr* target,
                                   const uint8_t* payload, size_t payload_len,
                                   uint8_t* out, size_t out_len) {
    size_t pos = 0;
    if (out_len < kDataHeaderSize) return 0;

    out[pos++] = kVersion;
    out[pos++] = static_cast<uint8_t>(cmd);
    store_be32(out + pos, session_id);
    pos += 4;

    if (target && (cmd == TunnelCmd::Connect || cmd == TunnelCmd::UdpPacket)) {
        if (pos + 1 > out_len) return 0;
        out[pos++] = static_cast<uint8_t>(target->type);

        switch (target->type) {
            case AddrType::IPv4: {
                if (pos + 4 + 2 > out_len) return 0;
                auto addr = IpAddr::from_string(target->host);
                memcpy(out + pos, addr.data.v4, 4);
                pos += 4;
                break;
            }
            case AddrType::Domain: {
                size_t host_len = std::min<size_t>(target->host.size(), 255);
                if (pos + 1 + host_len + 2 > out_len) return 0;
                out[pos++] = static_cast<uint8_t>(host_len);
                memcpy(out + pos, target->host.data(), host_len);
                pos += host_len;
                break;
            }
            case AddrType::IPv6: {
                if (pos + 16 + 2 > out_len) return 0;
                auto addr = IpAddr::from_string(target->host);
                memcpy(out + pos, addr.data.v6, 16);
                pos += 16;
                break;
            }
        }

        store_be16(out + pos, target->port);
        pos += 2;
    }

    if (payload && payload_len > 0) {
        if (payload_len > out_len - pos) {
            return 0;
        }
        memcpy(out + pos, payload, payload_len);
        pos += payload_len;
    }

    return pos;
}

bool TunnelCodec::build_nonce(bool send, uint64_t seq, uint8_t out[AeadCipher::kNonceLen]) const {
    const std::vector<uint8_t>& prefix = send ? send_nonce_prefix_ : recv_nonce_prefix_;
    if (prefix.size() != kNoncePrefixLen) {
        return false;
    }
    memcpy(out, prefix.data(), kNoncePrefixLen);
    store_be64(out + kNoncePrefixLen, seq);
    return true;
}

void TunnelCodec::build_aad(TunnelDirection direction, uint64_t seq, uint32_t frame_len,
                            uint8_t out[kAadSize]) const {
    out[0] = 'T';
    out[1] = 'X';
    out[2] = 'A';
    out[3] = 'D';
    out[4] = kVersion;
    out[5] = static_cast<uint8_t>(cipher_kind_);
    out[6] = static_cast<uint8_t>(direction);
    out[7] = 0;
    store_be64(out + 8, seq);
    store_be32(out + 16, frame_len);
}

bool TunnelCodec::encode(TunnelCmd cmd, SessionId session_id,
                          const TargetAddr& target,
                          const uint8_t* payload, size_t payload_len,
                          Buffer& out) {
    if (!send_cipher_) {
        TX_ERROR("Tunnel codec is not initialized");
        return false;
    }
    if (payload_len > kMaxPlaintextSize) {
        TX_ERROR("Tunnel payload too large: %zu bytes", payload_len);
        return false;
    }

    size_t expected_frame_size = 0;
    if (!encoded_frame_size(cmd, target, payload_len, expected_frame_size)) {
        TX_ERROR("Tunnel message is too large for command %u", static_cast<unsigned>(cmd));
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

    const uint32_t frame_len = static_cast<uint32_t>(msg_len + AeadCipher::kOverhead);
    uint8_t nonce[AeadCipher::kNonceLen];
    uint8_t aad[kAadSize];
    if (!build_nonce(true, send_seq_, nonce)) {
        TX_ERROR("Tunnel nonce build failed");
        return false;
    }
    build_aad(send_direction_, send_seq_, frame_len, aad);

    uint8_t encrypted[kMaxEncryptedFrameSize];
    int enc_len = send_cipher_->encrypt(nonce, aad, sizeof(aad),
                                        plaintext, msg_len,
                                        encrypted, sizeof(encrypted));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    if (enc_len < 0) {
        TX_ERROR("Tunnel encrypt failed");
        return false;
    }

    uint8_t len_buf[kLenPrefixSize];
    store_be32(len_buf, static_cast<uint32_t>(enc_len));
    out.append(len_buf, kLenPrefixSize);
    out.append(encrypted, static_cast<size_t>(enc_len));
    ++send_seq_;
    return true;
}

bool TunnelCodec::encode_data(SessionId session_id,
                               const uint8_t* payload, size_t payload_len,
                               Buffer& out) {
    if (payload_len > kMaxDataPayloadSize) {
        TX_ERROR("Tunnel data payload too large: %zu bytes", payload_len);
        return false;
    }

    TargetAddr dummy;
    return encode(TunnelCmd::Data, session_id, dummy, payload, payload_len, out);
}

bool TunnelCodec::encode_data_chunks(SessionId session_id,
                                      const uint8_t* payload, size_t payload_len,
                                      Buffer& out) {
    size_t offset = 0;
    while (offset < payload_len) {
        size_t chunk_len = std::min(kMaxDataPayloadSize, payload_len - offset);
        if (!encode_data(session_id, payload + offset, chunk_len, out)) {
            return false;
        }
        offset += chunk_len;
    }
    return true;
}

bool TunnelCodec::encode_udp_packet(SessionId session_id,
                                    const TargetAddr& target,
                                    const uint8_t* payload, size_t payload_len,
                                    Buffer& out) {
    if (payload_len > kMaxDataPayloadSize) {
        TX_ERROR("Tunnel UDP payload too large: %zu bytes", payload_len);
        return false;
    }
    return encode(TunnelCmd::UdpPacket, session_id, target, payload, payload_len, out);
}

bool TunnelCodec::encode_dns_query(SessionId session_id,
                                   const uint8_t* payload, size_t payload_len,
                                   Buffer& out) {
    if (!payload || payload_len < 12 || payload_len > kMaxDataPayloadSize) {
        TX_ERROR("Tunnel DNS query has invalid size: %zu bytes", payload_len);
        return false;
    }
    TargetAddr dummy;
    return encode(TunnelCmd::DnsQuery, session_id, dummy, payload, payload_len, out);
}

bool TunnelCodec::encode_dns_response(SessionId session_id,
                                      const uint8_t* payload, size_t payload_len,
                                      Buffer& out) {
    if (payload_len > kMaxDataPayloadSize || (payload_len != 0 && !payload)) {
        TX_ERROR("Tunnel DNS response has invalid size: %zu bytes", payload_len);
        return false;
    }
    TargetAddr dummy;
    return encode(TunnelCmd::DnsResponse, session_id, dummy, payload, payload_len, out);
}

bool TunnelCodec::encode_disconnect(SessionId session_id, Buffer& out) {
    TargetAddr dummy;
    return encode(TunnelCmd::Disconnect, session_id, dummy, nullptr, 0, out);
}

bool TunnelCodec::encode_half_close(SessionId session_id, Buffer& out) {
    TargetAddr dummy;
    return encode(TunnelCmd::HalfClose, session_id, dummy, nullptr, 0, out);
}

bool TunnelCodec::encode_connect_result(SessionId session_id, bool success, Buffer& out) {
    uint8_t result = success ? 1 : 0;
    TargetAddr dummy;
    return encode(TunnelCmd::ConnectResult, session_id, dummy,
                  &result, sizeof(result), out);
}

bool TunnelCodec::decode(Buffer& in,
                          TunnelCmd& cmd, SessionId& session_id,
                          TargetAddr& target,
                          Buffer& payload) {
    target = TargetAddr();
    payload.clear();

    if (!recv_cipher_) {
        TX_ERROR("Tunnel codec is not initialized");
        protocol_error_ = true;
        in.clear();
        return false;
    }

    if (in.readable() < kLenPrefixSize) return false;

    uint32_t frame_len = load_be32(in.data());
    if (frame_len < AeadCipher::kOverhead || frame_len > kMaxEncryptedFrameSize) {
        TX_ERROR("Tunnel protocol error: invalid frame length %u bytes", frame_len);
        protocol_error_ = true;
        in.clear();
        return false;
    }

    if (in.readable() < kLenPrefixSize + frame_len) return false;

    const uint8_t* enc_data = in.data() + kLenPrefixSize;
    const size_t ciphertext_len = frame_len - AeadCipher::kTagLen;
    const uint8_t* tag = enc_data + ciphertext_len;

    uint8_t nonce[AeadCipher::kNonceLen];
    uint8_t aad[kAadSize];
    if (!build_nonce(false, recv_seq_, nonce)) {
        TX_ERROR("Tunnel nonce build failed");
        protocol_error_ = true;
        in.clear();
        return false;
    }
    build_aad(recv_direction_, recv_seq_, frame_len, aad);

    uint8_t plaintext[kMaxPlaintextSize];
    int pt_len = recv_cipher_->decrypt(nonce, aad, sizeof(aad),
                                       enc_data, ciphertext_len, tag,
                                       plaintext, sizeof(plaintext));
    if (pt_len < 0) {
        TX_ERROR("Tunnel decrypt failed, closing connection");
        protocol_error_ = true;
        in.clear();
        return false;
    }
    ++recv_seq_;

    size_t pos = 0;
    if (static_cast<size_t>(pt_len) < kDataHeaderSize) {
        TX_ERROR("Tunnel message too short: %d bytes", pt_len);
        protocol_error_ = true;
        in.clear();
        return false;
    }

    uint8_t version = plaintext[pos++];
    if (version != kVersion) {
        TX_ERROR("Tunnel version mismatch: got %u, expected %u", version, kVersion);
        protocol_error_ = true;
        in.clear();
        return false;
    }

    cmd = static_cast<TunnelCmd>(plaintext[pos++]);
    session_id = load_be32(plaintext + pos);
    pos += 4;

    if (cmd != TunnelCmd::Connect &&
        cmd != TunnelCmd::Data &&
        cmd != TunnelCmd::Disconnect &&
        cmd != TunnelCmd::HalfClose &&
        cmd != TunnelCmd::ConnectResult &&
        cmd != TunnelCmd::UdpPacket &&
        cmd != TunnelCmd::DnsQuery &&
        cmd != TunnelCmd::DnsResponse) {
        TX_ERROR("Unknown tunnel command: %u", static_cast<unsigned>(cmd));
        protocol_error_ = true;
        in.clear();
        return false;
    }

    if (cmd == TunnelCmd::Connect || cmd == TunnelCmd::UdpPacket) {
        if (pos >= static_cast<size_t>(pt_len)) {
            protocol_error_ = true;
            in.clear();
            return false;
        }

        target.type = static_cast<AddrType>(plaintext[pos++]);

        switch (target.type) {
            case AddrType::IPv4: {
                if (pos + 4 + 2 > static_cast<size_t>(pt_len)) {
                    protocol_error_ = true;
                    in.clear();
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
                    protocol_error_ = true;
                    in.clear();
                    return false;
                }
                uint8_t host_len = plaintext[pos++];
                if (pos + host_len + 2 > static_cast<size_t>(pt_len)) {
                    protocol_error_ = true;
                    in.clear();
                    return false;
                }
                target.host.assign(reinterpret_cast<const char*>(plaintext + pos), host_len);
                pos += host_len;
                break;
            }
            case AddrType::IPv6: {
                if (pos + 16 + 2 > static_cast<size_t>(pt_len)) {
                    protocol_error_ = true;
                    in.clear();
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
                in.clear();
                return false;
        }

        if (pos + 2 > static_cast<size_t>(pt_len)) {
            protocol_error_ = true;
            in.clear();
            return false;
        }
        target.port = load_be16(plaintext + pos);
        pos += 2;
    }

    if (pos < static_cast<size_t>(pt_len)) {
        payload.append(plaintext + pos, static_cast<size_t>(pt_len) - pos);
    }

    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    in.consume(kLenPrefixSize + frame_len);
    return true;
}

bool TunnelCodec::build_client_hello(const std::vector<uint8_t>& psk,
                                      AeadCipherKind cipher,
                                      Buffer& out,
                                      TunnelHandshakeState& state) {
    state = TunnelHandshakeState();
    state.cipher = cipher;
    state.nonce.assign(kHandshakeNonceSize, 0);
    if (RAND_bytes(state.nonce.data(), static_cast<int>(state.nonce.size())) != 1) {
        TX_ERROR("RAND_bytes failed for tunnel client nonce");
        return false;
    }
    if (!generate_x25519_keypair(state.private_key, state.public_key)) {
        TX_ERROR("Failed to generate tunnel client X25519 key");
        return false;
    }

    std::vector<uint8_t> mac_input;
    append_hello_fields(kClientHello, state.cipher, state.nonce, state.public_key, mac_input);

    uint8_t mac[kHandshakeMacSize];
    if (!hmac_sha256(psk, mac_input.data(), mac_input.size(), mac)) {
        TX_ERROR("Failed to build tunnel client hello MAC");
        return false;
    }

    out.append(mac_input.data(), mac_input.size());
    out.append(mac, sizeof(mac));
    return true;
}

bool TunnelCodec::parse_client_hello(const std::vector<uint8_t>& psk,
                                      const uint8_t* data, size_t len,
                                      TunnelPeerHello& client_hello) {
    if (len != kHandshakeSize ||
        memcmp(data, kHandshakeMagic, sizeof(kHandshakeMagic)) != 0 ||
        data[sizeof(kHandshakeMagic)] != kClientHello) {
        TX_ERROR("Rejected tunnel client hello with unsupported protocol version");
        return false;
    }

    AeadCipherKind cipher;
    if (!parse_cipher_id(data[sizeof(kHandshakeMagic) + 1], cipher)) {
        return false;
    }

    size_t pos = sizeof(kHandshakeMagic) + 2;
    client_hello.cipher = cipher;
    client_hello.nonce.assign(data + pos, data + pos + kHandshakeNonceSize);
    pos += kHandshakeNonceSize;
    client_hello.public_key.assign(data + pos, data + pos + kHandshakePublicKeySize);
    pos += kHandshakePublicKeySize;
    const uint8_t* received_mac = data + pos;

    std::vector<uint8_t> mac_input(data, data + pos);
    uint8_t expected_mac[kHandshakeMacSize];
    if (!hmac_sha256(psk, mac_input.data(), mac_input.size(), expected_mac)) {
        return false;
    }

    return constant_time_equal(received_mac, expected_mac, sizeof(expected_mac));
}

bool TunnelCodec::build_server_hello(const std::vector<uint8_t>& psk,
                                      const TunnelPeerHello& client_hello,
                                      Buffer& out,
                                      TunnelHandshakeState& server_state,
                                      TunnelTrafficKeys& keys) {
    server_state = TunnelHandshakeState();
    server_state.cipher = client_hello.cipher;
    server_state.nonce.assign(kHandshakeNonceSize, 0);
    if (RAND_bytes(server_state.nonce.data(), static_cast<int>(server_state.nonce.size())) != 1) {
        TX_ERROR("RAND_bytes failed for tunnel server nonce");
        return false;
    }
    if (!generate_x25519_keypair(server_state.private_key, server_state.public_key)) {
        TX_ERROR("Failed to generate tunnel server X25519 key");
        return false;
    }

    std::vector<uint8_t> shared;
    if (!x25519_derive(server_state.private_key, client_hello.public_key, shared)) {
        TX_ERROR("Failed to derive tunnel server X25519 shared secret");
        return false;
    }

    if (!derive_traffic_keys(psk, shared,
                             client_hello.nonce, server_state.nonce,
                             client_hello.public_key, server_state.public_key,
                             server_state.cipher, keys)) {
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }
    OPENSSL_cleanse(shared.data(), shared.size());

    std::vector<uint8_t> fields;
    append_hello_fields(kServerHello, server_state.cipher,
                        server_state.nonce, server_state.public_key, fields);

    std::vector<uint8_t> mac_input;
    append_server_mac_input(client_hello, server_state, mac_input);
    uint8_t mac[kHandshakeMacSize];
    if (!hmac_sha256(psk, mac_input.data(), mac_input.size(), mac)) {
        TX_ERROR("Failed to build tunnel server hello MAC");
        return false;
    }

    out.append(fields.data(), fields.size());
    out.append(mac, sizeof(mac));
    cleanse_handshake_state(server_state);
    return true;
}

bool TunnelCodec::parse_server_hello(const std::vector<uint8_t>& psk,
                                      const TunnelHandshakeState& client_state,
                                      const uint8_t* data, size_t len,
                                      TunnelTrafficKeys& keys) {
    if (client_state.nonce.size() != kHandshakeNonceSize ||
        client_state.public_key.size() != kHandshakePublicKeySize ||
        client_state.private_key.size() != kHandshakePublicKeySize ||
        len != kHandshakeSize ||
        memcmp(data, kHandshakeMagic, sizeof(kHandshakeMagic)) != 0 ||
        data[sizeof(kHandshakeMagic)] != kServerHello) {
        TX_ERROR("Rejected tunnel server hello with unsupported protocol version");
        return false;
    }

    AeadCipherKind cipher;
    if (!parse_cipher_id(data[sizeof(kHandshakeMagic) + 1], cipher) ||
        cipher != client_state.cipher) {
        return false;
    }

    size_t pos = sizeof(kHandshakeMagic) + 2;
    TunnelHandshakeState server_state;
    server_state.cipher = cipher;
    server_state.nonce.assign(data + pos, data + pos + kHandshakeNonceSize);
    pos += kHandshakeNonceSize;
    server_state.public_key.assign(data + pos, data + pos + kHandshakePublicKeySize);
    pos += kHandshakePublicKeySize;
    const uint8_t* received_mac = data + pos;

    TunnelPeerHello client_hello;
    client_hello.cipher = client_state.cipher;
    client_hello.nonce = client_state.nonce;
    client_hello.public_key = client_state.public_key;

    std::vector<uint8_t> mac_input;
    append_server_mac_input(client_hello, server_state, mac_input);
    uint8_t expected_mac[kHandshakeMacSize];
    if (!hmac_sha256(psk, mac_input.data(), mac_input.size(), expected_mac) ||
        !constant_time_equal(received_mac, expected_mac, sizeof(expected_mac))) {
        return false;
    }

    std::vector<uint8_t> shared;
    if (!x25519_derive(client_state.private_key, server_state.public_key, shared)) {
        return false;
    }

    bool ok = derive_traffic_keys(psk, shared,
                                  client_state.nonce, server_state.nonce,
                                  client_state.public_key, server_state.public_key,
                                  cipher, keys);
    OPENSSL_cleanse(shared.data(), shared.size());
    return ok;
}

void TunnelCodec::cleanse_handshake_state(TunnelHandshakeState& state) {
    if (!state.private_key.empty()) {
        OPENSSL_cleanse(state.private_key.data(), state.private_key.size());
    }
    if (!state.nonce.empty()) {
        OPENSSL_cleanse(state.nonce.data(), state.nonce.size());
    }
    state = TunnelHandshakeState();
}

} // namespace tx
