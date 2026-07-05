#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include "tx/common/types.h"
#include "tx/net/buffer.h"
#include "tx/crypto/aead.h"

namespace tx {

enum class TunnelDirection : uint8_t {
    ClientToServer = 1,
    ServerToClient = 2
};

struct TunnelHandshakeState {
    AeadCipherKind cipher = AeadCipherKind::Aes256Gcm;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> public_key;
};

struct TunnelPeerHello {
    AeadCipherKind cipher = AeadCipherKind::Aes256Gcm;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> public_key;
};

struct TunnelTrafficKeys {
    AeadCipherKind cipher = AeadCipherKind::Aes256Gcm;
    std::vector<uint8_t> client_to_server_key;
    std::vector<uint8_t> server_to_client_key;
    std::vector<uint8_t> client_to_server_nonce_prefix;
    std::vector<uint8_t> server_to_client_nonce_prefix;
};

// Tunnel protocol: encrypted channel between client and server
//
// Wire format (before encryption, inside payload):
//   [Version:1][Command:1][SessionID:4][AddrType:1][TargetAddr:var][Payload:var]
//
// After encryption, each message is:
//   [TotalLen:4][Ciphertext:var][Tag:16]
//
// Nonces are derived from a per-direction nonce prefix and an increasing
// 64-bit sequence number. Sequence/direction/version/length are authenticated
// as AEAD associated data.

class TunnelCodec {
public:
    static constexpr uint8_t kVersion = 0x01;
    static constexpr size_t kLenPrefixSize = 4;    // big-endian length prefix
    static constexpr size_t kMinFrameSize = kLenPrefixSize + AeadCipher::kOverhead;
    static constexpr size_t kMaxPlaintextSize = 66000;
    static constexpr size_t kMaxEncryptedFrameSize = kMaxPlaintextSize + AeadCipher::kOverhead;
    static constexpr size_t kDataHeaderSize = 6;
    static constexpr size_t kMaxDataPayloadSize = kMaxPlaintextSize - kDataHeaderSize;
    static constexpr size_t kHandshakeNonceSize = 16;
    static constexpr size_t kHandshakePublicKeySize = 32;
    static constexpr size_t kHandshakeMacSize = 32;
    static constexpr size_t kHandshakeSize =
        4 + 1 + 1 + kHandshakeNonceSize + kHandshakePublicKeySize + kHandshakeMacSize;

    TunnelCodec() = default;
    TunnelCodec(const TunnelTrafficKeys& keys, bool client_side);

    // Encode a tunnel message (plaintext) into encrypted frame
    // Returns encrypted frame: [len:4][ciphertext+tag]
    bool encode(TunnelCmd cmd, SessionId session_id,
                const TargetAddr& target,
                const uint8_t* payload, size_t payload_len,
                Buffer& out);

    // Encode DATA message (no address needed)
    bool encode_data(SessionId session_id,
                     const uint8_t* payload, size_t payload_len,
                     Buffer& out);

    // Encode DATA as one or more frames when payload exceeds one frame.
    bool encode_data_chunks(SessionId session_id,
                            const uint8_t* payload, size_t payload_len,
                            Buffer& out);

    // Encode one UDP datagram with its target/source address.
    bool encode_udp_packet(SessionId session_id,
                           const TargetAddr& target,
                           const uint8_t* payload, size_t payload_len,
                           Buffer& out);

    // Encode DISCONNECT message
    bool encode_disconnect(SessionId session_id, Buffer& out);

    // Encode CONNECT result message. Payload is a single byte: 1=success, 0=failure.
    bool encode_connect_result(SessionId session_id, bool success, Buffer& out);

    // Decode one frame from buffer. Returns true if a complete message was decoded.
    // Consumes bytes from 'in'. Parsed fields stored in output params.
    bool decode(Buffer& in,
                TunnelCmd& cmd, SessionId& session_id,
                TargetAddr& target,
                Buffer& payload);

    bool has_protocol_error() const { return protocol_error_; }
    void clear_protocol_error() { protocol_error_ = false; }

    static bool build_client_hello(const std::vector<uint8_t>& psk,
                                   AeadCipherKind cipher,
                                   Buffer& out,
                                   TunnelHandshakeState& state);
    static bool parse_client_hello(const std::vector<uint8_t>& psk,
                                   const uint8_t* data, size_t len,
                                   TunnelPeerHello& client_hello);
    static bool build_server_hello(const std::vector<uint8_t>& psk,
                                   const TunnelPeerHello& client_hello,
                                   Buffer& out,
                                   TunnelHandshakeState& server_state,
                                   TunnelTrafficKeys& keys);
    static bool parse_server_hello(const std::vector<uint8_t>& psk,
                                   const TunnelHandshakeState& client_state,
                                   const uint8_t* data, size_t len,
                                   TunnelTrafficKeys& keys);
    static void cleanse_handshake_state(TunnelHandshakeState& state);

private:
    // Build plaintext message body
    size_t build_message(TunnelCmd cmd, SessionId session_id,
                         const TargetAddr* target,
                         const uint8_t* payload, size_t payload_len,
                         uint8_t* out, size_t out_len);

    bool build_nonce(bool send, uint64_t seq, uint8_t out[AeadCipher::kNonceLen]) const;
    static constexpr size_t kAadSize = 20;
    void build_aad(TunnelDirection direction, uint64_t seq, uint32_t frame_len,
                   uint8_t out[kAadSize]) const;

    std::shared_ptr<AeadCipher> send_cipher_;
    std::shared_ptr<AeadCipher> recv_cipher_;
    std::vector<uint8_t> send_nonce_prefix_;
    std::vector<uint8_t> recv_nonce_prefix_;
    TunnelDirection send_direction_ = TunnelDirection::ClientToServer;
    TunnelDirection recv_direction_ = TunnelDirection::ServerToClient;
    AeadCipherKind cipher_kind_ = AeadCipherKind::Aes256Gcm;
    uint64_t send_seq_ = 0;
    uint64_t recv_seq_ = 0;
    bool protocol_error_ = false;
};

} // namespace tx
