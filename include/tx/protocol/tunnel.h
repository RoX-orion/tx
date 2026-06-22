#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include "tx/common/types.h"
#include "tx/net/buffer.h"
#include "tx/crypto/aes_gcm.h"

namespace tx {

// Tunnel protocol: encrypted channel between client and server
//
// Wire format (before encryption, inside payload):
//   [Version:1][Command:1][SessionID:4][AddrType:1][TargetAddr:var][Payload:var]
//
// After encryption, each message is:
//   [TotalLen:4][Nonce:12][Ciphertext:var][Tag:16]
//
// The outer length prefix allows framing over TCP stream.

class TunnelCodec {
public:
    static constexpr uint8_t kVersion = 0x01;
    static constexpr size_t kLenPrefixSize = 4;    // big-endian length prefix
    static constexpr size_t kMinFrameSize = kLenPrefixSize + AesGcm::kOverhead;
    static constexpr size_t kMaxPlaintextSize = 66000;
    static constexpr size_t kMaxEncryptedFrameSize = kMaxPlaintextSize + AesGcm::kOverhead;
    static constexpr size_t kDataHeaderSize = 6;
    static constexpr size_t kMaxDataPayloadSize = kMaxPlaintextSize - kDataHeaderSize;
    static constexpr size_t kHandshakeNonceSize = 16;
    static constexpr size_t kHandshakeMacSize = 32;
    static constexpr size_t kHandshakeSize = 4 + 1 + kHandshakeNonceSize + kHandshakeMacSize;

    TunnelCodec() : aes_(nullptr) {}
    explicit TunnelCodec(std::shared_ptr<AesGcm> aes) : aes_(std::move(aes)) {}

    // Encode a tunnel message (plaintext) into encrypted frame
    // Returns encrypted frame: [len:4][nonce:12][ciphertext+tag]
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

    std::shared_ptr<AesGcm> aes() const { return aes_; }
    bool has_protocol_error() const { return protocol_error_; }
    void clear_protocol_error() { protocol_error_ = false; }

    static bool build_client_hello(const std::vector<uint8_t>& master_key,
                                   Buffer& out,
                                   std::vector<uint8_t>& client_nonce);
    static bool parse_client_hello(const std::vector<uint8_t>& master_key,
                                   const uint8_t* data, size_t len,
                                   std::vector<uint8_t>& client_nonce);
    static bool build_server_hello(const std::vector<uint8_t>& master_key,
                                   const std::vector<uint8_t>& client_nonce,
                                   Buffer& out,
                                   std::vector<uint8_t>& server_nonce);
    static bool parse_server_hello(const std::vector<uint8_t>& master_key,
                                   const std::vector<uint8_t>& client_nonce,
                                   const uint8_t* data, size_t len,
                                   std::vector<uint8_t>& server_nonce);
    static std::vector<uint8_t> derive_session_key(const std::vector<uint8_t>& master_key,
                                                   const std::vector<uint8_t>& client_nonce,
                                                   const std::vector<uint8_t>& server_nonce);

private:
    // Build plaintext message body
    size_t build_message(TunnelCmd cmd, SessionId session_id,
                         const TargetAddr* target,
                         const uint8_t* payload, size_t payload_len,
                         uint8_t* out, size_t out_len);

    std::shared_ptr<AesGcm> aes_;
    bool protocol_error_ = false;
};

} // namespace tx
