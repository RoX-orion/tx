#include "tx/protocol/tunnel.h"
#include "tx/common/endian.h"
#include "tx/common/log.h"
#include <cstring>
#include <arpa/inet.h>

namespace tx {

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
    if (payload_len > kMaxPlaintextSize - 6) {
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

bool TunnelCodec::decode(Buffer& in,
                          TunnelCmd& cmd, SessionId& session_id,
                          TargetAddr& target,
                          Buffer& payload) {
    target = TargetAddr();
    payload.clear();

    // Need at least length prefix
    if (in.readable() < kLenPrefixSize) return false;

    uint32_t frame_len = load_be32(in.data());
    if (frame_len > kMaxEncryptedFrameSize) {
        TX_ERROR("Tunnel frame too large: %u bytes", frame_len);
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
        in.consume(kLenPrefixSize + frame_len);
        return false;
    }

    cmd = static_cast<TunnelCmd>(plaintext[pos++]);
    session_id = load_be32(plaintext + pos);
    pos += 4;

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

} // namespace tx
