#include "tx/protocol/quic_sni.h"

#include "tx/protocol/tls_sni.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace tx {
namespace {

constexpr uint32_t kQuicVersionDraft29 = 0xff00001d;
constexpr uint32_t kQuicVersion1 = 0x00000001;
constexpr uint32_t kQuicVersion2 = 0x6b3343cf;
constexpr size_t kSha256Size = 32;
constexpr size_t kAesBlockSize = 16;
constexpr size_t kGcmTagSize = 16;
constexpr size_t kMaxAckRanges = 256;
constexpr size_t kMaxInitialPacketNumberSpaces = 8;

const uint8_t kSaltDraft29[] = {
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
    0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
};
const uint8_t kSaltV1[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};
const uint8_t kSaltV2[] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

struct InitialLabels {
    const uint8_t* salt;
    size_t salt_len;
    const char* key_label;
    const char* iv_label;
    const char* hp_label;
    uint8_t initial_packet_type;
};

bool labels_for_version(uint32_t version, InitialLabels& labels) {
    switch (version) {
        case kQuicVersionDraft29:
            labels = {kSaltDraft29, sizeof(kSaltDraft29), "quic key", "quic iv",
                      "quic hp", 0};
            return true;
        case kQuicVersion1:
            labels = {kSaltV1, sizeof(kSaltV1), "quic key", "quic iv", "quic hp", 0};
            return true;
        case kQuicVersion2:
            labels = {kSaltV2, sizeof(kSaltV2), "quicv2 key", "quicv2 iv",
                      "quicv2 hp", 1};
            return true;
        default:
            return false;
    }
}

uint32_t load_u32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

uint32_t load_u24(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           static_cast<uint32_t>(data[2]);
}

bool read_varint(const uint8_t* data, size_t len, size_t& pos, uint64_t& value) {
    if (pos >= len) return false;
    const uint8_t first = data[pos];
    const size_t width = static_cast<size_t>(1) << (first >> 6);
    if (width > len - pos) return false;
    value = first & 0x3f;
    for (size_t i = 1; i < width; ++i) {
        value = (value << 8) | data[pos + i];
    }
    pos += width;
    return true;
}

bool hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len,
                 uint8_t out[kSha256Size]) {
    unsigned int out_len = 0;
    unsigned char* result = HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, len,
                                 out, &out_len);
    return result == out && out_len == kSha256Size;
}

bool hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,
                  uint8_t out[kSha256Size]) {
    return hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

bool hkdf_expand(const uint8_t prk[kSha256Size], const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len) {
    if (!out || out_len == 0 || out_len > 255 * kSha256Size) return false;

    uint8_t previous[kSha256Size] = {0};
    size_t previous_len = 0;
    size_t written = 0;
    uint8_t counter = 1;
    bool ok = true;
    while (written < out_len && ok) {
        std::vector<uint8_t> input;
        input.reserve(previous_len + info_len + 1);
        input.insert(input.end(), previous, previous + previous_len);
        input.insert(input.end(), info, info + info_len);
        input.push_back(counter);
        ok = hmac_sha256(prk, kSha256Size, input.data(), input.size(), previous);
        previous_len = kSha256Size;
        const size_t copied = std::min(kSha256Size, out_len - written);
        if (ok) {
            memcpy(out + written, previous, copied);
            written += copied;
            ++counter;
        }
    }
    OPENSSL_cleanse(previous, sizeof(previous));
    return ok;
}

bool hkdf_expand_label(const uint8_t secret[kSha256Size], const char* label,
                       uint8_t* out, size_t out_len) {
    if (!label || out_len > 65535) return false;
    const size_t label_len = strlen(label);
    if (label_len > 249) return false;

    std::vector<uint8_t> info;
    info.reserve(3 + 6 + label_len + 1);
    info.push_back(static_cast<uint8_t>(out_len >> 8));
    info.push_back(static_cast<uint8_t>(out_len));
    info.push_back(static_cast<uint8_t>(6 + label_len));
    static const uint8_t prefix[] = {'t', 'l', 's', '1', '3', ' '};
    info.insert(info.end(), prefix, prefix + sizeof(prefix));
    info.insert(info.end(), label, label + label_len);
    info.push_back(0); // empty context
    return hkdf_expand(secret, info.data(), info.size(), out, out_len);
}

bool aes_ecb_mask(const uint8_t key[16], const uint8_t sample[kAesBlockSize],
                  uint8_t mask[kAesBlockSize]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int written = 0;
    int final_written = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1 &&
              EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
              EVP_EncryptUpdate(ctx, mask, &written, sample, kAesBlockSize) == 1 &&
              EVP_EncryptFinal_ex(ctx, mask + written, &final_written) == 1 &&
              written + final_written == static_cast<int>(kAesBlockSize);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aes_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12], const uint8_t* aad,
                     size_t aad_len, const uint8_t* encrypted, size_t encrypted_len,
                     std::vector<uint8_t>& plaintext) {
    if (!encrypted || encrypted_len < kGcmTagSize) return false;
    const size_t ciphertext_len = encrypted_len - kGcmTagSize;
    plaintext.assign(ciphertext_len, 0);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        plaintext.clear();
        return false;
    }
    int ignored = 0;
    int written = 0;
    int final_written = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1;
    if (ok && aad_len > 0) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &ignored, aad, static_cast<int>(aad_len)) == 1;
    }
    if (ok && ciphertext_len > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &written, encrypted,
                               static_cast<int>(ciphertext_len)) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagSize,
                                 const_cast<uint8_t*>(encrypted + ciphertext_len)) == 1;
    }
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + written, &final_written) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok || written + final_written != static_cast<int>(ciphertext_len)) {
        plaintext.clear();
        return false;
    }
    return true;
}

enum class PacketParseResult {
    Initial,
    NotQuic,
    UnsupportedVersion,
    Malformed,
};

PacketParseResult decrypt_initial(const uint8_t* data, size_t len,
                                  std::vector<uint8_t>& plaintext,
                                  size_t& consumed,
                                  std::unordered_map<std::string, uint64_t>& expected_numbers,
                                  std::unordered_map<std::string,
                                                     std::vector<uint8_t>>& key_cache) {
    consumed = 0;
    if (!data || len < 7) return PacketParseResult::NotQuic;
    const uint8_t first = data[0];
    if ((first & 0xc0) != 0xc0) return PacketParseResult::NotQuic;

    const uint32_t version = load_u32(data + 1);
    InitialLabels labels;
    if (!labels_for_version(version, labels)) return PacketParseResult::UnsupportedVersion;
    if (((first & 0x30) >> 4) != labels.initial_packet_type) {
        return PacketParseResult::NotQuic;
    }

    size_t pos = 5;
    const uint8_t dcid_len = data[pos++];
    if (dcid_len == 0 || dcid_len > 20 || dcid_len > len - pos) {
        return PacketParseResult::Malformed;
    }
    const uint8_t* dcid = data + pos;
    const std::string dcid_key(reinterpret_cast<const char*>(dcid), dcid_len);
    std::string cache_key(reinterpret_cast<const char*>(data + 1), 4);
    cache_key.append(reinterpret_cast<const char*>(dcid), dcid_len);
    pos += dcid_len;
    if (pos >= len) return PacketParseResult::Malformed;
    const uint8_t scid_len = data[pos++];
    if (scid_len > 20 || scid_len > len - pos) return PacketParseResult::Malformed;
    pos += scid_len;

    uint64_t token_len = 0;
    if (!read_varint(data, len, pos, token_len) || token_len > len - pos) {
        return PacketParseResult::Malformed;
    }
    pos += static_cast<size_t>(token_len);
    uint64_t packet_len = 0;
    if (!read_varint(data, len, pos, packet_len) || packet_len > len - pos ||
        packet_len < 1 + kGcmTagSize) {
        return PacketParseResult::Malformed;
    }
    const size_t packet_number_offset = pos;
    const size_t packet_end = packet_number_offset + static_cast<size_t>(packet_len);
    if (packet_number_offset + 4 + kAesBlockSize > packet_end) {
        return PacketParseResult::Malformed;
    }

    uint8_t initial_secret[kSha256Size] = {0};
    uint8_t client_secret[kSha256Size] = {0};
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t hp_key[16] = {0};
    uint8_t mask[kAesBlockSize] = {0};
    bool ok = false;
    auto cached = key_cache.find(cache_key);
    if (cached != key_cache.end() && cached->second.size() == 44) {
        std::memcpy(key, cached->second.data(), sizeof(key));
        std::memcpy(iv, cached->second.data() + sizeof(key), sizeof(iv));
        std::memcpy(hp_key, cached->second.data() + sizeof(key) + sizeof(iv),
                    sizeof(hp_key));
        ok = true;
    } else {
        ok = hkdf_extract(labels.salt, labels.salt_len, dcid, dcid_len, initial_secret) &&
             hkdf_expand_label(initial_secret, "client in", client_secret,
                               sizeof(client_secret)) &&
             hkdf_expand_label(client_secret, labels.key_label, key, sizeof(key)) &&
             hkdf_expand_label(client_secret, labels.iv_label, iv, sizeof(iv)) &&
             hkdf_expand_label(client_secret, labels.hp_label, hp_key, sizeof(hp_key));
        if (ok) {
            if (key_cache.size() >= kMaxInitialPacketNumberSpaces) {
                for (auto& item : key_cache) {
                    if (!item.second.empty()) {
                        OPENSSL_cleanse(item.second.data(), item.second.size());
                    }
                }
                key_cache.clear();
            }
            std::vector<uint8_t> material;
            material.reserve(44);
            material.insert(material.end(), key, key + sizeof(key));
            material.insert(material.end(), iv, iv + sizeof(iv));
            material.insert(material.end(), hp_key, hp_key + sizeof(hp_key));
            key_cache.emplace(cache_key, std::move(material));
        }
    }
    ok = ok && aes_ecb_mask(hp_key, data + packet_number_offset + 4, mask);
    OPENSSL_cleanse(initial_secret, sizeof(initial_secret));
    OPENSSL_cleanse(client_secret, sizeof(client_secret));
    OPENSSL_cleanse(hp_key, sizeof(hp_key));
    if (!ok) {
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(iv, sizeof(iv));
        return PacketParseResult::Malformed;
    }

    std::vector<uint8_t> header(data, data + packet_number_offset + 4);
    header[0] ^= static_cast<uint8_t>(mask[0] & 0x0f);
    const size_t packet_number_len = static_cast<size_t>(header[0] & 0x03) + 1;
    if (packet_number_len > 4 || packet_number_offset + packet_number_len > packet_end) {
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(iv, sizeof(iv));
        return PacketParseResult::Malformed;
    }
    header.resize(packet_number_offset + packet_number_len);
    uint64_t truncated_packet_number = 0;
    for (size_t i = 0; i < packet_number_len; ++i) {
        header[packet_number_offset + i] ^= mask[i + 1];
        truncated_packet_number =
            (truncated_packet_number << 8) | header[packet_number_offset + i];
    }

    const uint64_t expected = expected_numbers.count(dcid_key)
        ? expected_numbers[dcid_key] : 0;
    const uint64_t packet_number_window = UINT64_C(1) << (packet_number_len * 8);
    const uint64_t packet_number_half_window = packet_number_window / 2;
    const uint64_t packet_number_mask = packet_number_window - 1;
    uint64_t packet_number = (expected & ~packet_number_mask) | truncated_packet_number;
    if (packet_number <= UINT64_MAX - packet_number_half_window &&
        packet_number + packet_number_half_window <= expected &&
        packet_number <= ((UINT64_C(1) << 62) - packet_number_window)) {
        packet_number += packet_number_window;
    } else if (packet_number > expected + packet_number_half_window &&
               packet_number >= packet_number_window) {
        packet_number -= packet_number_window;
    }
    for (size_t i = 0; i < 8; ++i) {
        iv[sizeof(iv) - 1 - i] ^= static_cast<uint8_t>(packet_number >> (8 * i));
    }

    const uint8_t* encrypted = data + packet_number_offset + packet_number_len;
    const size_t encrypted_len = packet_end - packet_number_offset - packet_number_len;
    ok = aes_gcm_decrypt(key, iv, header.data(), header.size(), encrypted, encrypted_len,
                         plaintext);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(mask, sizeof(mask));
    if (!ok) return PacketParseResult::Malformed;
    if (expected_numbers.find(dcid_key) == expected_numbers.end() &&
        expected_numbers.size() >= kMaxInitialPacketNumberSpaces) {
        expected_numbers.clear();
    }
    const uint64_t next_expected = packet_number == ((UINT64_C(1) << 62) - 1)
        ? packet_number : packet_number + 1;
    auto number_it = expected_numbers.find(dcid_key);
    if (number_it == expected_numbers.end() || number_it->second < next_expected) {
        expected_numbers[dcid_key] = next_expected;
    }
    consumed = packet_end;
    return PacketParseResult::Initial;
}

bool skip_ack_frame(const uint8_t* data, size_t len, size_t& pos, bool ecn) {
    uint64_t value = 0;
    if (!read_varint(data, len, pos, value) || !read_varint(data, len, pos, value)) return false;
    uint64_t range_count = 0;
    if (!read_varint(data, len, pos, range_count) || range_count > kMaxAckRanges ||
        !read_varint(data, len, pos, value)) {
        return false;
    }
    for (uint64_t i = 0; i < range_count; ++i) {
        if (!read_varint(data, len, pos, value) || !read_varint(data, len, pos, value)) {
            return false;
        }
    }
    if (ecn) {
        for (unsigned i = 0; i < 3; ++i) {
            if (!read_varint(data, len, pos, value)) return false;
        }
    }
    return true;
}

} // namespace

QuicSniSniffer::QuicSniSniffer()
    : started_(false), contiguous_bytes_(0), buffered_bytes_(0) {}

QuicSniSniffer::~QuicSniSniffer() { reset(); }

void QuicSniSniffer::reset() {
    started_ = false;
    std::vector<uint8_t>().swap(crypto_);
    std::vector<uint8_t>().swap(present_);
    expected_packet_numbers_.clear();
    for (auto& item : initial_keys_) {
        if (!item.second.empty()) {
            OPENSSL_cleanse(item.second.data(), item.second.size());
        }
    }
    initial_keys_.clear();
    contiguous_bytes_ = 0;
    buffered_bytes_ = 0;
}

QuicSniResult QuicSniSniffer::add_crypto_fragment(uint64_t offset, const uint8_t* data,
                                                   size_t len, std::string& host) {
    if (!data || offset > kMaxCryptoBytes || len > kMaxCryptoBytes - offset) {
        return QuicSniResult::Malformed;
    }
    const size_t start = static_cast<size_t>(offset);
    const size_t end = start + len;
    if (crypto_.size() < end) {
        crypto_.resize(end, 0);
        present_.resize(end, 0);
    }
    for (size_t i = 0; i < len; ++i) {
        const size_t index = start + i;
        if (present_[index]) {
            if (crypto_[index] != data[i]) return QuicSniResult::Malformed;
        } else {
            crypto_[index] = data[i];
            present_[index] = 1;
            ++buffered_bytes_;
        }
    }
    while (contiguous_bytes_ < present_.size() && present_[contiguous_bytes_]) {
        ++contiguous_bytes_;
    }
    if (contiguous_bytes_ < 4) return QuicSniResult::NeedMore;
    if (crypto_[0] != 1) return QuicSniResult::NoServerName;
    const size_t hello_len = 4 + static_cast<size_t>(load_u24(crypto_.data() + 1));
    if (hello_len > kMaxCryptoBytes) return QuicSniResult::Malformed;
    if (contiguous_bytes_ < hello_len) return QuicSniResult::NeedMore;

    const TlsSniResult tls_result =
        extract_tls_client_hello_sni(crypto_.data(), hello_len, host);
    if (tls_result == TlsSniResult::Found) return QuicSniResult::Found;
    if (tls_result == TlsSniResult::NeedMore) return QuicSniResult::NeedMore;
    return QuicSniResult::NoServerName;
}

QuicSniResult QuicSniSniffer::feed(const uint8_t* data, size_t len, std::string& host) {
    host.clear();
    size_t packet_offset = 0;
    while (packet_offset < len) {
        std::vector<uint8_t> plaintext;
        size_t packet_len = 0;
        const PacketParseResult packet_result = decrypt_initial(
            data + packet_offset, len - packet_offset, plaintext, packet_len,
            expected_packet_numbers_, initial_keys_);
        if (packet_result != PacketParseResult::Initial) {
            // Later packets in a coalesced datagram can be Handshake or
            // 0-RTT packets. Once an Initial was parsed, they simply provide
            // no additional ClientHello CRYPTO bytes to this sniffer.
            if (started_) return QuicSniResult::NeedMore;
            switch (packet_result) {
                case PacketParseResult::UnsupportedVersion:
                    return QuicSniResult::UnsupportedVersion;
                case PacketParseResult::Malformed:
                    return QuicSniResult::Malformed;
                default:
                    return QuicSniResult::NotQuic;
            }
        }
        if (packet_len == 0 || packet_len > len - packet_offset) {
            return QuicSniResult::Malformed;
        }
        started_ = true;

        size_t pos = 0;
        while (pos < plaintext.size()) {
            uint64_t frame_type = 0;
            if (!read_varint(plaintext.data(), plaintext.size(), pos, frame_type)) {
                return QuicSniResult::NeedMore;
            }
            switch (frame_type) {
                case 0x00: // PADDING
                case 0x01: // PING
                    break;
                case 0x02: // ACK
                    if (!skip_ack_frame(plaintext.data(), plaintext.size(), pos, false)) {
                        return QuicSniResult::Malformed;
                    }
                    break;
                case 0x03: // ACK_ECN
                    if (!skip_ack_frame(plaintext.data(), plaintext.size(), pos, true)) {
                        return QuicSniResult::Malformed;
                    }
                    break;
                case 0x06: { // CRYPTO
                    uint64_t offset = 0;
                    uint64_t crypto_len = 0;
                    if (!read_varint(plaintext.data(), plaintext.size(), pos, offset) ||
                        !read_varint(plaintext.data(), plaintext.size(), pos, crypto_len) ||
                        crypto_len > plaintext.size() - pos) {
                        return QuicSniResult::Malformed;
                    }
                    const QuicSniResult result = add_crypto_fragment(
                        offset, plaintext.data() + pos, static_cast<size_t>(crypto_len), host);
                    pos += static_cast<size_t>(crypto_len);
                    if (result != QuicSniResult::NeedMore) return result;
                    break;
                }
                case 0x1c: // CONNECTION_CLOSE (transport)
                case 0x1d: { // CONNECTION_CLOSE (application)
                    uint64_t value = 0;
                    if (!read_varint(plaintext.data(), plaintext.size(), pos, value)) {
                        return QuicSniResult::Malformed;
                    }
                    if (frame_type == 0x1c &&
                        !read_varint(plaintext.data(), plaintext.size(), pos, value)) {
                        return QuicSniResult::Malformed;
                    }
                    uint64_t reason_len = 0;
                    if (!read_varint(plaintext.data(), plaintext.size(), pos, reason_len) ||
                        reason_len > plaintext.size() - pos) {
                        return QuicSniResult::Malformed;
                    }
                    pos += static_cast<size_t>(reason_len);
                    break;
                }
                default:
                    return QuicSniResult::Malformed;
            }
        }
        packet_offset += packet_len;
    }
    return QuicSniResult::NeedMore;
}

} // namespace tx
