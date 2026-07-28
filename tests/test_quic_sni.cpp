#include "tx/protocol/quic_sni.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kVersionDraft29 = 0xff00001d;
constexpr uint32_t kVersion1 = 0x00000001;
constexpr uint32_t kVersion2 = 0x6b3343cf;

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

void push16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void push32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void push_varint(std::vector<uint8_t>& out, uint64_t value) {
    if (value < 64) {
        out.push_back(static_cast<uint8_t>(value));
    } else if (value < 16384) {
        push16(out, static_cast<uint16_t>(value | 0x4000));
    } else {
        assert(value < (1ULL << 30));
        push32(out, static_cast<uint32_t>(value | 0x80000000U));
    }
}

std::vector<uint8_t> client_hello(const std::string& host) {
    std::vector<uint8_t> body(34, 0);
    body[0] = 3;
    body[1] = 3;
    body.push_back(0); // session id length
    push16(body, 2);
    push16(body, 0x1301);
    body.push_back(1);
    body.push_back(0);

    std::vector<uint8_t> extensions;
    if (!host.empty()) {
        std::vector<uint8_t> sni;
        push16(sni, static_cast<uint16_t>(host.size() + 3));
        sni.push_back(0);
        push16(sni, static_cast<uint16_t>(host.size()));
        sni.insert(sni.end(), host.begin(), host.end());
        push16(extensions, 0);
        push16(extensions, static_cast<uint16_t>(sni.size()));
        extensions.insert(extensions.end(), sni.begin(), sni.end());
    }
    push16(body, static_cast<uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(1);
    handshake.push_back(static_cast<uint8_t>(body.size() >> 16));
    handshake.push_back(static_cast<uint8_t>(body.size() >> 8));
    handshake.push_back(static_cast<uint8_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

bool hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len,
                 uint8_t out[32]) {
    unsigned int out_len = 0;
    return HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, len, out, &out_len) == out &&
           out_len == 32;
}

bool hkdf_expand(const uint8_t prk[32], const std::vector<uint8_t>& info,
                 uint8_t* out, size_t len) {
    uint8_t previous[32] = {0};
    size_t previous_len = 0;
    size_t written = 0;
    uint8_t counter = 1;
    while (written < len) {
        std::vector<uint8_t> input;
        input.insert(input.end(), previous, previous + previous_len);
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        if (!hmac_sha256(prk, 32, input.data(), input.size(), previous)) return false;
        previous_len = 32;
        const size_t copied = std::min<size_t>(32, len - written);
        memcpy(out + written, previous, copied);
        written += copied;
    }
    return true;
}

bool hkdf_expand_label(const uint8_t secret[32], const char* label,
                       uint8_t* out, size_t out_len) {
    const size_t label_len = strlen(label);
    std::vector<uint8_t> info;
    push16(info, static_cast<uint16_t>(out_len));
    info.push_back(static_cast<uint8_t>(6 + label_len));
    static const uint8_t prefix[] = {'t', 'l', 's', '1', '3', ' '};
    info.insert(info.end(), prefix, prefix + sizeof(prefix));
    info.insert(info.end(), label, label + label_len);
    info.push_back(0);
    return hkdf_expand(secret, info, out, out_len);
}

bool aes_ecb_mask(const uint8_t key[16], const uint8_t sample[16], uint8_t out[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int written = 0;
    int final_written = 0;
    const bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1 &&
                    EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
                    EVP_EncryptUpdate(ctx, out, &written, sample, 16) == 1 &&
                    EVP_EncryptFinal_ex(ctx, out + written, &final_written) == 1 &&
                    written + final_written == 16;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

std::vector<uint8_t> aes_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                                     const std::vector<uint8_t>& aad,
                                     const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> encrypted(plaintext.size() + 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    assert(ctx);
    int ignored = 0;
    int written = 0;
    int final_written = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
              EVP_EncryptUpdate(ctx, nullptr, &ignored, aad.data(),
                                static_cast<int>(aad.size())) == 1 &&
              EVP_EncryptUpdate(ctx, encrypted.data(), &written, plaintext.data(),
                                static_cast<int>(plaintext.size())) == 1 &&
              EVP_EncryptFinal_ex(ctx, encrypted.data() + written, &final_written) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                                  encrypted.data() + written + final_written) == 1;
    EVP_CIPHER_CTX_free(ctx);
    assert(ok && written + final_written == static_cast<int>(plaintext.size()));
    return encrypted;
}

struct Labels {
    const uint8_t* salt;
    size_t salt_len;
    const char* key;
    const char* iv;
    const char* hp;
    uint8_t packet_type;
};

Labels labels_for(uint32_t version) {
    switch (version) {
        case kVersionDraft29:
            return {kSaltDraft29, sizeof(kSaltDraft29), "quic key", "quic iv", "quic hp", 0};
        case kVersion2:
            return {kSaltV2, sizeof(kSaltV2), "quicv2 key", "quicv2 iv", "quicv2 hp", 1};
        default:
            return {kSaltV1, sizeof(kSaltV1), "quic key", "quic iv", "quic hp", 0};
    }
}

std::vector<uint8_t> initial_packet(uint32_t version, uint8_t packet_number,
                                    uint64_t crypto_offset,
                                    const uint8_t* crypto, size_t crypto_len) {
    const Labels labels = labels_for(version);
    std::vector<uint8_t> plaintext;
    plaintext.push_back(0x06); // CRYPTO
    push_varint(plaintext, crypto_offset);
    push_varint(plaintext, crypto_len);
    plaintext.insert(plaintext.end(), crypto, crypto + crypto_len);

    const uint8_t dcid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    const uint8_t scid[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t initial_secret[32] = {0};
    uint8_t client_secret[32] = {0};
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t hp_key[16] = {0};
    assert(hmac_sha256(labels.salt, labels.salt_len, dcid, sizeof(dcid), initial_secret));
    assert(hkdf_expand_label(initial_secret, "client in", client_secret, sizeof(client_secret)));
    assert(hkdf_expand_label(client_secret, labels.key, key, sizeof(key)));
    assert(hkdf_expand_label(client_secret, labels.iv, iv, sizeof(iv)));
    assert(hkdf_expand_label(client_secret, labels.hp, hp_key, sizeof(hp_key)));

    std::vector<uint8_t> packet;
    packet.push_back(static_cast<uint8_t>(0xc0 | (labels.packet_type << 4)));
    push32(packet, version);
    packet.push_back(sizeof(dcid));
    packet.insert(packet.end(), dcid, dcid + sizeof(dcid));
    packet.push_back(sizeof(scid));
    packet.insert(packet.end(), scid, scid + sizeof(scid));
    packet.push_back(0); // token length
    push_varint(packet, 1 + plaintext.size() + 16);
    const size_t packet_number_offset = packet.size();
    packet.push_back(packet_number);

    iv[11] ^= packet_number;
    const std::vector<uint8_t> encrypted = aes_gcm_encrypt(key, iv, packet, plaintext);
    packet.insert(packet.end(), encrypted.begin(), encrypted.end());
    assert(packet_number_offset + 4 + 16 <= packet.size());

    uint8_t mask[16] = {0};
    assert(aes_ecb_mask(hp_key, packet.data() + packet_number_offset + 4, mask));
    packet[0] ^= static_cast<uint8_t>(mask[0] & 0x0f);
    packet[packet_number_offset] ^= mask[1];
    return packet;
}

void test_versions() {
    const std::vector<uint8_t> hello = client_hello("www.youtube.com");
    for (uint32_t version : {kVersionDraft29, kVersion1, kVersion2}) {
        const auto packet = initial_packet(version, 0, 0, hello.data(), hello.size());
        tx::QuicSniSniffer sniffer;
        std::string host;
        assert(sniffer.feed(packet.data(), packet.size(), host) == tx::QuicSniResult::Found);
        assert(host == "www.youtube.com");
    }
}

void test_fragmented_and_out_of_order() {
    const std::vector<uint8_t> hello = client_hello("video.googlevideo.com");
    const size_t split = 17;
    const auto first = initial_packet(kVersion1, 0, 0, hello.data(), split);
    const auto second = initial_packet(kVersion1, 1, split, hello.data() + split,
                                       hello.size() - split);
    std::string host;
    tx::QuicSniSniffer sniffer;
    assert(sniffer.feed(first.data(), first.size(), host) == tx::QuicSniResult::NeedMore);
    assert(sniffer.feed(second.data(), second.size(), host) == tx::QuicSniResult::Found);
    assert(host == "video.googlevideo.com");

    tx::QuicSniSniffer out_of_order;
    assert(out_of_order.feed(second.data(), second.size(), host) == tx::QuicSniResult::NeedMore);
    assert(out_of_order.feed(first.data(), first.size(), host) == tx::QuicSniResult::Found);
    assert(host == "video.googlevideo.com");

    tx::QuicSniSniffer duplicate;
    assert(duplicate.feed(first.data(), first.size(), host) == tx::QuicSniResult::NeedMore);
    assert(duplicate.feed(first.data(), first.size(), host) == tx::QuicSniResult::NeedMore);
    assert(duplicate.feed(second.data(), second.size(), host) == tx::QuicSniResult::Found);
    assert(host == "video.googlevideo.com");

    std::vector<uint8_t> conflicting_fragment(hello.begin(), hello.begin() + split);
    conflicting_fragment.back() ^= 0x01;
    const auto conflicting = initial_packet(kVersion1, 2, 0, conflicting_fragment.data(),
                                            conflicting_fragment.size());
    tx::QuicSniSniffer conflict;
    assert(conflict.feed(first.data(), first.size(), host) == tx::QuicSniResult::NeedMore);
    assert(conflict.feed(conflicting.data(), conflicting.size(), host) ==
           tx::QuicSniResult::Malformed);

    std::vector<uint8_t> coalesced = first;
    coalesced.insert(coalesced.end(), second.begin(), second.end());
    tx::QuicSniSniffer coalesced_sniffer;
    assert(coalesced_sniffer.feed(coalesced.data(), coalesced.size(), host) ==
           tx::QuicSniResult::Found);
    assert(host == "video.googlevideo.com");
}

void test_failures() {
    const std::vector<uint8_t> hello = client_hello("example.com");
    auto packet = initial_packet(kVersion1, 0, 0, hello.data(), hello.size());
    std::string host;
    tx::QuicSniSniffer sniffer;
    packet.back() ^= 0x80;
    assert(sniffer.feed(packet.data(), packet.size(), host) == tx::QuicSniResult::Malformed);

    const uint8_t not_quic[] = {0x00, 0x01, 0x02};
    assert(sniffer.feed(not_quic, sizeof(not_quic), host) == tx::QuicSniResult::NotQuic);

    auto unknown = initial_packet(kVersion1, 0, 0, hello.data(), hello.size());
    unknown[1] = 0x12;
    unknown[2] = 0x34;
    unknown[3] = 0x56;
    unknown[4] = 0x78;
    tx::QuicSniSniffer unsupported;
    assert(unsupported.feed(unknown.data(), unknown.size(), host) ==
           tx::QuicSniResult::UnsupportedVersion);

    const std::vector<uint8_t> no_name = client_hello("");
    const auto no_name_packet = initial_packet(kVersion1, 0, 0, no_name.data(), no_name.size());
    tx::QuicSniSniffer no_name_sniffer;
    assert(no_name_sniffer.feed(no_name_packet.data(), no_name_packet.size(), host) ==
           tx::QuicSniResult::NoServerName);

    std::vector<uint8_t> oversized(tx::QuicSniSniffer::kMaxCryptoBytes + 1, 0);
    const auto oversized_packet = initial_packet(kVersion1, 0, 0, oversized.data(),
                                                 oversized.size());
    tx::QuicSniSniffer oversized_sniffer;
    assert(oversized_sniffer.feed(oversized_packet.data(), oversized_packet.size(), host) ==
           tx::QuicSniResult::Malformed);
}

} // namespace

int main() {
    test_versions();
    test_fragmented_and_out_of_order();
    test_failures();
    std::printf("quic_sni tests passed\n");
    return 0;
}
