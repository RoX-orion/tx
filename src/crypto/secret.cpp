#include "tx/crypto/secret.h"
#include "tx/common/log.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace tx {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool hex_value(char c, uint8_t& out) {
    if (c >= '0' && c <= '9') {
        out = static_cast<uint8_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        out = static_cast<uint8_t>(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        out = static_cast<uint8_t>(c - 'A' + 10);
        return true;
    }
    return false;
}

bool parse_hex(const std::string& text, std::vector<uint8_t>& out) {
    if (text.size() % 2 != 0) return false;
    std::vector<uint8_t> bytes(text.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t hi = 0;
        uint8_t lo = 0;
        if (!hex_value(text[i * 2], hi) || !hex_value(text[i * 2 + 1], lo)) {
            return false;
        }
        bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    out.swap(bytes);
    return true;
}

bool parse_base64(const std::string& text, std::vector<uint8_t>& out) {
    if (text.empty() || text.size() % 4 != 0) {
        return false;
    }

    std::vector<uint8_t> decoded((text.size() / 4) * 3 + 3);
    int len = EVP_DecodeBlock(decoded.data(),
                              reinterpret_cast<const unsigned char*>(text.data()),
                              static_cast<int>(text.size()));
    if (len < 0) {
        return false;
    }

    size_t padding = 0;
    if (!text.empty() && text[text.size() - 1] == '=') ++padding;
    if (text.size() > 1 && text[text.size() - 2] == '=') ++padding;
    decoded.resize(static_cast<size_t>(len) - padding);
    out.swap(decoded);
    return true;
}

bool parse_uuid_v4(const std::string& text, std::vector<uint8_t>& out) {
    if (text.size() != 36 ||
        text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-') {
        return false;
    }

    std::string hex;
    hex.reserve(32);
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '-') continue;
        hex.push_back(text[i]);
    }

    std::vector<uint8_t> bytes;
    if (!parse_hex(hex, bytes) || bytes.size() != 16) {
        return false;
    }

    const bool version4 = (bytes[6] & 0xf0) == 0x40;
    const bool rfc4122_variant = (bytes[8] & 0xc0) == 0x80;
    if (!version4 || !rfc4122_variant) {
        return false;
    }

    out.assign(Secret::kPskLen, 0);
    static const uint8_t label[] = {'t', 'x', '-', 'u', 'u', 'i', 'd', '-', 'p', 's', 'k'};
    return Secret::hkdf_sha256(label, sizeof(label),
                               bytes.data(), bytes.size(),
                               nullptr, 0,
                               out.data(), out.size());
}

bool starts_with(const std::string& s, const char* prefix) {
    size_t n = strlen(prefix);
    return s.size() >= n && s.compare(0, n, prefix) == 0;
}

} // namespace

bool Secret::parse_psk(const std::string& text, std::vector<uint8_t>& out) {
    std::string value = text;
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }), value.end());

    std::string low = lower(value);
    std::vector<uint8_t> bytes;

    if (starts_with(low, "base64:")) {
        if (!parse_base64(value.substr(7), bytes)) {
            TX_ERROR("Invalid base64 secret");
            return false;
        }
    } else if (starts_with(low, "hex:")) {
        if (!parse_hex(value.substr(4), bytes)) {
            TX_ERROR("Invalid hex secret");
            return false;
        }
    } else if (starts_with(low, "uuid-v4:")) {
        return parse_uuid_v4(value.substr(8), out);
    } else {
        TX_ERROR("Secret must use base64:, hex:, or uuid-v4: prefix");
        return false;
    }

    if (bytes.size() != kPskLen) {
        TX_ERROR("Secret must decode to exactly %zu bytes, got %zu", kPskLen, bytes.size());
        return false;
    }

    out.swap(bytes);
    return true;
}

bool Secret::generate_psk(std::vector<uint8_t>& out) {
    out.assign(kPskLen, 0);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        TX_ERROR("RAND_bytes failed for secret generation");
        out.clear();
        return false;
    }
    return true;
}

std::string Secret::encode_base64_secret(const uint8_t* data, size_t len) {
    std::vector<unsigned char> encoded(((len + 2) / 3) * 4 + 1);
    int n = EVP_EncodeBlock(encoded.data(), data, static_cast<int>(len));
    if (n < 0) return std::string();
    return std::string("base64:") +
           std::string(reinterpret_cast<const char*>(encoded.data()), static_cast<size_t>(n));
}

bool Secret::hkdf_sha256(const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len,
                         const uint8_t* info, size_t info_len,
                         uint8_t* out, size_t out_len) {
    if (!out || out_len == 0 || out_len > 255 * 32) {
        return false;
    }

    uint8_t zero_salt[32] = {0};
    if (!salt) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    uint8_t prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), salt, static_cast<int>(salt_len),
              ikm, ikm_len, prk, &prk_len) || prk_len != 32) {
        return false;
    }

    size_t written = 0;
    uint8_t previous[32];
    unsigned int previous_len = 0;
    uint8_t counter = 1;

    while (written < out_len) {
        std::vector<uint8_t> block_input;
        if (previous_len > 0) {
            block_input.insert(block_input.end(), previous, previous + previous_len);
        }
        if (info && info_len > 0) {
            block_input.insert(block_input.end(), info, info + info_len);
        }
        block_input.push_back(counter);

        unsigned char* mac = HMAC(EVP_sha256(), prk, static_cast<int>(prk_len),
                                  block_input.data(), block_input.size(),
                                  previous, &previous_len);
        if (mac != previous || previous_len != 32) {
            OPENSSL_cleanse(prk, sizeof(prk));
            OPENSSL_cleanse(previous, sizeof(previous));
            return false;
        }

        size_t n = std::min(static_cast<size_t>(previous_len), out_len - written);
        memcpy(out + written, previous, n);
        written += n;
        ++counter;
    }

    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(previous, sizeof(previous));
    return true;
}

} // namespace tx
