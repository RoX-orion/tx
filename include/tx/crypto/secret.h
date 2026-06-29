#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tx {

class Secret {
public:
    static constexpr size_t kPskLen = 32;

    static bool parse_psk(const std::string& text, std::vector<uint8_t>& out);
    static bool generate_psk(std::vector<uint8_t>& out);
    static std::string encode_base64_secret(const uint8_t* data, size_t len);

    static bool hkdf_sha256(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* out, size_t out_len);
};

} // namespace tx
