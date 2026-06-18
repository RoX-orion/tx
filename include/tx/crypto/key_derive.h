#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace tx {

// Derive a 256-bit key from password using PBKDF2-HMAC-SHA256
class KeyDeriver {
public:
    static constexpr size_t kKeyLen   = 32;  // AES-256
    static constexpr size_t kSaltLen  = 16;
    static constexpr int    kIter     = 100000;

    // Generate a random salt
    static std::vector<uint8_t> generate_salt();

    // Derive key from password + salt
    static std::vector<uint8_t> derive(const std::string& password,
                                       const uint8_t* salt, size_t salt_len,
                                       int iterations = kIter);

    // Deterministic key derivation with a fixed protocol salt.
    // Used when both sides must derive the same key without exchanging a salt.
    static std::vector<uint8_t> derive_deterministic(const std::string& password);
};

} // namespace tx
