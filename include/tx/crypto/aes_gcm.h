#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>

namespace tx {

// AES-256-GCM encrypt/decrypt using OpenSSL EVP interface
class AesGcm {
public:
    static constexpr size_t kKeyLen  = 32;   // 256 bits
    static constexpr size_t kNonceLen = 12;  // 96 bits (recommended for GCM)
    static constexpr size_t kTagLen  = 16;   // 128 bits auth tag

    // Result = nonce(kNonceLen) || ciphertext || tag(kTagLen)
    // nonce is prepended automatically with a random value
    static constexpr size_t kOverhead = kNonceLen + kTagLen;

    explicit AesGcm(const uint8_t* key, size_t key_len = kKeyLen);
    ~AesGcm();

    // Non-copyable
    AesGcm(const AesGcm&) = delete;
    AesGcm& operator=(const AesGcm&) = delete;

    // Encrypt plaintext. Returns [nonce || ciphertext || tag]
    // Output buffer must be at least plaintext_len + kOverhead bytes
    // Returns total output length on success, -1 on failure
    int encrypt(const uint8_t* plaintext, size_t plaintext_len,
                uint8_t* output, size_t output_len);

    // Encrypt with specified nonce (for testing / counter mode)
    int encrypt(const uint8_t* nonce,
                const uint8_t* plaintext, size_t plaintext_len,
                uint8_t* output, size_t output_len);

    // Decrypt [nonce || ciphertext || tag]. Returns plaintext length or -1 on failure
    // Output buffer must be at least input_len - kOverhead bytes
    int decrypt(const uint8_t* input, size_t input_len,
                uint8_t* output, size_t output_len);

    // Decrypt with specified nonce
    int decrypt(const uint8_t* nonce,
                const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* tag,
                uint8_t* plaintext, size_t plaintext_len);

private:
    uint8_t key_[kKeyLen];
};

} // namespace tx
