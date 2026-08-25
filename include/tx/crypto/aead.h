#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tx {

enum class AeadCipherKind : uint8_t {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2
};

const char* aead_cipher_name(AeadCipherKind kind);
bool parse_aead_cipher(const std::string& name, AeadCipherKind& kind);

class AeadCipher {
public:
    static constexpr size_t kKeyLen = 32;
    static constexpr size_t kNonceLen = 12;
    static constexpr size_t kTagLen = 16;
    static constexpr size_t kOverhead = kTagLen;

    AeadCipher(AeadCipherKind kind, const uint8_t* key, size_t key_len = kKeyLen);
    ~AeadCipher();

    AeadCipher(const AeadCipher&) = delete;
    AeadCipher& operator=(const AeadCipher&) = delete;

    AeadCipherKind kind() const { return kind_; }

    int encrypt(const uint8_t nonce[kNonceLen],
                const uint8_t* aad, size_t aad_len,
                const uint8_t* plaintext, size_t plaintext_len,
                uint8_t* output, size_t output_len);

    int decrypt(const uint8_t nonce[kNonceLen],
                const uint8_t* aad, size_t aad_len,
                const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* tag,
                uint8_t* plaintext, size_t plaintext_len);

private:
    struct Impl;

    AeadCipherKind kind_;
    uint8_t key_[kKeyLen];
    std::unique_ptr<Impl> impl_;
};

} // namespace tx
