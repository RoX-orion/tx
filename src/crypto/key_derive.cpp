#include "tx/crypto/key_derive.h"
#include "tx/common/log.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <climits>
#include <cstring>
#include <stdexcept>

namespace tx {

std::vector<uint8_t> KeyDeriver::generate_salt() {
    std::vector<uint8_t> salt(kSaltLen);
    if (RAND_bytes(salt.data(), static_cast<int>(kSaltLen)) != 1) {
        throw std::runtime_error("RAND_bytes failed for salt generation");
    }
    return salt;
}

std::vector<uint8_t> KeyDeriver::derive(const std::string& password,
                                         const uint8_t* salt, size_t salt_len,
                                         int iterations) {
    if (password.size() > static_cast<size_t>(INT_MAX) ||
        (!salt && salt_len != 0) || salt_len > static_cast<size_t>(INT_MAX) ||
        iterations <= 0) {
        throw std::invalid_argument("Invalid PBKDF2 input");
    }
    std::vector<uint8_t> key(kKeyLen);

    int r = PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                               salt, static_cast<int>(salt_len),
                               iterations,
                               EVP_sha256(),
                               static_cast<int>(kKeyLen),
                               key.data());
    if (r != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }

    TX_DEBUG("Derived %zu-byte key with %d iterations", kKeyLen, iterations);
    return key;
}

std::vector<uint8_t> KeyDeriver::derive_deterministic(const std::string& password) {
    static const uint8_t kProtocolSalt[] = {
        't', 'x', '-', 'a', 'e', 's', '-', 'g',
        'c', 'm', '-', 'v', '1', 0x00, 0x01, 0x00
    };

    auto key = derive(password, kProtocolSalt, sizeof(kProtocolSalt), kIter);
    TX_DEBUG("Derived deterministic %zu-byte key from password", key.size());
    return key;
}

} // namespace tx
