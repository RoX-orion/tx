#include "tx/crypto/aes_gcm.h"
#include "tx/crypto/key_derive.h"
#include "tx/common/log.h"

#include <cstdio>
#include <cstring>
#include <cassert>

static void test_key_derive() {
    printf("  test_key_derive... ");
    auto salt = tx::KeyDeriver::generate_salt();
    assert(salt.size() == tx::KeyDeriver::kSaltLen);

    auto key1 = tx::KeyDeriver::derive("password123", salt.data(), salt.size());
    auto key2 = tx::KeyDeriver::derive("password123", salt.data(), salt.size());
    assert(key1 == key2); // Same password + salt = same key

    auto key3 = tx::KeyDeriver::derive("different", salt.data(), salt.size());
    assert(key1 != key3); // Different password = different key

    printf("OK\n");
}

static void test_encrypt_decrypt() {
    printf("  test_encrypt_decrypt... ");
    auto salt = tx::KeyDeriver::generate_salt();
    auto key = tx::KeyDeriver::derive("test", salt.data(), salt.size());

    tx::AesGcm aes(key.data(), key.size());

    const char* plaintext = "Hello, World! This is a test message.";
    size_t pt_len = strlen(plaintext);

    uint8_t encrypted[256];
    int enc_len = aes.encrypt(reinterpret_cast<const uint8_t*>(plaintext), pt_len,
                               encrypted, sizeof(encrypted));
    assert(enc_len > 0);
    assert(static_cast<size_t>(enc_len) == pt_len + tx::AesGcm::kOverhead);

    uint8_t decrypted[256];
    int dec_len = aes.decrypt(encrypted, static_cast<size_t>(enc_len),
                               decrypted, sizeof(decrypted));
    assert(dec_len > 0);
    assert(static_cast<size_t>(dec_len) == pt_len);
    assert(memcmp(decrypted, plaintext, pt_len) == 0);

    printf("OK\n");
}

static void test_deterministic_key_derive() {
    printf("  test_deterministic_key_derive... ");
    auto key1 = tx::KeyDeriver::derive_deterministic("shared-password");
    auto key2 = tx::KeyDeriver::derive_deterministic("shared-password");
    auto key3 = tx::KeyDeriver::derive_deterministic("other-password");

    assert(key1.size() == tx::KeyDeriver::kKeyLen);
    assert(key1 == key2);
    assert(key1 != key3);

    printf("OK\n");
}

static void test_tamper_detection() {
    printf("  test_tamper_detection... ");
    auto salt = tx::KeyDeriver::generate_salt();
    auto key = tx::KeyDeriver::derive("test", salt.data(), salt.size());

    tx::AesGcm aes(key.data(), key.size());

    const char* plaintext = "secret data";
    uint8_t encrypted[128];
    int enc_len = aes.encrypt(reinterpret_cast<const uint8_t*>(plaintext), strlen(plaintext),
                               encrypted, sizeof(encrypted));
    assert(enc_len > 0);

    // Tamper with ciphertext
    encrypted[tx::AesGcm::kNonceLen] ^= 0xFF;

    uint8_t decrypted[128];
    int dec_len = aes.decrypt(encrypted, static_cast<size_t>(enc_len),
                               decrypted, sizeof(decrypted));
    assert(dec_len == -1); // Should fail

    printf("OK\n");
}

static void test_empty_plaintext() {
    printf("  test_empty_plaintext... ");
    auto salt = tx::KeyDeriver::generate_salt();
    auto key = tx::KeyDeriver::derive("test", salt.data(), salt.size());

    tx::AesGcm aes(key.data(), key.size());

    uint8_t encrypted[128];
    int enc_len = aes.encrypt(nullptr, 0, encrypted, sizeof(encrypted));
    assert(enc_len > 0);
    assert(static_cast<size_t>(enc_len) == tx::AesGcm::kOverhead);

    uint8_t decrypted[128];
    int dec_len = aes.decrypt(encrypted, static_cast<size_t>(enc_len),
                               decrypted, sizeof(decrypted));
    assert(dec_len == 0);

    printf("OK\n");
}

int main() {
    printf("=== Crypto Tests ===\n");
    test_key_derive();
    test_deterministic_key_derive();
    test_encrypt_decrypt();
    test_tamper_detection();
    test_empty_plaintext();
    printf("All crypto tests passed!\n");
    return 0;
}
