#include "tx/crypto/aes_gcm.h"
#include "tx/crypto/aead.h"
#include "tx/crypto/key_derive.h"
#include "tx/crypto/secret.h"
#include "tx/common/log.h"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <string>
#include <limits>
#include <stdexcept>
#include <vector>

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

static void test_secret_parse() {
    printf("  test_secret_parse... ");

    std::vector<uint8_t> generated;
    assert(tx::Secret::generate_psk(generated));
    assert(generated.size() == tx::Secret::kPskLen);

    std::string encoded = tx::Secret::encode_base64_secret(generated.data(), generated.size());
    std::vector<uint8_t> parsed;
    assert(tx::Secret::parse_psk(encoded, parsed));
    assert(parsed == generated);

    assert(tx::Secret::parse_psk("uuid-v4:7e52be0e-6929-432b-b74e-4e1d559dbccb", parsed));
    assert(parsed.size() == tx::Secret::kPskLen);
    assert(!tx::Secret::parse_psk("uuid-v4:7e52be0e-6929-132b-b74e-4e1d559dbccb", parsed));
    assert(!tx::Secret::parse_psk("password123", parsed));
    assert(!tx::Secret::parse_psk(encoded + "\n", parsed));
    assert(!tx::Secret::parse_psk(encoded.substr(0, encoded.size() - 1), parsed));
    std::string noncanonical = encoded;
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const size_t last_data = noncanonical.find_last_not_of('=');
    const size_t alphabet_index = alphabet.find(noncanonical[last_data]);
    assert(alphabet_index != std::string::npos);
    noncanonical[last_data] = alphabet[(alphabet_index & ~size_t(3)) |
                                       ((alphabet_index + 1) & size_t(3))];
    assert(!tx::Secret::parse_psk(noncanonical, parsed));

    printf("OK\n");
}

static void test_crypto_input_bounds() {
    uint8_t key[tx::AeadCipher::kKeyLen] = {};
    bool threw = false;
    try { tx::AeadCipher invalid(tx::AeadCipherKind::Aes256Gcm, nullptr, 0); }
    catch (const std::invalid_argument&) { threw = true; }
    assert(threw);
    threw = false;
    try { tx::AesGcm invalid(key, sizeof(key) - 1); }
    catch (const std::invalid_argument&) { threw = true; }
    assert(threw);

    tx::AeadCipher aead(tx::AeadCipherKind::Aes256Gcm, key, sizeof(key));
    tx::AesGcm aes(key, sizeof(key));
    uint8_t nonce[tx::AeadCipher::kNonceLen] = {};
    uint8_t byte = 0;
    const size_t huge = static_cast<size_t>(std::numeric_limits<int>::max()) + 1;
    assert(aead.encrypt(nonce, nullptr, 0, &byte, huge, &byte,
                        std::numeric_limits<size_t>::max()) == -1);
    assert(aes.encrypt(nonce, &byte, huge, &byte,
                       std::numeric_limits<size_t>::max()) == -1);
}

static void test_aead_chacha20_poly1305() {
    printf("  test_aead_chacha20_poly1305... ");

    std::vector<uint8_t> key(tx::AeadCipher::kKeyLen, 0x33);
    tx::AeadCipher cipher(tx::AeadCipherKind::ChaCha20Poly1305, key.data(), key.size());

    uint8_t nonce[tx::AeadCipher::kNonceLen] = {0};
    const uint8_t aad[] = {'a', 'a', 'd'};
    const char* plaintext = "hello chacha";
    uint8_t encrypted[128];
    int enc_len = cipher.encrypt(nonce, aad, sizeof(aad),
                                 reinterpret_cast<const uint8_t*>(plaintext), strlen(plaintext),
                                 encrypted, sizeof(encrypted));
    assert(enc_len == static_cast<int>(strlen(plaintext) + tx::AeadCipher::kTagLen));

    uint8_t decrypted[128];
    int dec_len = cipher.decrypt(nonce, aad, sizeof(aad),
                                 encrypted, strlen(plaintext),
                                 encrypted + strlen(plaintext),
                                 decrypted, sizeof(decrypted));
    assert(dec_len == static_cast<int>(strlen(plaintext)));
    assert(memcmp(decrypted, plaintext, strlen(plaintext)) == 0);

    printf("OK\n");
}

static void test_aead_context_reuse_after_authentication_failure() {
    printf("  test_aead_context_reuse_after_authentication_failure... ");
    uint8_t key[tx::AeadCipher::kKeyLen] = {};
    uint8_t nonce[tx::AeadCipher::kNonceLen] = {};
    const uint8_t aad[] = {1, 2, 3};
    const uint8_t plaintext[] = {4, 5, 6, 7};

    for (auto kind : {tx::AeadCipherKind::Aes256Gcm,
                      tx::AeadCipherKind::ChaCha20Poly1305}) {
        tx::AeadCipher cipher(kind, key, sizeof(key));
        uint8_t encrypted[64] = {};
        const int encrypted_len = cipher.encrypt(
            nonce, aad, sizeof(aad), plaintext, sizeof(plaintext),
            encrypted, sizeof(encrypted));
        assert(encrypted_len == static_cast<int>(sizeof(plaintext) +
                                                 tx::AeadCipher::kTagLen));

        uint8_t bad_tag[tx::AeadCipher::kTagLen];
        std::memcpy(bad_tag, encrypted + sizeof(plaintext), sizeof(bad_tag));
        bad_tag[0] ^= 1;
        uint8_t decrypted[64];
        std::memset(decrypted, 0xa5, sizeof(decrypted));
        assert(cipher.decrypt(nonce, aad, sizeof(aad), encrypted,
                              sizeof(plaintext), bad_tag,
                              decrypted, sizeof(decrypted)) == -1);
        for (size_t i = 0; i < sizeof(plaintext); ++i) assert(decrypted[i] == 0);

        assert(cipher.decrypt(nonce, aad, sizeof(aad), encrypted,
                              sizeof(plaintext), encrypted + sizeof(plaintext),
                              decrypted, sizeof(decrypted)) ==
               static_cast<int>(sizeof(plaintext)));
        assert(std::memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
    }
    printf("OK\n");
}

int main() {
    printf("=== Crypto Tests ===\n");
    test_key_derive();
    test_deterministic_key_derive();
    test_encrypt_decrypt();
    test_tamper_detection();
    test_empty_plaintext();
    test_secret_parse();
    test_aead_chacha20_poly1305();
    test_aead_context_reuse_after_authentication_failure();
    test_crypto_input_bounds();
    printf("All crypto tests passed!\n");
    return 0;
}
