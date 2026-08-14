#include "tx/crypto/aes_gcm.h"
#include "tx/common/log.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <climits>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace tx {

AesGcm::AesGcm(const uint8_t* key, size_t key_len) {
    if (!key || key_len != kKeyLen)
        throw std::invalid_argument("AES-GCM key must be exactly 32 bytes");
    memcpy(key_, key, kKeyLen);
}

AesGcm::~AesGcm() {
    // Secure wipe
    OPENSSL_cleanse(key_, kKeyLen);
}

int AesGcm::encrypt(const uint8_t* plaintext, size_t plaintext_len,
                     uint8_t* output, size_t output_len) {
    // Generate random nonce
    uint8_t nonce[kNonceLen];
    if (RAND_bytes(nonce, kNonceLen) != 1) {
        TX_ERROR("RAND_bytes failed for nonce");
        return -1;
    }
    return encrypt(nonce, plaintext, plaintext_len, output, output_len);
}

int AesGcm::encrypt(const uint8_t* nonce,
                     const uint8_t* plaintext, size_t plaintext_len,
                     uint8_t* output, size_t output_len) {
    if (!nonce || (!plaintext && plaintext_len != 0) || !output ||
        plaintext_len > static_cast<size_t>(INT_MAX) ||
        plaintext_len > std::numeric_limits<size_t>::max() - kOverhead ||
        plaintext_len + kOverhead > static_cast<size_t>(INT_MAX)) {
        TX_ERROR("Invalid or oversized AES-GCM encryption input");
        return -1;
    }
    size_t total = kNonceLen + plaintext_len + kTagLen;
    if (output_len < total) {
        TX_ERROR("Output buffer too small: need %zu, got %zu", total, output_len);
        return -1;
    }

    // Write nonce to output
    memcpy(output, nonce, kNonceLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outlen = 0;
    int tmplen = 0;
    bool ok = true;

    ok = ok && (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_, nonce) == 1);

    if (ok && plaintext_len > 0) {
        ok = (EVP_EncryptUpdate(ctx, output + kNonceLen, &outlen,
                                 plaintext, static_cast<int>(plaintext_len)) == 1);
    }

    ok = ok && (EVP_EncryptFinal_ex(ctx, output + kNonceLen + outlen, &tmplen) == 1);
    outlen += tmplen;

    // Append tag
    if (ok) {
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                                   output + kNonceLen + outlen) == 1);
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        TX_ERROR("AES-GCM encryption failed");
        return -1;
    }

    return static_cast<int>(kNonceLen + outlen + kTagLen);
}

int AesGcm::decrypt(const uint8_t* input, size_t input_len,
                     uint8_t* output, size_t output_len) {
    if (!input || !output || input_len > static_cast<size_t>(INT_MAX)) {
        TX_ERROR("Invalid or oversized AES-GCM input");
        return -1;
    }
    if (input_len < kNonceLen + kTagLen) {
        TX_ERROR("Input too short for AES-GCM: %zu bytes", input_len);
        return -1;
    }

    const uint8_t* nonce = input;
    const uint8_t* ciphertext = input + kNonceLen;
    size_t ciphertext_len = input_len - kNonceLen - kTagLen;
    const uint8_t* tag = input + kNonceLen + ciphertext_len;

    return decrypt(nonce, ciphertext, ciphertext_len, tag, output, output_len);
}

int AesGcm::decrypt(const uint8_t* nonce,
                     const uint8_t* ciphertext, size_t ciphertext_len,
                     const uint8_t* tag,
                     uint8_t* plaintext, size_t plaintext_len) {
    if (!nonce || (!ciphertext && ciphertext_len != 0) || !tag || !plaintext ||
        ciphertext_len > static_cast<size_t>(INT_MAX)) {
        TX_ERROR("Invalid or oversized AES-GCM decryption input");
        return -1;
    }
    if (plaintext_len < ciphertext_len) {
        TX_ERROR("Plaintext buffer too small");
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outlen = 0;
    int tmplen = 0;
    bool ok = true;

    ok = ok && (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_, nonce) == 1);

    if (ok && ciphertext_len > 0) {
        ok = (EVP_DecryptUpdate(ctx, plaintext, &outlen,
                                 ciphertext, static_cast<int>(ciphertext_len)) == 1);
    }

    // Set expected tag
    if (ok) {
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                                   const_cast<uint8_t*>(tag)) == 1);
    }

    // Verify tag — this will fail if tampered
    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen) == 1);
    outlen += tmplen;

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        TX_ERROR("AES-GCM decryption failed (tag mismatch or corrupt data)");
        return -1;
    }

    return outlen;
}

} // namespace tx
