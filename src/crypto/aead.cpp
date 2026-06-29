#include "tx/crypto/aead.h"
#include "tx/common/log.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace tx {

namespace {

const EVP_CIPHER* cipher_for(AeadCipherKind kind) {
    switch (kind) {
        case AeadCipherKind::Aes256Gcm:
            return EVP_aes_256_gcm();
        case AeadCipherKind::ChaCha20Poly1305:
            return EVP_chacha20_poly1305();
    }
    return nullptr;
}

std::string normalized(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

} // namespace

const char* aead_cipher_name(AeadCipherKind kind) {
    switch (kind) {
        case AeadCipherKind::Aes256Gcm:
            return "aes-256-gcm";
        case AeadCipherKind::ChaCha20Poly1305:
            return "chacha20-poly1305";
    }
    return "unknown";
}

bool parse_aead_cipher(const std::string& name, AeadCipherKind& kind) {
    std::string n = normalized(name);
    if (n == "aes-256-gcm" || n == "aes256-gcm" || n == "aes-gcm") {
        kind = AeadCipherKind::Aes256Gcm;
        return true;
    }
    if (n == "chacha20-poly1305" || n == "chacha20poly1305" || n == "chacha") {
        kind = AeadCipherKind::ChaCha20Poly1305;
        return true;
    }
    return false;
}

AeadCipher::AeadCipher(AeadCipherKind kind, const uint8_t* key, size_t key_len)
    : kind_(kind) {
    if (key_len < kKeyLen) {
        TX_FATAL("AEAD key must be at least %zu bytes", kKeyLen);
    }
    memcpy(key_, key, kKeyLen);
}

AeadCipher::~AeadCipher() {
    OPENSSL_cleanse(key_, kKeyLen);
}

int AeadCipher::encrypt(const uint8_t nonce[kNonceLen],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* plaintext, size_t plaintext_len,
                        uint8_t* output, size_t output_len) {
    if (output_len < plaintext_len + kTagLen) {
        TX_ERROR("AEAD output buffer too small");
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outlen = 0;
    int tmplen = 0;
    bool ok = true;
    const EVP_CIPHER* cipher = cipher_for(kind_);

    ok = ok && cipher != nullptr;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    if (kind_ == AeadCipherKind::Aes256Gcm) {
        ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) == 1);
    }
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_, nonce) == 1);

    if (ok && aad && aad_len > 0) {
        ok = (EVP_EncryptUpdate(ctx, nullptr, &tmplen,
                                aad, static_cast<int>(aad_len)) == 1);
    }

    if (ok && plaintext && plaintext_len > 0) {
        ok = (EVP_EncryptUpdate(ctx, output, &outlen,
                                plaintext, static_cast<int>(plaintext_len)) == 1);
    }

    ok = ok && (EVP_EncryptFinal_ex(ctx, output + outlen, &tmplen) == 1);
    outlen += tmplen;

    if (ok) {
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                                  output + outlen) == 1);
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        TX_ERROR("AEAD encryption failed");
        return -1;
    }

    return outlen + static_cast<int>(kTagLen);
}

int AeadCipher::decrypt(const uint8_t nonce[kNonceLen],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ciphertext, size_t ciphertext_len,
                        const uint8_t* tag,
                        uint8_t* plaintext, size_t plaintext_len) {
    if (plaintext_len < ciphertext_len) {
        TX_ERROR("AEAD plaintext buffer too small");
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outlen = 0;
    int tmplen = 0;
    bool ok = true;
    const EVP_CIPHER* cipher = cipher_for(kind_);

    ok = ok && cipher != nullptr;
    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    if (kind_ == AeadCipherKind::Aes256Gcm) {
        ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) == 1);
    }
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_, nonce) == 1);

    if (ok && aad && aad_len > 0) {
        ok = (EVP_DecryptUpdate(ctx, nullptr, &tmplen,
                                aad, static_cast<int>(aad_len)) == 1);
    }

    if (ok && ciphertext && ciphertext_len > 0) {
        ok = (EVP_DecryptUpdate(ctx, plaintext, &outlen,
                                ciphertext, static_cast<int>(ciphertext_len)) == 1);
    }

    if (ok) {
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                                  const_cast<uint8_t*>(tag)) == 1);
    }

    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen) == 1);
    outlen += tmplen;

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        TX_ERROR("AEAD decryption failed");
        return -1;
    }

    return outlen;
}

} // namespace tx
