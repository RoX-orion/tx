#include "tx/protocol/tunnel.h"

#include <uv.h>
#include <cstdio>
#include <vector>

namespace {

tx::TunnelTrafficKeys keys(tx::AeadCipherKind kind) {
    tx::TunnelTrafficKeys result;
    result.cipher = kind;
    result.client_to_server_key.assign(tx::AeadCipher::kKeyLen, 0x11);
    result.server_to_client_key.assign(tx::AeadCipher::kKeyLen, 0x22);
    result.client_to_server_nonce_prefix = {1, 2, 3, 4};
    result.server_to_client_nonce_prefix = {5, 6, 7, 8};
    return result;
}

void run(tx::AeadCipherKind kind, size_t payload_size, size_t iterations) {
    tx::TunnelCodec codec(keys(kind), true);
    std::vector<uint8_t> payload(payload_size, 0x5a);
    tx::Buffer encoded(payload_size + 128);
    size_t bytes = 0;
    const uint64_t start = uv_hrtime();
    for (size_t i = 0; i < iterations; ++i) {
        encoded.clear();
        if (!codec.encode_data(1, payload.data(), payload.size(), encoded)) return;
        bytes += encoded.readable();
    }
    const uint64_t elapsed = uv_hrtime() - start;
    const double seconds = static_cast<double>(elapsed) / 1e9;
    std::printf("tunnel_encode cipher=%s payload=%zu frames/s=%.0f MiB/s=%.2f\n",
                tx::aead_cipher_name(kind), payload_size, iterations / seconds,
                bytes / seconds / (1024.0 * 1024.0));
}

} // namespace

int main() {
    for (auto kind : {tx::AeadCipherKind::Aes256Gcm,
                      tx::AeadCipherKind::ChaCha20Poly1305}) {
        run(kind, 64, 100000);
        run(kind, 512, 100000);
        run(kind, 1400, 50000);
        run(kind, 16384, 10000);
        run(kind, 60000, 2000);
    }
    return 0;
}
