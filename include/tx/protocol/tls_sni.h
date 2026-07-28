#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace tx {

enum class TlsSniResult {
    NeedMore,
    NotFound,
    Found,
};

// Extracts server_name directly from a TLS ClientHello handshake message
// (handshake type + uint24 length + body). The caller is responsible for
// reassembling any transport-specific framing, such as QUIC CRYPTO frames.
TlsSniResult extract_tls_client_hello_sni(const uint8_t* data, size_t len,
                                          std::string& host);

// Extracts the clear-text server_name from a TLS ClientHello. NeedMore means
// that the caller should retain the bytes and retry after the next TCP read.
TlsSniResult extract_tls_sni(const uint8_t* data, size_t len, std::string& host);

} // namespace tx
