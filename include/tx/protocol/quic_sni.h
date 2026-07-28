#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tx {

enum class QuicSniResult {
    NeedMore,
    Found,
    NotQuic,
    UnsupportedVersion,
    Malformed,
    NoServerName,
};

// Reassembles QUIC Initial CRYPTO frames and extracts the TLS ClientHello SNI.
// QUIC Initial keys are intentionally derivable from public packet fields; no
// TLS application data is decrypted by this helper.
class QuicSniSniffer {
public:
    static constexpr size_t kMaxCryptoBytes = 16 * 1024;

    QuicSniSniffer();

    QuicSniResult feed(const uint8_t* data, size_t len, std::string& host);
    void reset();

    bool started() const { return started_; }
    size_t buffered_bytes() const { return buffered_bytes_; }

private:
    QuicSniResult add_crypto_fragment(uint64_t offset, const uint8_t* data,
                                      size_t len, std::string& host);

    bool started_;
    std::vector<uint8_t> crypto_;
    std::vector<uint8_t> present_;
    size_t contiguous_bytes_;
    size_t buffered_bytes_;
};

} // namespace tx
