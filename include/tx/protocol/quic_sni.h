#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
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
    ~QuicSniSniffer();

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
    // Initial packet numbers are truncated on the wire.  Keep the expected
    // value per DCID while this flow is being sniffed so the AEAD nonce is
    // reconstructed according to QUIC's packet-number decoding rules.
    std::unordered_map<std::string, uint64_t> expected_packet_numbers_;
    // version || DCID -> client Initial key, IV, and header-protection key.
    // The cache is bounded alongside packet-number spaces.
    std::unordered_map<std::string, std::vector<uint8_t>> initial_keys_;
    size_t contiguous_bytes_;
    size_t buffered_bytes_;
};

} // namespace tx
