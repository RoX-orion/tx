#include "tx/protocol/tls_sni.h"

#include <algorithm>
#include <cctype>
#include <vector>

namespace tx {
namespace {

uint16_t read_u16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t read_u24(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) | data[2];
}

bool valid_hostname(const std::string& host) {
    if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.')
        return false;
    bool label_start = true;
    size_t label_length = 0;
    for (unsigned char ch : host) {
        if (ch == '.') {
            if (label_start || label_length > 63) return false;
            label_start = true;
            label_length = 0;
            continue;
        }
        if (!(std::isalnum(ch) || ch == '-')) return false;
        label_start = false;
        ++label_length;
    }
    return !label_start && label_length <= 63;
}

} // namespace

TlsSniResult extract_tls_sni(const uint8_t* data, size_t len, std::string& host) {
    host.clear();
    if (!data || len < 5) return TlsSniResult::NeedMore;
    if (data[0] != 22 || data[1] != 3) return TlsSniResult::NotFound;

    // A ClientHello may be split across multiple handshake records (not just
    // TCP reads). Reassemble record payloads before parsing its extensions.
    std::vector<uint8_t> handshake;
    size_t input_pos = 0;
    size_t required = 4;
    while (handshake.size() < required) {
        if (input_pos + 5 > len) return TlsSniResult::NeedMore;
        if (data[input_pos] != 22 || data[input_pos + 1] != 3)
            return TlsSniResult::NotFound;
        const size_t record_length = read_u16(data + input_pos + 3);
        if (input_pos + 5 + record_length > len) return TlsSniResult::NeedMore;
        handshake.insert(handshake.end(), data + input_pos + 5,
                         data + input_pos + 5 + record_length);
        input_pos += 5 + record_length;
        if (handshake.size() >= 4) {
            if (handshake[0] != 1) return TlsSniResult::NotFound;
            required = 4 + read_u24(handshake.data() + 1);
            if (required > 65539) return TlsSniResult::NotFound;
        }
    }

    const uint8_t* hello = handshake.data();
    const size_t record_length = handshake.size();
    const size_t hello_length = read_u24(hello + 1);
    if (hello_length + 4 > record_length) return TlsSniResult::NotFound;

    size_t pos = 4;
    const size_t end = 4 + hello_length;
    if (pos + 34 > end) return TlsSniResult::NotFound;
    pos += 34; // legacy_version + random
    if (pos + 1 > end) return TlsSniResult::NotFound;
    const size_t session_id_length = hello[pos++];
    if (pos + session_id_length + 2 > end) return TlsSniResult::NotFound;
    pos += session_id_length;
    const size_t cipher_length = read_u16(hello + pos);
    pos += 2;
    if (pos + cipher_length + 1 > end) return TlsSniResult::NotFound;
    pos += cipher_length;
    const size_t compression_length = hello[pos++];
    if (pos + compression_length == end) return TlsSniResult::NotFound;
    if (pos + compression_length + 2 > end) return TlsSniResult::NotFound;
    pos += compression_length;
    const size_t extensions_length = read_u16(hello + pos);
    pos += 2;
    if (pos + extensions_length > end) return TlsSniResult::NotFound;
    const size_t extensions_end = pos + extensions_length;

    while (pos + 4 <= extensions_end) {
        const uint16_t type = read_u16(hello + pos);
        const size_t extension_length = read_u16(hello + pos + 2);
        pos += 4;
        if (pos + extension_length > extensions_end) return TlsSniResult::NotFound;
        if (type == 0) {
            if (extension_length < 5) return TlsSniResult::NotFound;
            size_t name_pos = pos + 2;
            const size_t names_end = name_pos + read_u16(hello + pos);
            if (names_end > pos + extension_length) return TlsSniResult::NotFound;
            while (name_pos + 3 <= names_end) {
                const uint8_t name_type = hello[name_pos++];
                const size_t name_length = read_u16(hello + name_pos);
                name_pos += 2;
                if (name_pos + name_length > names_end) return TlsSniResult::NotFound;
                if (name_type == 0) {
                    host.assign(reinterpret_cast<const char*>(hello + name_pos), name_length);
                    std::transform(host.begin(), host.end(), host.begin(),
                                   [](unsigned char ch) {
                                       return static_cast<char>(std::tolower(ch));
                                   });
                    if (!valid_hostname(host)) {
                        host.clear();
                        return TlsSniResult::NotFound;
                    }
                    return TlsSniResult::Found;
                }
                name_pos += name_length;
            }
            return TlsSniResult::NotFound;
        }
        pos += extension_length;
    }
    return TlsSniResult::NotFound;
}

} // namespace tx
