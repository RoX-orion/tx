#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

namespace tx {
namespace detail {

inline bool read_proto_varint(const uint8_t* data, size_t len, size_t& pos,
                              uint64_t& value) {
    value = 0;
    for (unsigned index = 0; index < 10; ++index) {
        if (pos >= len) return false;
        const uint8_t byte = data[pos++];
        if (index == 9 && (byte & 0xfeu) != 0) return false;
        value |= static_cast<uint64_t>(byte & 0x7fu) << (index * 7);
        if ((byte & 0x80u) == 0) return true;
    }
    return false;
}

inline bool read_proto_bytes(const uint8_t* data, size_t len, size_t& pos,
                             const uint8_t*& field, size_t& field_len) {
    uint64_t wire_len = 0;
    if (!read_proto_varint(data, len, pos, wire_len)) return false;
    const size_t remaining = len - pos;
    if (wire_len > remaining || wire_len > std::numeric_limits<size_t>::max()) return false;
    field_len = static_cast<size_t>(wire_len);
    field = data + pos;
    pos += field_len;
    return true;
}

inline bool skip_proto_field(const uint8_t* data, size_t len, size_t& pos,
                             uint32_t wire_type) {
    switch (wire_type) {
        case 0: {
            uint64_t ignored = 0;
            return read_proto_varint(data, len, pos, ignored);
        }
        case 1:
            if (len - pos < 8) return false;
            pos += 8;
            return true;
        case 2: {
            const uint8_t* ignored = nullptr;
            size_t ignored_len = 0;
            return read_proto_bytes(data, len, pos, ignored, ignored_len);
        }
        case 5:
            if (len - pos < 4) return false;
            pos += 4;
            return true;
        default:
            return false;
    }
}

} // namespace detail
} // namespace tx
