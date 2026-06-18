#pragma once

#include <cstdint>
#include <cstring>

namespace tx {

// Byte order utilities
inline uint16_t load_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t load_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
            static_cast<uint32_t>(p[3]);
}

inline uint64_t load_be64(const uint8_t* p) {
    return (static_cast<uint64_t>(load_be32(p)) << 32) | load_be32(p + 4);
}

inline void store_be16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline void store_be64(uint8_t* p, uint64_t v) {
    store_be32(p, static_cast<uint32_t>(v >> 32));
    store_be32(p + 4, static_cast<uint32_t>(v));
}

// Convenience overloads for raw pointers
inline uint16_t load_be16(const void* p) { return load_be16(static_cast<const uint8_t*>(p)); }
inline uint32_t load_be32(const void* p) { return load_be32(static_cast<const uint8_t*>(p)); }
inline void store_be16(void* p, uint16_t v) { store_be16(static_cast<uint8_t*>(p), v); }
inline void store_be32(void* p, uint32_t v) { store_be32(static_cast<uint8_t*>(p), v); }

} // namespace tx
