#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace tx {

// GeoIP data loader: reads V2Ray geoip.dat via mmap and builds RadixTree indexes.
class GeoData {
public:
    GeoData();
    ~GeoData();

    // Load geoip.dat file via mmap
    bool load_geoip(const std::string& path);

    // Load geosite.dat file via mmap
    bool load_geosite(const std::string& path);

    // Unload all data
    void unload();

    bool has_geoip() const { return geoip_loaded_; }
    bool has_geosite() const { return geosite_loaded_; }

    // Raw protobuf data access (for parsing into data structures)
    const uint8_t* geoip_data() const { return geoip_data_; }
    size_t geoip_size() const { return geoip_size_; }
    const uint8_t* geosite_data() const { return geosite_data_; }
    size_t geosite_size() const { return geosite_size_; }

private:
    // mmap a file, returns (data, size) or (nullptr, 0) on failure
    static std::pair<uint8_t*, size_t> mmap_file(const std::string& path);
    static void munmap_file(uint8_t* data, size_t size);

    uint8_t* geoip_data_;
    size_t   geoip_size_;
    bool     geoip_loaded_;

    uint8_t* geosite_data_;
    size_t   geosite_size_;
    bool     geosite_loaded_;
};

} // namespace tx
