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

    bool has_geoip() const { return geoip_mapping_.loaded; }
    bool has_geosite() const { return geosite_mapping_.loaded; }

    // Raw protobuf data access (for parsing into data structures)
    const uint8_t* geoip_data() const { return geoip_mapping_.data; }
    size_t geoip_size() const { return geoip_mapping_.size; }
    const uint8_t* geosite_data() const { return geosite_mapping_.data; }
    size_t geosite_size() const { return geosite_mapping_.size; }

private:
    struct FileMapping {
        uint8_t* data;
        size_t size;
        bool loaded;
#ifdef _WIN32
        void* file_handle;
        void* mapping_handle;
#endif
    };

    // Map a file, returns an empty mapping on failure.
    static FileMapping mmap_file(const std::string& path);
    static void munmap_file(FileMapping& mapping);

    FileMapping geoip_mapping_;
    FileMapping geosite_mapping_;
};

} // namespace tx
