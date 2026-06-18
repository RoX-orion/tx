#include "tx/geo/geo_data.h"
#include "tx/common/log.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

namespace tx {

GeoData::GeoData()
    : geoip_data_(nullptr), geoip_size_(0), geoip_loaded_(false),
      geosite_data_(nullptr), geosite_size_(0), geosite_loaded_(false) {}

GeoData::~GeoData() {
    unload();
}

std::pair<uint8_t*, size_t> GeoData::mmap_file(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        TX_ERROR("Failed to open geo file: %s", path.c_str());
        return {nullptr, 0};
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        TX_ERROR("fstat failed for: %s", path.c_str());
        close(fd);
        return {nullptr, 0};
    }

    if (st.st_size == 0) {
        TX_WARN("Geo file is empty: %s", path.c_str());
        close(fd);
        return {nullptr, 0};
    }

    size_t size = static_cast<size_t>(st.st_size);
    void* data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) {
        TX_ERROR("mmap failed for: %s (%s)", path.c_str(), strerror(errno));
        return {nullptr, 0};
    }

    // Hint: sequential access for initial parse
    madvise(data, size, MADV_SEQUENTIAL);

    TX_INFO("mmap'd %s: %zu bytes", path.c_str(), size);
    return {static_cast<uint8_t*>(data), size};
}

void GeoData::munmap_file(uint8_t* data, size_t size) {
    if (data && size > 0) {
        munmap(data, size);
    }
}

bool GeoData::load_geoip(const std::string& path) {
    if (geoip_loaded_) {
        munmap_file(geoip_data_, geoip_size_);
    }
    auto p = mmap_file(path);
    geoip_data_ = p.first;
    geoip_size_ = p.second;
    geoip_loaded_ = (geoip_data_ != nullptr);
    return geoip_loaded_;
}

bool GeoData::load_geosite(const std::string& path) {
    if (geosite_loaded_) {
        munmap_file(geosite_data_, geosite_size_);
    }
    auto p = mmap_file(path);
    geosite_data_ = p.first;
    geosite_size_ = p.second;
    geosite_loaded_ = (geosite_data_ != nullptr);
    return geosite_loaded_;
}

void GeoData::unload() {
    if (geoip_loaded_) {
        munmap_file(geoip_data_, geoip_size_);
        geoip_data_ = nullptr;
        geoip_size_ = 0;
        geoip_loaded_ = false;
    }
    if (geosite_loaded_) {
        munmap_file(geosite_data_, geosite_size_);
        geosite_data_ = nullptr;
        geosite_size_ = 0;
        geosite_loaded_ = false;
    }
}

} // namespace tx
