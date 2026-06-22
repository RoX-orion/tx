#include "tx/geo/geo_data.h"
#include "tx/common/log.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstring>

namespace tx {

GeoData::GeoData()
    : geoip_mapping_{nullptr, 0, false
#ifdef _WIN32
      , nullptr, nullptr
#endif
      },
      geosite_mapping_{nullptr, 0, false
#ifdef _WIN32
      , nullptr, nullptr
#endif
      } {}

GeoData::~GeoData() {
    unload();
}

GeoData::FileMapping GeoData::mmap_file(const std::string& path) {
#ifdef _WIN32
    FileMapping mapping{nullptr, 0, false, nullptr, nullptr};

    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        TX_ERROR("Failed to open geo file: %s", path.c_str());
        return mapping;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file, &file_size)) {
        TX_ERROR("GetFileSizeEx failed for: %s", path.c_str());
        CloseHandle(file);
        return mapping;
    }

    if (file_size.QuadPart <= 0) {
        TX_WARN("Geo file is empty: %s", path.c_str());
        CloseHandle(file);
        return mapping;
    }

    HANDLE file_mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!file_mapping) {
        TX_ERROR("CreateFileMapping failed for: %s", path.c_str());
        CloseHandle(file);
        return mapping;
    }

    void* data = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!data) {
        TX_ERROR("MapViewOfFile failed for: %s", path.c_str());
        CloseHandle(file_mapping);
        CloseHandle(file);
        return mapping;
    }

    mapping.data = static_cast<uint8_t*>(data);
    mapping.size = static_cast<size_t>(file_size.QuadPart);
    mapping.loaded = true;
    mapping.file_handle = file;
    mapping.mapping_handle = file_mapping;

    TX_INFO("mapped %s: %zu bytes", path.c_str(), mapping.size);
    return mapping;
#else
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        TX_ERROR("Failed to open geo file: %s", path.c_str());
        return {nullptr, 0, false};
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        TX_ERROR("fstat failed for: %s", path.c_str());
        close(fd);
        return {nullptr, 0, false};
    }

    if (st.st_size == 0) {
        TX_WARN("Geo file is empty: %s", path.c_str());
        close(fd);
        return {nullptr, 0, false};
    }

    size_t size = static_cast<size_t>(st.st_size);
    void* data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) {
        TX_ERROR("mmap failed for: %s (%s)", path.c_str(), strerror(errno));
        return {nullptr, 0, false};
    }

    // Hint: sequential access for initial parse
    madvise(data, size, MADV_SEQUENTIAL);

    TX_INFO("mmap'd %s: %zu bytes", path.c_str(), size);
    return {static_cast<uint8_t*>(data), size, true};
#endif
}

void GeoData::munmap_file(FileMapping& mapping) {
    if (!mapping.loaded || !mapping.data || mapping.size == 0) {
        return;
    }

#ifdef _WIN32
    UnmapViewOfFile(mapping.data);
    if (mapping.mapping_handle) {
        CloseHandle(static_cast<HANDLE>(mapping.mapping_handle));
    }
    if (mapping.file_handle) {
        CloseHandle(static_cast<HANDLE>(mapping.file_handle));
    }
    mapping.file_handle = nullptr;
    mapping.mapping_handle = nullptr;
#else
    munmap(mapping.data, mapping.size);
#endif

    mapping.data = nullptr;
    mapping.size = 0;
    mapping.loaded = false;
}

bool GeoData::load_geoip(const std::string& path) {
    if (geoip_mapping_.loaded) {
        munmap_file(geoip_mapping_);
    }
    geoip_mapping_ = mmap_file(path);
    return geoip_mapping_.loaded;
}

bool GeoData::load_geosite(const std::string& path) {
    if (geosite_mapping_.loaded) {
        munmap_file(geosite_mapping_);
    }
    geosite_mapping_ = mmap_file(path);
    return geosite_mapping_.loaded;
}

void GeoData::unload() {
    if (geoip_mapping_.loaded) {
        munmap_file(geoip_mapping_);
    }
    if (geosite_mapping_.loaded) {
        munmap_file(geosite_mapping_);
    }
}

} // namespace tx
