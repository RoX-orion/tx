#pragma once

#include "tx/common/log.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace tx {
namespace detail {

inline bool read_geo_file(const std::string& path, std::vector<uint8_t>& data) {
    data.clear();

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        TX_ERROR("Failed to open geo file: %s", path.c_str());
        return false;
    }

    const std::streampos end = file.tellg();
    if (end == std::streampos(-1)) {
        TX_ERROR("Failed to determine geo file size: %s", path.c_str());
        return false;
    }

    const std::streamoff file_size = static_cast<std::streamoff>(end);
    if (file_size == 0) {
        TX_WARN("Geo file is empty: %s", path.c_str());
        return false;
    }

    const uintmax_t max_size = (std::min)(
        static_cast<uintmax_t>(std::numeric_limits<size_t>::max()),
        static_cast<uintmax_t>(std::numeric_limits<std::streamsize>::max()));
    if (static_cast<uintmax_t>(file_size) > max_size) {
        TX_ERROR("Geo file is too large: %s", path.c_str());
        return false;
    }

    data.resize(static_cast<size_t>(file_size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(data.data()),
                   static_cast<std::streamsize>(data.size()))) {
        TX_ERROR("Failed to read geo file: %s", path.c_str());
        data.clear();
        return false;
    }

    TX_INFO("Loaded %s: %zu bytes", path.c_str(), data.size());
    return true;
}

} // namespace detail
} // namespace tx
