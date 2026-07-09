#pragma once

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace tx {

class PlatformTunDevice {
public:
    virtual ~PlatformTunDevice() = default;

    static std::unique_ptr<PlatformTunDevice> create();

    virtual bool open(const ClientConfig& config, std::string& error) = 0;
    virtual void close() = 0;
    virtual int fd() const { return -1; }
    virtual const std::string& name() const = 0;
    virtual std::ptrdiff_t read_packet(uint8_t* data, size_t len, std::string& error) = 0;
    virtual bool write_packet(const uint8_t* data, size_t len, std::string& error) = 0;
};

} // namespace tx
