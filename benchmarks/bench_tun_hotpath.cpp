#include "tx/net/tun_write_queue.h"

#include <uv.h>
#include <cstdio>
#include <vector>

int main() {
    constexpr size_t iterations = 1000000;
    std::vector<uint8_t> packet(1400, 0x45);
    tx::TunWriteQueue queue(1, packet.size());
    size_t checksum = 0;
    const uint64_t start = uv_hrtime();
    for (size_t i = 0; i < iterations; ++i) {
        if (!queue.push(packet.data(), packet.size())) return 1;
        checksum += queue.front().data()[0];
        queue.pop();
    }
    const uint64_t elapsed = uv_hrtime() - start;
    std::printf("tun_queue packet=1400 iterations=%zu ns/op=%.2f checksum=%zu\n",
                iterations, static_cast<double>(elapsed) / iterations, checksum);
    return 0;
}
