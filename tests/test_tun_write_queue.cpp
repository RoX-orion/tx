#include "tx/net/tun_write_queue.h"

#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
    tx::TunWriteQueue queue(2, 5);
    const uint8_t first[] = {1, 2, 3};
    const uint8_t second[] = {4, 5};
    const uint8_t extra[] = {6};

    assert(queue.push(first, sizeof(first)));
    assert(queue.push(second, sizeof(second)));
    assert(!queue.push(extra, sizeof(extra)));
    assert(queue.packet_count() == 2);
    assert(queue.byte_count() == 5);
    assert(queue.front().readable() == sizeof(first));
    assert(std::memcmp(queue.front().data(), first, sizeof(first)) == 0);

    queue.pop();
    assert(queue.packet_count() == 1);
    assert(queue.byte_count() == sizeof(second));
    assert(std::memcmp(queue.front().data(), second, sizeof(second)) == 0);

    tx::Buffer moved(1);
    moved.append(extra, sizeof(extra));
    assert(queue.push(std::move(moved)));
    assert(queue.packet_count() == 2);
    assert(queue.byte_count() == 3);

    queue.clear();
    assert(queue.empty());
    assert(queue.byte_count() == 0);
    assert(!queue.push(nullptr, 1));

    std::printf("tun write queue tests passed\n");
    return 0;
}
