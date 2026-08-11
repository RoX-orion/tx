#include "tx/net/buffer.h"

#include <cassert>
#include <cstdio>
#include <vector>

static void test_compacts_consumed_prefix_before_growth() {
    printf("  test_compacts_consumed_prefix_before_growth... ");

    tx::Buffer buffer(64);
    const uint8_t first[] = {1, 2, 3, 4};
    const uint8_t second[] = {5, 6, 7, 8, 9, 10};
    buffer.append(first, sizeof(first));
    buffer.consume(2);
    const size_t before = buffer.capacity();
    buffer.append(second, sizeof(second));

    assert(buffer.capacity() == before);
    assert(buffer.readable() == 8);
    const uint8_t expected[] = {3, 4, 5, 6, 7, 8, 9, 10};
    for (size_t i = 0; i < sizeof(expected); ++i) {
        assert(buffer.data()[i] == expected[i]);
    }

    printf("OK\n");
}

static void test_misaligned_frame_stream_stays_bounded() {
    printf("  test_misaligned_frame_stream_stays_bounded... ");

    // Model a 64 KiB read followed by a decoder that leaves a small partial
    // frame in the persistent input buffer.  Before compaction this pattern
    // grows the vector once per iteration and eventually reaches GiB sizes.
    tx::Buffer buffer;
    std::vector<uint8_t> chunk(65536, 0xa5);
    for (size_t i = 0; i < 1024; ++i) {
        buffer.append(chunk.data(), chunk.size());
        assert(buffer.readable() >= 100);
        buffer.consume(buffer.readable() - 100);
    }

    assert(buffer.readable() == 100);
    assert(buffer.capacity() <= 256 * 1024);
    printf("OK\n");
}

static void test_clear_preserves_reusable_capacity() {
    printf("  test_clear_preserves_reusable_capacity... ");

    tx::Buffer buffer;
    std::vector<uint8_t> data(32768, 0x3c);
    buffer.append(data.data(), data.size());
    const size_t capacity = buffer.capacity();
    buffer.clear();
    assert(buffer.empty());
    assert(buffer.capacity() == capacity);

    const uint8_t marker = 0x7f;
    buffer.append(&marker, 1);
    assert(buffer.readable() == 1);
    assert(buffer.data()[0] == marker);
    printf("OK\n");
}

int main() {
    printf("=== Buffer Tests ===\n");
    test_compacts_consumed_prefix_before_growth();
    test_misaligned_frame_stream_stays_bounded();
    test_clear_preserves_reusable_capacity();
    printf("All Buffer tests passed!\n");
    return 0;
}
