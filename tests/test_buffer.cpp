#include "tx/net/buffer.h"
#include "tx/net/tcp_flow_bridge.h"

#include <cassert>
#include <cstdio>
#include <limits>
#include <stdexcept>
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

static void test_strict_bounds_and_self_append() {
    tx::Buffer buffer(1);
    const uint8_t values[] = {1, 2, 3, 4};
    buffer.append(values, sizeof(values));
    buffer.append(buffer);
    assert(buffer.readable() == 8);
    for (size_t i = 0; i < 8; ++i) assert(buffer.data()[i] == values[i % 4]);

    const uint8_t* own_data = buffer.data();
    buffer.append(own_data, buffer.readable());
    assert(buffer.readable() == 16);
    for (size_t i = 0; i < 16; ++i) assert(buffer.data()[i] == values[i % 4]);

    bool threw = false;
    try { buffer.commit(buffer.writable_bytes() + 1); }
    catch (const std::out_of_range&) { threw = true; }
    assert(threw);
    threw = false;
    try { buffer.prepend(values, buffer.capacity() + 1); }
    catch (const std::out_of_range&) { threw = true; }
    assert(threw);
    threw = false;
    try { buffer.append(static_cast<const uint8_t*>(nullptr), 1); }
    catch (const std::invalid_argument&) { threw = true; }
    assert(threw);
    threw = false;
    try { tx::Buffer huge(std::numeric_limits<size_t>::max()); }
    catch (const std::length_error&) { threw = true; }
    assert(threw);

    tx::Buffer empty;
    tx::TcpFlowBridge bridge(nullptr, nullptr);
    assert(bridge.forward_from_left(empty));
    assert(bridge.forward_from_right(empty));
}

int main() {
    printf("=== Buffer Tests ===\n");
    test_compacts_consumed_prefix_before_growth();
    test_misaligned_frame_stream_stays_bounded();
    test_clear_preserves_reusable_capacity();
    test_strict_bounds_and_self_append();
    printf("All Buffer tests passed!\n");
    return 0;
}
