#include "tx/common/log.h"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <thread>

int main() {
    std::atomic<bool> start{false};
    const auto writer = [&start](tx::LogLevel first, tx::LogLevel second) {
        while (!start.load(std::memory_order_acquire)) {}
        for (unsigned i = 0; i < 100000; ++i)
            tx::set_log_level((i & 1u) == 0 ? first : second);
    };

    std::thread first(writer, tx::LogLevel::Debug, tx::LogLevel::Warn);
    std::thread second(writer, tx::LogLevel::Info, tx::LogLevel::Error);
    start.store(true, std::memory_order_release);
    for (unsigned i = 0; i < 100000; ++i) {
        const tx::LogLevel level = tx::get_log_level();
        assert(level >= tx::LogLevel::Debug && level <= tx::LogLevel::Off);
    }
    first.join();
    second.join();
    tx::set_log_level(tx::LogLevel::Info);
    std::printf("log concurrency tests passed\n");
    return 0;
}
