#pragma once

#include <cstdio>
#include <cstdarg>
#include <string>

namespace tx {

enum class LogLevel {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
    Fatal = 4,
    Off   = 5,
};

void set_log_level(LogLevel level);
LogLevel get_log_level();
void set_log_file(FILE* fp);
void log_impl(LogLevel level, const char* file, int line, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define TX_LOG(level, ...) \
    do { \
        if (level >= tx::get_log_level()) { \
            tx::log_impl(level, __FILE__, __LINE__, __VA_ARGS__); \
        } \
    } while (0)

#define TX_DEBUG(...) TX_LOG(tx::LogLevel::Debug, __VA_ARGS__)
#define TX_INFO(...)  TX_LOG(tx::LogLevel::Info,  __VA_ARGS__)
#define TX_WARN(...)  TX_LOG(tx::LogLevel::Warn,  __VA_ARGS__)
#define TX_ERROR(...) TX_LOG(tx::LogLevel::Error, __VA_ARGS__)
#define TX_FATAL(...) TX_LOG(tx::LogLevel::Fatal, __VA_ARGS__)

} // namespace tx
