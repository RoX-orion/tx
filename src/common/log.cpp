#include "tx/common/log.h"
#include <cstdio>
#include <cstring>
#include <ctime>

#if defined(TX_PLATFORM_ANDROID)
#include <android/log.h>
#endif

namespace tx {

static LogLevel g_level = LogLevel::Info;
static FILE* g_log_file = nullptr;

void set_log_level(LogLevel level) { g_level = level; }
LogLevel get_log_level() { return g_level; }
void set_log_file(FILE* fp) { g_log_file = fp; }

static const char* level_str(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DBG";
        case LogLevel::Info:  return "INF";
        case LogLevel::Warn:  return "WRN";
        case LogLevel::Error: return "ERR";
        case LogLevel::Fatal: return "FTL";
        default:              return "???";
    }
}

void log_impl(LogLevel level, const char* file, int line, const char* fmt, ...) {
    // Extract filename
    const char* slash = strrchr(file, '/');
    const char* backslash = strrchr(file, '\\');
    const char* separator = !slash ? backslash
                                   : (!backslash || slash > backslash ? slash : backslash);
    const char* fname = separator ? separator + 1 : file;

#if defined(TX_PLATFORM_ANDROID)
    if (!g_log_file) {
        int priority = ANDROID_LOG_INFO;
        switch (level) {
            case LogLevel::Debug: priority = ANDROID_LOG_DEBUG; break;
            case LogLevel::Info:  priority = ANDROID_LOG_INFO; break;
            case LogLevel::Warn:  priority = ANDROID_LOG_WARN; break;
            case LogLevel::Error: priority = ANDROID_LOG_ERROR; break;
            case LogLevel::Fatal: priority = ANDROID_LOG_FATAL; break;
            default: break;
        }
        char message[2048];
        va_list args;
        va_start(args, fmt);
        vsnprintf(message, sizeof(message), fmt, args);
        va_end(args);
        __android_log_print(priority, "TX", "%s:%d: %s", fname, line, message);
        if (level == LogLevel::Fatal) abort();
        return;
    }
#endif

    FILE* out = g_log_file ? g_log_file : stderr;

    // Timestamp
    time_t now = time(nullptr);
    struct tm tm_buf;
#if defined(TX_PLATFORM_WINDOWS)
    localtime_s(&tm_buf, &now);
#else
    localtime_r(&now, &tm_buf);
#endif
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    fprintf(out, "[%s] %s %s:%d: ", timebuf, level_str(level), fname, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fputc('\n', out);
    fflush(out);

    if (level == LogLevel::Fatal) {
        abort();
    }
}

} // namespace tx
