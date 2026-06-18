#include "tx/common/log.h"
#include <cstdio>
#include <cstring>
#include <ctime>

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
    FILE* out = g_log_file ? g_log_file : stderr;

    // Timestamp
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    // Extract filename
    const char* fname = strrchr(file, '/');
    fname = fname ? fname + 1 : file;

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
