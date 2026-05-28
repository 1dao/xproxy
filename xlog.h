#ifndef XLOG_H
#define XLOG_H

#include <stddef.h>

/* Stack buffer used for the common short-log fast path. Records larger than
** this may use heap memory, then fall back to truncated stack output if heap
** allocation fails. */
#ifndef XLOG_RECORD_STACK_BYTES
#define XLOG_RECORD_STACK_BYTES 4096u
#endif

/* Longer formatted records are truncated to this many bytes instead of being
** dropped. Override at build time if a different per-record cap is needed. */
#ifndef XLOG_RECORD_MAX_BYTES
#define XLOG_RECORD_MAX_BYTES (1024u * 1024u)
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
    XLOG_LEVEL_VERBOSE = 2,
    XLOG_LEVEL_DEBUG   = 3,
    XLOG_LEVEL_INFO    = 4,
    XLOG_LEVEL_SYSM    = 5,
    XLOG_LEVEL_WARN    = 6,
    XLOG_LEVEL_ERROR   = 7,
    XLOG_LEVEL_FATAL   = 8
};

#define XLOG_LEVEL_NAME_VERBOSE "VERB"
#define XLOG_LEVEL_NAME_DEBUG   "DBUG"
#define XLOG_LEVEL_NAME_INFO    "INFO"
#define XLOG_LEVEL_NAME_SYSM    "SYSM"
#define XLOG_LEVEL_NAME_WARN    "WARN"
#define XLOG_LEVEL_NAME_ERROR   "ERRR"
#define XLOG_LEVEL_NAME_FATAL   "FATL"

#define XLOG_COLOR_CYAN    "\033[36m"
#define XLOG_COLOR_GRAY    "\033[90m"
#define XLOG_COLOR_WHITE   "\033[37m"
#define XLOG_COLOR_DARK_ORANGE "\033[38;5;166m"
#define XLOG_COLOR_YELLOW  "\033[33m"
#define XLOG_COLOR_RED     "\033[31m"
#define XLOG_COLOR_MAGENTA "\033[35m"
#define XLOG_COLOR_RESET   "\033[0m"

#define XLOG_TAG_VERBOSE XLOG_COLOR_CYAN    "[" XLOG_LEVEL_NAME_VERBOSE "]" XLOG_COLOR_RESET
#define XLOG_TAG_DEBUG   XLOG_COLOR_GRAY    "[" XLOG_LEVEL_NAME_DEBUG   "]" XLOG_COLOR_RESET
#define XLOG_TAG_INFO    XLOG_COLOR_WHITE   "[" XLOG_LEVEL_NAME_INFO    "]" XLOG_COLOR_RESET
#define XLOG_TAG_SYSM    XLOG_COLOR_DARK_ORANGE "[" XLOG_LEVEL_NAME_SYSM    "]" XLOG_COLOR_RESET
#define XLOG_TAG_WARN    XLOG_COLOR_YELLOW  "[" XLOG_LEVEL_NAME_WARN    "]" XLOG_COLOR_RESET
#define XLOG_TAG_ERROR   XLOG_COLOR_RED     "[" XLOG_LEVEL_NAME_ERROR   "]" XLOG_COLOR_RESET
#define XLOG_TAG_FATAL   XLOG_COLOR_MAGENTA "[" XLOG_LEVEL_NAME_FATAL   "]" XLOG_COLOR_RESET

void xlog_init(const char* log_dir, const char* process_name, int enable_console);
void xlog_uninit(void);
void xlog_set_level(int min_level);
int  xlog_get_level(void);
int  xlog_is_enabled(int level);
void xlog_printf(int level, const char* level_name, const char* console_tag, const char* fmt, ...);
void xlog_set_thread(int id, const char* name, const char* thread_label);
void xlog_clear_thread(void);
size_t xlog_format(int level, const char* level_name, const char* msg, size_t len, int append_newline, char* buf, size_t cap);
void xlog_write(int level, const char* level_name, const char* console_tag, const char* msg, size_t len, int append_newline);
void xlog_write_raw(const char* msg, size_t len);

#ifdef __ANDROID__
#include <android/log.h>
#include <stdio.h>

#ifndef LOG_TAG
#define LOG_TAG "socks5_server"
#endif

extern void native_log_to_java(int level, const char* tag, const char* msg);

#define xlogv(...) do { \
    if (xlog_is_enabled(XLOG_LEVEL_VERBOSE)) { \
        __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__); \
        char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_VERBOSE, LOG_TAG, _buf); \
    } \
} while(0)

#define xlogd(...) do { \
    if (xlog_is_enabled(XLOG_LEVEL_DEBUG)) { \
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); \
        char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_DEBUG, LOG_TAG, _buf); \
    } \
} while(0)

#define xlogi(...) do { \
    if (xlog_is_enabled(XLOG_LEVEL_INFO)) { \
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
        char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_INFO, LOG_TAG, _buf); \
    } \
} while(0)

#define xlogs(...) do { \
    if (xlog_is_enabled(XLOG_LEVEL_SYSM)) { \
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
        char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_SYSM, LOG_TAG, _buf); \
    } \
} while(0)

#define xlogw(...) do { \
    if (xlog_is_enabled(XLOG_LEVEL_WARN)) { \
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); \
        char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_WARN, LOG_TAG, _buf); \
    } \
} while(0)

#define xloge(...) do { \
    if (xlog_is_enabled(XLOG_LEVEL_ERROR)) { \
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
        char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_ERROR, LOG_TAG, _buf); \
    } \
} while(0)

#define xlogf(...) do { \
    if (xlog_is_enabled(XLOG_LEVEL_FATAL)) { \
        __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__); \
        char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_FATAL, LOG_TAG, _buf); \
    } \
} while(0)

#else

#define xlogi(fmt, ...) do { if (xlog_is_enabled(XLOG_LEVEL_INFO))    xlog_printf(XLOG_LEVEL_INFO,    XLOG_LEVEL_NAME_INFO,    XLOG_TAG_INFO,    fmt, ##__VA_ARGS__); } while(0)
#define xlogs(fmt, ...) do { if (xlog_is_enabled(XLOG_LEVEL_SYSM))    xlog_printf(XLOG_LEVEL_SYSM,    XLOG_LEVEL_NAME_SYSM,    XLOG_TAG_SYSM,    fmt, ##__VA_ARGS__); } while(0)
#define xloge(fmt, ...) do { if (xlog_is_enabled(XLOG_LEVEL_ERROR))   xlog_printf(XLOG_LEVEL_ERROR,   XLOG_LEVEL_NAME_ERROR,   XLOG_TAG_ERROR,   fmt, ##__VA_ARGS__); } while(0)
#define xlogd(fmt, ...) do { if (xlog_is_enabled(XLOG_LEVEL_DEBUG))   xlog_printf(XLOG_LEVEL_DEBUG,   XLOG_LEVEL_NAME_DEBUG,   XLOG_TAG_DEBUG,   fmt, ##__VA_ARGS__); } while(0)
#define xlogw(fmt, ...) do { if (xlog_is_enabled(XLOG_LEVEL_WARN))    xlog_printf(XLOG_LEVEL_WARN,    XLOG_LEVEL_NAME_WARN,    XLOG_TAG_WARN,    fmt, ##__VA_ARGS__); } while(0)
#define xlogv(fmt, ...) do { if (xlog_is_enabled(XLOG_LEVEL_VERBOSE)) xlog_printf(XLOG_LEVEL_VERBOSE, XLOG_LEVEL_NAME_VERBOSE, XLOG_TAG_VERBOSE, fmt, ##__VA_ARGS__); } while(0)
#define xlogf(fmt, ...) do { if (xlog_is_enabled(XLOG_LEVEL_FATAL))   xlog_printf(XLOG_LEVEL_FATAL,   XLOG_LEVEL_NAME_FATAL,   XLOG_TAG_FATAL,   fmt, ##__VA_ARGS__); } while(0)

#endif

/* Backward compatibility for legacy call sites. */
#ifndef XLOGV
#define XLOGV(...) xlogv(__VA_ARGS__)
#endif
#ifndef XLOGD
#define XLOGD(...) xlogd(__VA_ARGS__)
#endif
#ifndef XLOGI
#define XLOGI(...) xlogi(__VA_ARGS__)
#endif
#ifndef XLOGS
#define XLOGS(...) xlogs(__VA_ARGS__)
#endif
#ifndef XLOGW
#define XLOGW(...) xlogw(__VA_ARGS__)
#endif
#ifndef XLOGE
#define XLOGE(...) xloge(__VA_ARGS__)
#endif
#ifndef XLOGF
#define XLOGF(...) xlogf(__VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

#endif /* XLOG_H */
