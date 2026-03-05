#ifndef XLOG_H
#define XLOG_H


#ifdef __ANDROID__
#define LOG_TAG "socks5_server"

#include <android/log.h>
#include <stdio.h>

// 日志回调函数声明（在 xproxy_jni.c 中实现）
extern void native_log_to_java(int level, const char* tag, const char* msg);

// Android 日志级别
#define XLOG_LEVEL_VERBOSE  2
#define XLOG_LEVEL_DEBUG    3
#define XLOG_LEVEL_INFO     4
#define XLOG_LEVEL_WARN     5
#define XLOG_LEVEL_ERROR    6
#define XLOG_LEVEL_FATAL    7

// 默认日志标签
#ifndef LOG_TAG
#define LOG_TAG "xproxy"
#endif

// 日志宏 - 同时输出到系统日志和 Java 回调
#define XLOGV(...) do { \
    __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__); \
    char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_VERBOSE, LOG_TAG, _buf); \
} while(0)

#define XLOGD(...) do { \
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); \
    char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_DEBUG, LOG_TAG, _buf); \
} while(0)

#define XLOGI(...) do { \
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
    char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_INFO, LOG_TAG, _buf); \
} while(0)

#define XLOGW(...) do { \
    __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); \
    char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_WARN, LOG_TAG, _buf); \
} while(0)

#define XLOGE(...) do { \
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
    char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_ERROR, LOG_TAG, _buf); \
} while(0)

#define XLOGF(...) do { \
    __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__); \
    char _buf[1024]; snprintf(_buf, sizeof(_buf), __VA_ARGS__); native_log_to_java(XLOG_LEVEL_FATAL, LOG_TAG, _buf); \
} while(0)
#else
// VT100 颜色代码
#define XLOG_COLOR_RED     "\033[31m"
#define XLOG_COLOR_GREEN   "\033[32m"
#define XLOG_COLOR_YELLOW  "\033[33m"
#define XLOG_COLOR_BLUE    "\033[34m"
#define XLOG_COLOR_MAGENTA "\033[35m"
#define XLOG_COLOR_CYAN    "\033[36m"
#define XLOG_COLOR_WHITE   "\033[37m"
#define XLOG_COLOR_GRAY    "\033[90m"
#define XLOG_COLOR_RESET   "\033[0m"

#define XLOGI(fmt, ...) do { printf(XLOG_COLOR_WHITE fmt XLOG_COLOR_RESET "\n", ##__VA_ARGS__); } while(0)
#define XLOGE(fmt, ...) do { fprintf(stderr, XLOG_COLOR_RED fmt XLOG_COLOR_RESET "\n", ##__VA_ARGS__); } while(0)
#define XLOGD(fmt, ...) do { printf(XLOG_COLOR_GRAY fmt XLOG_COLOR_RESET "\n", ##__VA_ARGS__); } while(0)
#define XLOGW(fmt, ...) do { fprintf(stderr, XLOG_COLOR_YELLOW fmt XLOG_COLOR_RESET "\n", ##__VA_ARGS__); } while(0)
#define XLOGV(fmt, ...) do { printf(XLOG_COLOR_CYAN fmt XLOG_COLOR_RESET "\n", ##__VA_ARGS__); } while(0)
#define XLOGF(fmt, ...) do { fprintf(stderr, XLOG_COLOR_MAGENTA fmt XLOG_COLOR_RESET "\n", ##__VA_ARGS__); } while(0)
#endif

#endif // XLOG_H
