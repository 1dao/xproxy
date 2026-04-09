#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ANDROID__)
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 4
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 5
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 6
#endif
#endif
#if defined(__linux__)
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 21
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 25
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 19
#endif
#endif
#ifndef INT_PTR
typedef intptr_t INT_PTR;
#endif

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define SOCKET_T SOCKET
    #define CLOSE_SOCKET(s) closesocket(s)
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define SHUTDOWN_SOCKET(s, how) shutdown(s, how)
    #define SHUTDOWN_WR SD_SEND
    #define GET_ERRNO() WSAGetLastError()
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <errno.h>
    #include <fcntl.h>  // Added for fcntl, F_GETFL, F_SETFL, O_NONBLOCK
    #define SOCKET_T int
    #define CLOSE_SOCKET(s) close(s)
    #define SOCKET_ERROR_VAL -1
    #define INVALID_SOCKET -1
    #ifndef max
        #define max(a,b) ((a) > (b) ? (a) : (b))
    #endif
    #define SHUTDOWN_SOCKET(s, how) shutdown(s, how)
    #define SHUTDOWN_WR SHUT_WR
    #define GET_ERRNO() errno
#endif

// Define BOOL for non-Windows platforms
#ifndef _WIN32
    typedef int BOOL;
    #define TRUE 1
    #define FALSE 0
#endif

// Include platform-specific TCP constants if needed
#if !defined(_WIN32) && (defined(__APPLE__) || defined(__MACH__))
    #include <netinet/tcp.h>  // Include TCP constants for macOS
#endif

typedef long long long64;

static inline SOCKET_T tcp_socket_create(void) {
    SOCKET_T sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == SOCKET_ERROR_VAL) {
        perror("socket create failed");
        return SOCKET_ERROR_VAL;
    }
    return sock;
}

static inline int socket_set_reuseaddr(SOCKET_T sock) {
    int opt = 1;
#ifdef _WIN32
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt, sizeof(opt));
#endif
}

static inline void socket_set_keepalive(SOCKET_T sock, int iddle_sec, int interval_sec, int times) {
    int keepalive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));

    #ifdef _WIN32
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&iddle_sec, sizeof(iddle_sec));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&interval_sec, sizeof(interval_sec));
    #elif defined(__linux__)
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &iddle_sec, sizeof(iddle_sec));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval_sec, sizeof(interval_sec));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &times, sizeof(times));
    #elif defined(__APPLE__) || defined(__MACH__)
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &iddle_sec, sizeof(iddle_sec));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval_sec, sizeof(interval_sec));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &times, sizeof(times));
    #endif
}

#ifdef _WIN32
static inline int winsock_init(void) {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

static inline void winsock_cleanup(void) {
    WSACleanup();
}

static inline int socket_set_nonblocking(SOCKET_T sock) {
    unsigned long mode = 1;  // Non-blocking mode
    return ioctlsocket(sock, FIONBIO, &mode);
}

static inline BOOL socket_check_eagain() {
    int err = GET_ERRNO();
    return err == WSAEWOULDBLOCK || err == WSAEINTR;
}

static inline long64 time_get_ms() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    return ull.QuadPart / 10000 - 11644473600000LL;
}

#define socket_init() winsock_init()
#define socket_cleanup() winsock_cleanup()
#else
static inline int socket_set_nonblocking(SOCKET_T sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

static inline BOOL socket_check_eagain() {
    int err = GET_ERRNO();
    return err == EWOULDBLOCK || err == EAGAIN || err == EINTR;
}

static inline long64 time_get_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long64)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

#define socket_init() 0
#define socket_cleanup() do {} while(0)
#endif

#ifndef max
    #define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifdef __cplusplus
}
#endif
#endif // SOCKET_UTIL_H
