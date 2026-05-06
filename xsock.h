#ifndef XSOCK_H
#define XSOCK_H

#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <mstcpip.h>

    #ifdef _MSC_VER
        #pragma comment(lib, "ws2_32.lib")
    #endif

    #define SOCKET_T SOCKET
    #define CLOSE_SOCKET(s) closesocket(s)
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define SHUTDOWN_SOCKET(s, how) shutdown(s, how)
    #define SHUTDOWN_WR SD_SEND
    #define GET_ERRNO() WSAGetLastError()
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <errno.h>
    #include <fcntl.h>

    #define SOCKET_T int
    #define CLOSE_SOCKET(s) close(s)
    #define SHUTDOWN_SOCKET(s, how) shutdown(s, how)
    #define SHUTDOWN_WR SHUT_WR
    #define GET_ERRNO() errno
    #define INVALID_SOCKET -1
    #define INVALID_SOCKET_VAL -1
    #define SOCKET_ERROR_VAL -1

    typedef int BOOL;
    #define TRUE 1
    #define FALSE 0
#endif

#if defined(__ANDROID__)
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 4
#endif

#ifndef INT_PTR
typedef intptr_t INT_PTR;
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

#ifdef __cplusplus
extern "C" {
#endif

typedef long long long64;

static inline SOCKET_T tcp_socket_create(void) {
    SOCKET_T sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET_VAL) {
        #ifdef _WIN32
            fprintf(stderr, "socket create failed: %d\n", WSAGetLastError());
        #else
            perror("socket create failed");
        #endif
        return INVALID_SOCKET_VAL;
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

static inline void socket_set_keepalive(SOCKET_T sock, int idle_sec, int interval_sec, int times) {
    int keepalive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));

#ifdef _WIN32
    (void)times;
    #ifndef TCP_KEEPIDLE
        #define TCP_KEEPIDLE 3
    #endif
    #ifndef TCP_KEEPINTVL
        #define TCP_KEEPINTVL 17
    #endif
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&idle_sec, sizeof(idle_sec));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&interval_sec, sizeof(interval_sec));
#elif defined(__linux__)
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle_sec, sizeof(idle_sec));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval_sec, sizeof(interval_sec));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &times, sizeof(times));
#elif defined(__APPLE__) || defined(__MACH__)
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &idle_sec, sizeof(idle_sec));
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
    unsigned long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode);
}

static inline BOOL socket_check_eagain(void) {
    int err = GET_ERRNO();
    return err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS;
}

static inline long64 time_get_ms(void) {
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

static inline BOOL socket_check_eagain(void) {
    int err = GET_ERRNO();
    return err == EWOULDBLOCK || err == EAGAIN || err == EINTR || err == EINPROGRESS;
}

static inline long64 time_get_ms(void) {
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

#define XSOCK_OK 0
#define XSOCK_ERR -1
#define XSOCK_ERR_LEN 256

/* Connection flags */
#define XSOCK_CONNECT_NONE 0
#define XSOCK_CONNECT_NONBLOCK 1

/** ========== Client Connection ==========**\
 * Connect to a remote address.
 * If port is -1, 'addr' is treated as a Unix Domain Socket path.
 * Otherwise, 'addr' is treated as an IP or Hostname.
 */
SOCKET_T xsock_connect(char *err, const char *addr, int port, int flags);

/* Helper wrappers */
SOCKET_T xsock_tcp_connect(char *err, const char *addr, int port);
SOCKET_T xsock_tcp_aconnect(char *err, const char *addr, int port);

/* ========== Server Logic ========== **\
 * Create a listening socket.
 * If port is -1, 'bindaddr' is the path for Unix Domain Socket.
 * If port > 0, 'bindaddr' is the local IP to bind (NULL for any).
 */
SOCKET_T xsock_listen(char *err, const char *bindaddr, int port);

/**
 * Accept a new connection.
 * Supports both TCP and Unix Domain Sockets.
 */
SOCKET_T xsock_accept(char *err, SOCKET_T serversock, char *ip, int *port);

/* ========== I/O Operations ========== */
int xsock_read(SOCKET_T fd, char *buf, int count);
int xsock_read_with_timeout(SOCKET_T fd, char *buf, int count, long long timeout_ms);
int xsock_write(SOCKET_T fd, const char *buf, int count);

/* ========== Socket Configuration ========== */
int xsock_set_nonblock(char *err, SOCKET_T fd);
int xsock_set_tcp_nodelay(char *err, SOCKET_T fd);
int xsock_set_keepalive(char *err, SOCKET_T fd);
int xsock_set_send_buffer(char *err, SOCKET_T fd, int buffsize);

/* ========== Utilities ========== */
int xsock_resolve(char *err, const char *host, char *ipbuf);
int xsock_get_peer_info(SOCKET_T fd, char *ip, int *port);
void xsock_close(SOCKET_T fd);

#ifdef __cplusplus
}
#endif

#endif /* XSOCK_H */
