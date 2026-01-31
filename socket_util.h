#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define SOCKET_T SOCKET
    #define CLOSE_SOCKET(s) closesocket(s)
    #define SOCKET_ERROR_VAL SOCKET_ERROR
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #define SOCKET_T int
    #define CLOSE_SOCKET(s) close(s)
    #define SOCKET_ERROR_VAL -1
    #define INVALID_SOCKET -1
    #ifndef max
        #define max(a,b) ((a) > (b) ? (a) : (b))
    #endif
#endif

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

#ifdef _WIN32
static inline int winsock_init(void) {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

static inline void winsock_cleanup(void) {
    WSACleanup();
}

#define socket_init() winsock_init()
#define socket_cleanup() winsock_cleanup()
#else
#define socket_init() 0
#define socket_cleanup() do {} while(0)
#include <unistd.h>
#endif

#ifndef max
    #define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#endif // SOCKET_UTIL_H
