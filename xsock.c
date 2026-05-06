#define _DEFAULT_SOURCE
#include "xsock.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

/* Ensure AF_UNIX/AF_LOCAL compatibility */
#ifndef _WIN32
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>

    /* Fallback for AF_LOCAL if only AF_UNIX is defined */
    #ifndef AF_LOCAL
        #define AF_LOCAL AF_UNIX
    #endif
#else
    /* On Windows, define a dummy AF_LOCAL for compilation if missing */
    #ifndef AF_LOCAL
        #define AF_LOCAL 1
    #endif
#endif

/* Set internal error message */
static void xsock_set_error(char *err, const char *fmt, ...) {
    if (!err) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, XSOCK_ERR_LEN, fmt, ap);
    va_end(ap);
}

/* Format system error message (cross-platform) */
static void xsock_format_error(char *err, const char *msg) {
    if (!err) return;
    char errbuf[XSOCK_ERR_LEN];
#ifdef _WIN32
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageA(flags, NULL, (DWORD)GET_ERRNO(), 0, errbuf, sizeof(errbuf), NULL);
    if (len > 0) {
        while (len > 0 && (errbuf[len-1] == '\r' || errbuf[len-1] == '\n')) len--;
        errbuf[len] = '\0';
    } else {
        snprintf(errbuf, sizeof(errbuf), "Unknown error %d", (int)GET_ERRNO());
    }
#else
    strncpy(errbuf, strerror(errno), sizeof(errbuf));
    errbuf[sizeof(errbuf)-1] = '\0';
#endif
    xsock_set_error(err, "%s: %s", msg, errbuf);
}

/* ========== Socket Options Implementation ========== */

int xsock_set_nonblock(char *err, SOCKET_T fd) {
    if (socket_set_nonblocking(fd) == -1) {
        xsock_format_error(err, "set_nonblock");
        return XSOCK_ERR;
    }
    return XSOCK_OK;
}

int xsock_set_tcp_nodelay(char *err, SOCKET_T fd) {
    int yes = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&yes, sizeof(yes)) == -1) {
        xsock_format_error(err, "setsockopt TCP_NODELAY");
        return XSOCK_ERR;
    }
    return XSOCK_OK;
}

int xsock_set_keepalive(char *err, SOCKET_T fd) {
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&yes, sizeof(yes)) == -1) {
        xsock_format_error(err, "setsockopt SO_KEEPALIVE");
        return XSOCK_ERR;
    }
    return XSOCK_OK;
}

int xsock_set_send_buffer(char *err, SOCKET_T fd, int buffsize) {
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&buffsize, sizeof(buffsize)) == -1) {
        xsock_format_error(err, "setsockopt SO_SNDBUF");
        return XSOCK_ERR;
    }
    return XSOCK_OK;
}

/* ========== Connection Logic ========== */

SOCKET_T xsock_connect(char *err, const char *addr, int port, int flags) {
    SOCKET_T s;
    int is_unix = (port == -1);
    int domain = AF_INET;

#ifdef _WIN32
    if (is_unix) {
        xsock_set_error(err, "Unix Domain Sockets not supported on Windows");
        return INVALID_SOCKET_VAL;
    }
#else
    if (is_unix) domain = AF_LOCAL;
#endif

    s = socket(domain, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET_VAL) {
        xsock_format_error(err, "socket creation failed");
        return INVALID_SOCKET_VAL;
    }

    if (flags & XSOCK_CONNECT_NONBLOCK) {
        if (xsock_set_nonblock(err, s) != XSOCK_OK) {
            CLOSE_SOCKET(s);
            return INVALID_SOCKET_VAL;
        }
    }

    if (is_unix) {
#ifndef _WIN32
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_LOCAL;
        strncpy(sa.sun_path, addr, sizeof(sa.sun_path)-1);
        if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == -1) goto conn_err;
#endif
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)port);
        if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
            struct hostent *he = gethostbyname(addr);
            if (!he) {
                xsock_set_error(err, "host resolution failed: %s", addr);
                CLOSE_SOCKET(s); return INVALID_SOCKET_VAL;
            }
            memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
        }
        if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == -1) goto conn_err;
    }
    return s;

conn_err:
    if (socket_check_eagain() && (flags & XSOCK_CONNECT_NONBLOCK)) return s;
    xsock_format_error(err, "connection failed");
    CLOSE_SOCKET(s);
    return INVALID_SOCKET_VAL;
}

SOCKET_T xsock_tcp_connect(char *err, const char *addr, int port) {
    return xsock_connect(err, addr, port, XSOCK_CONNECT_NONE);
}

SOCKET_T xsock_tcp_aconnect(char *err, const char *addr, int port) {
    return xsock_connect(err, addr, port, XSOCK_CONNECT_NONBLOCK);
}

/* ========== Server Listen & Accept Logic ========== */

SOCKET_T xsock_listen(char *err, const char *bindaddr, int port) {
    int is_unix = (port == -1);
    int domain = AF_INET;

#ifdef _WIN32
    if (is_unix) {
        xsock_set_error(err, "Unix sockets not supported on Windows");
        return INVALID_SOCKET_VAL;
    }
#else
    if (is_unix) domain = AF_LOCAL;
#endif

    SOCKET_T s = socket(domain, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET_VAL) { xsock_format_error(err, "socket creation failed"); return s; }

    socket_set_reuseaddr(s);

    if (is_unix) {
#ifndef _WIN32
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_LOCAL;
        strncpy(sa.sun_path, bindaddr, sizeof(sa.sun_path)-1);
        unlink(bindaddr);
        if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) == -1) goto listen_err;
#endif
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)port);
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bindaddr && inet_pton(AF_INET, bindaddr, &sa.sin_addr) != 1) {
            xsock_set_error(err, "invalid bind address");
            CLOSE_SOCKET(s); return INVALID_SOCKET_VAL;
        }
        if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) == -1) goto listen_err;
    }

    if (listen(s, 511) == -1) goto listen_err;
    return s;

listen_err:
    xsock_format_error(err, "bind/listen failed");
    CLOSE_SOCKET(s);
    return INVALID_SOCKET_VAL;
}

SOCKET_T xsock_accept(char *err, SOCKET_T s, char *ip, int *port) {
    SOCKET_T fd;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    while (1) {
        fd = accept(s, (struct sockaddr*)&sa, &salen);
        if (fd == INVALID_SOCKET_VAL) {
            if (GET_ERRNO() == EINTR) continue;
            xsock_format_error(err, "accept failed");
            return INVALID_SOCKET_VAL;
        }
        break;
    }

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET, &s4->sin_addr, ip, INET_ADDRSTRLEN);
        if (port) *port = ntohs(s4->sin_port);
    }
    return fd;
}

/* ========== Read / Write Implementation ========== */

int xsock_read(SOCKET_T fd, char *buf, int count) {
    int nread, totlen = 0;
    while (totlen < count) {
        nread = recv(fd, buf + totlen, count - totlen, 0);
        if (nread == 0) return totlen;
        if (nread == -1) return socket_check_eagain() ? totlen : -1;
        totlen += nread;
    }
    return totlen;
}

int xsock_write(SOCKET_T fd, const char *buf, int count) {
    int nwritten, totlen = 0;
    while (totlen < count) {
        nwritten = send(fd, buf + totlen, count - totlen, 0);
        if (nwritten <= 0) return socket_check_eagain() ? totlen : -1;
        totlen += nwritten;
    }
    return totlen;
}

void xsock_close(SOCKET_T fd) {
    if (fd != INVALID_SOCKET_VAL) CLOSE_SOCKET(fd);
}
