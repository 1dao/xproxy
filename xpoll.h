#ifndef XPOLL_H
#define XPOLL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Backend selection ─────────────────────────────────────────────────────
 * Priority: epoll (Linux) > kqueue (macOS/BSD) > WSAPoll (Win32) > poll
 * Override by defining XPOLL_USE_POLL before including this header.
 * Define XPOLL_USE_IO_URING on Linux to enable the optional per-submit
 * completion API. The readiness backend remains epoll.
 * ------------------------------------------------------------------------- */
#if defined(_WIN32)
#   define XPOLL_BACKEND_WSAPOLL
#   include <winsock2.h>
#elif defined(__linux__) && defined(XPOLL_USE_IO_URING) && !defined(XPOLL_USE_POLL)
#   define XPOLL_BACKEND_EPOLL
#   define XPOLL_WITH_IO_URING 1
#   include <sys/epoll.h>
#elif defined(__linux__) && !defined(XPOLL_USE_POLL)
#   define XPOLL_BACKEND_EPOLL
#   include <sys/epoll.h>
#elif (defined(__APPLE__) || defined(__FreeBSD__) || \
       defined(__OpenBSD__) || defined(__NetBSD__)) && !defined(XPOLL_USE_POLL)
#   define XPOLL_BACKEND_KQUEUE
#   include <sys/event.h>
#   include <sys/time.h>
#else
#   define XPOLL_BACKEND_POLL
#   include <poll.h>
#endif
#include "xsock.h"

/* ── Event mask flags ──────────────────────────────────────────────────── */
#define XPOLL_NONE      0
#define XPOLL_READABLE  1
#define XPOLL_WRITABLE  2
#define XPOLL_ERROR     4
#define XPOLL_CLOSE     8
#define XPOLL_ALL       (XPOLL_READABLE | XPOLL_WRITABLE | XPOLL_ERROR | XPOLL_CLOSE)

/* Forward declaration - opaque structure */
typedef struct xPollState xPollState;

/* File event callback function type */
typedef void (*xFileProc)(SOCKET_T fd, int mask, void *clientData);

#if defined(XPOLL_WITH_IO_URING)
#define XPOLL_OP_RECV    1
#define XPOLL_OP_SEND    2
#define XPOLL_OP_POLL    3
#define XPOLL_OP_CANCEL  4

typedef struct xPollRequest xPollRequest;

typedef struct xPollCompletion {
    SOCKET_T      fd;
    int           op;
    int           res;       /* cqe->res: bytes, poll revents, or -errno */
    unsigned      flags;     /* cqe->flags */
    int           mask;      /* XPOLL_* view derived from res */
    void         *buffer;
    size_t        length;
    xPollRequest *request;   /* valid only during the callback */
} xPollCompletion;

typedef void (*xPollCompleteProc)(const xPollCompletion *completion,
                                  void *clientData);
#endif

/* ── Public API ─────────────────────────────────────────────────────────── */
int         xpoll_init(void);
void        xpoll_uninit(void);
int         xpoll_inited(void);   /* 1 if this thread has an active poll loop */
xPollState* xpoll_get_default(void);

int  xpoll_resize(int setsize);

int  xpoll_add_event(SOCKET_T fd, int mask,
                     xFileProc rfileProc, xFileProc wfileProc,
                     xFileProc efileProc, void *clientData);

void xpoll_del_event(SOCKET_T fd, int mask);

int  xpoll_poll(int timeout_ms);

int   xpoll_get_fd(SOCKET_T fd);
void  xpoll_set_client_data(SOCKET_T fd, void *clientData);
void* xpoll_get_client_data(SOCKET_T fd);
int   xpoll_fd_count(void);

const char* xpoll_name(void);

#if defined(XPOLL_WITH_IO_URING)
int xpoll_uring_enabled(void);

xPollRequest* xpoll_submit_recv(SOCKET_T fd, void *buf, size_t len, int flags,
                                xPollCompleteProc completeProc,
                                void *clientData);
xPollRequest* xpoll_submit_send(SOCKET_T fd, const void *buf, size_t len,
                                int flags,
                                xPollCompleteProc completeProc,
                                void *clientData);
xPollRequest* xpoll_submit_poll(SOCKET_T fd, int mask,
                                xPollCompleteProc completeProc,
                                void *clientData);

int xpoll_cancel_request(xPollRequest *request);
#endif

#ifdef __cplusplus
}
#endif
#endif /* XPOLL_H */
