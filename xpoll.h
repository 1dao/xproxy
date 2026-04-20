#ifndef XPOLL_H
#define XPOLL_H

#include "socket_util.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ── Backend selection ─────────────────────────────────────────────────────
 * Priority: epoll (Linux) > kqueue (macOS/BSD) > WSAPoll (Win32) > poll
 * Override by defining XPOLL_USE_POLL before including this header.
 * ------------------------------------------------------------------------- */
#if defined(_WIN32)
#   define XPOLL_BACKEND_WSAPOLL
#   include <winsock2.h>
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

/* ── Public API ─────────────────────────────────────────────────────────── */
int         xpoll_init(void);
void        xpoll_uninit(void);
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

const char* xpoll_name(void);

#ifdef __cplusplus
}
#endif
#endif /* XPOLL_H */
