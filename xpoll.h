#ifndef XPOLL_H
#define XPOLL_H

#include "socket_util.h"

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <poll.h>
#endif

/* Event mask flags */
#define XPOLL_NONE      0
#define XPOLL_READABLE  1
#define XPOLL_WRITABLE  2
#define XPOLL_ERROR     4
#define XPOLL_CLOSE     8
#define XPOLL_ALL       (XPOLL_READABLE | XPOLL_WRITABLE | XPOLL_ERROR | XPOLL_CLOSE)

/* Forward declaration - opaque structure */
typedef struct xPollState xPollState;

/* File event callback function type */
typedef void (*xFileProc)(xPollState *loop, SOCKET_T fd, int mask, void *clientData);

/* API functions */
xPollState* xpoll_create(void);
void xpoll_free(xPollState *loop);
xPollState* xpoll_get_default(void);

int xpoll_resize(xPollState *loop, int setsize);

int xpoll_add_event(xPollState *loop, SOCKET_T fd, int mask,
                     xFileProc rfileProc, xFileProc wfileProc,
                     xFileProc efileProc, void *clientData);

void xpoll_del_event(xPollState *loop, SOCKET_T fd, int mask);

int xpoll_poll(xPollState *loop, int timeout_ms);

int xpoll_get_fd(xPollState *loop, SOCKET_T fd);
void xpoll_set_client_data(xPollState *loop, SOCKET_T fd, void *clientData);
void* xpoll_get_client_data(xPollState *loop, SOCKET_T fd);

const char* xpoll_name(void);

#endif /* XPOLL_H */
