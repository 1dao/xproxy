/* poll/WSAPoll-based I/O multiplexing module
 * Copyright (C) 2024
 * Released under the BSD license. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <unistd.h>
    #include <poll.h>
    #include <sys/time.h>
#endif

#include "xpoll.h"

/* Default set size for poll arrays */
#define XPOLL_SETSIZE 1024

/* File descriptor registration structure - internal */
typedef struct xPoolFD {
    SOCKET_T        fd;          /* file descriptor */
    short int       mask;        /* one of XPOLL_(READABLE|WRITABLE) */
    xFileProc       rfileProc;   /* callback for read event */
    xFileProc       wfileProc;   /* callback for write event */
    xFileProc       efileProc;   /* callback for error event */
    void*           clientData;   /* user data */
} xPoolFD;

/* Poll state structure - internal definition */
struct xPollState {
#ifdef _WIN32
    WSAPOLLFD *poll_fds;       /* WSAPoll structure array */
#else
    struct pollfd *poll_fds;   /* poll structure array */
#endif

    xPoolFD *events;           /* Registered events array */
    int setsize;               /* Size of the arrays */
    int nfds;                  /* Number of registered file descriptors */
    int maxfd;                 /* Maximum file descriptor */
};

/* Thread-local poll state for default instance */
#ifdef _MSC_VER
    static __declspec(thread) xPollState* _xpoll = NULL;
#else
    static __thread xPollState* _xpoll = NULL;
#endif

/* Create and initialize a new poll loop */
xPollState* xpoll_create(void) {
    xPollState *loop = (xPollState*)malloc(sizeof(xPollState));
    if (!loop)
        return NULL;

    /* Allocate poll_fds array */
    loop->poll_fds = malloc(sizeof(loop->poll_fds[0]) * XPOLL_SETSIZE);
    if (!loop->poll_fds) {
        free(loop);
        return NULL;
    }

    /* Allocate events array */
    loop->events = malloc(sizeof(loop->events[0]) * XPOLL_SETSIZE);
    if (!loop->events) {
        free(loop->poll_fds);
        free(loop);
        return NULL;
    }

    loop->setsize = XPOLL_SETSIZE;
    loop->nfds = 0;              /* Initialize nfds */
    loop->maxfd = -1;

    /* Initialize arrays */
    for (int i = 0; i < XPOLL_SETSIZE; i++) {
        loop->events[i].fd = INVALID_SOCKET;
        loop->events[i].mask = XPOLL_NONE;
        loop->events[i].rfileProc = NULL;
        loop->events[i].wfileProc = NULL;
        loop->events[i].efileProc = NULL;
        loop->events[i].clientData = NULL;
#ifdef _WIN32
        loop->poll_fds[i].fd = INVALID_SOCKET;
        loop->poll_fds[i].events = 0;
        loop->poll_fds[i].revents = 0;
#else
        loop->poll_fds[i].fd = -1;
        loop->poll_fds[i].events = 0;
        loop->poll_fds[i].revents = 0;
#endif
    }
    /* Set as thread-local default instance */
    _xpoll = loop;
    return loop;
}

/* Free poll loop resources */
void xpoll_free(xPollState *loop) {
    if (!loop)
        return;
    if (loop->poll_fds)
        free(loop->poll_fds);
    if (loop->events)
        free(loop->events);
    if (_xpoll == loop)
        _xpoll = NULL;

    free(loop);
}

/* Get thread-local default instance */
xPollState* xpoll_get_default(void) {
    return _xpoll?_xpoll:xpoll_create();
}

/* Resize poll arrays */
int xpoll_resize(xPollState *loop, int setsize) {
    if (!loop || setsize <= loop->setsize)
        return 0;

    /* Reallocate poll_fds array */
    void *new_poll_fds = realloc(loop->poll_fds, sizeof(loop->poll_fds[0]) * setsize);
    if (!new_poll_fds)
        return -1;
    loop->poll_fds = new_poll_fds;

    /* Reallocate events array */
    void *new_events = realloc(loop->events, sizeof(loop->events[0]) * setsize);
    if (!new_events)
        return -1;
    loop->events = new_events;

    /* Initialize new entries */
    for (int i = loop->setsize; i < setsize; i++) {
        loop->events[i].fd = INVALID_SOCKET;
        loop->events[i].mask = XPOLL_NONE;
        loop->events[i].rfileProc = NULL;
        loop->events[i].wfileProc = NULL;
        loop->events[i].efileProc = NULL;
        loop->events[i].clientData = NULL;
#ifdef _WIN32
        loop->poll_fds[i].fd = INVALID_SOCKET;
        loop->poll_fds[i].events = 0;
        loop->poll_fds[i].revents = 0;
#else
        loop->poll_fds[i].fd = -1;
        loop->poll_fds[i].events = 0;
        loop->poll_fds[i].revents = 0;
#endif
    }
    loop->setsize = setsize;
    return 0;
}

/* Find index for a given file descriptor */
static int xpoll_find_fd(xPollState *loop, SOCKET_T fd) {
    if (!loop)
        return -1;

    for (int i = 0; i < loop->nfds; i++) {  // ← 使用 nfds 而不是 setsize
        if (loop->events[i].fd == fd) {
            return i;
        }
    }
    return -1;
}

/* Find first available slot */
static int xpoll_find_free_slot(xPollState *loop) {
    if (!loop)
        return -1;

    for (int i = 0; i < loop->setsize; i++) {
#ifdef _WIN32
        if (loop->events[i].fd == INVALID_SOCKET) {
#else
        if (loop->events[i].fd == -1) {
#endif
            return i;
        }
    }
    return -1;
}

/* Add a file descriptor event */
int xpoll_add_event(xPollState *loop, SOCKET_T fd, int mask,
                     xFileProc rfileProc, xFileProc wfileProc,
                     xFileProc efileProc, void *clientData) {
    if (!loop)
        return -1;

    int idx = xpoll_find_fd(loop, fd);
    if (idx < 0) {
        /* New FD, find a free slot */
        idx = xpoll_find_free_slot(loop);
        if (idx < 0) {
            /* Need to resize */
            if (xpoll_resize(loop, loop->setsize * 2) < 0)
                return -1;
            idx = loop->setsize / 2; /* First slot in the newly allocated area */
        }

        loop->events[idx].fd = fd;
        loop->poll_fds[idx].fd = fd;
        loop->events[idx].mask = 0;
        loop->nfds++;
    } else {
        if ((loop->events[idx].mask & mask) == mask)
            return 0;
    }

    /* Update the event */
    loop->events[idx].mask |= mask;
    if (rfileProc)
        loop->events[idx].rfileProc = rfileProc;
    if (wfileProc)
        loop->events[idx].wfileProc = wfileProc;
    if (efileProc)
        loop->events[idx].efileProc = efileProc;

    loop->events[idx].clientData = clientData;
    loop->events[idx].fd = fd;

    loop->poll_fds[idx].fd = fd;
    loop->poll_fds[idx].events = 0;

    /* Update poll events */
    if (loop->events[idx].mask & XPOLL_READABLE)
        loop->poll_fds[idx].events |= POLLIN;
    if (loop->events[idx].mask & XPOLL_WRITABLE)
        loop->poll_fds[idx].events |= POLLOUT;

    /* Update maxfd */
    if ((int)fd > loop->maxfd)
        loop->maxfd = (int)fd;

    return 0;
}

/* Delete a file descriptor event */
void xpoll_del_event(xPollState *loop, SOCKET_T fd, int mask) {
    if (!loop)
        return;

    int idx = xpoll_find_fd(loop, fd);
    if (idx < 0)
        return;
    if (loop->events[idx].fd != fd || loop->poll_fds[idx].fd!=fd) {
        fprintf(stderr, "[xpoll] warn: fd or mask mismatch, find fd=%d, but events[%d].fd=%d, mask=%d\n",
                (int)fd, idx, (int)loop->events[idx].fd, loop->events[idx].mask);
        return;
    }

    /* Update the mask */
    loop->events[idx].mask &= ~mask;

    /* If mask becomes empty, remove the FD */
    if (loop->events[idx].mask == XPOLL_NONE) {
        loop->events[idx].fd = INVALID_SOCKET;
        loop->events[idx].rfileProc = NULL;
        loop->events[idx].wfileProc = NULL;
        loop->events[idx].efileProc = NULL;
        loop->events[idx].clientData = NULL;
        loop->poll_fds[idx].fd = INVALID_SOCKET;
        loop->poll_fds[idx].events = 0;
        loop->poll_fds[idx].revents = 0;

        if( loop->nfds!=idx+1 ) {
            loop->poll_fds[idx] = loop->poll_fds[loop->nfds-1];
            loop->events[idx] = loop->events[loop->nfds-1];
            memset(&loop->poll_fds[loop->nfds-1], 0, sizeof(loop->poll_fds[0]) );
            memset(&loop->events[loop->nfds-1], 0, sizeof(loop->events[0]));
            loop->events[loop->nfds-1].fd = INVALID_SOCKET;
            loop->poll_fds[loop->nfds-1].fd = INVALID_SOCKET;
        }
        loop->nfds--;  /* Decrement registered FD count */
    } else {
        /* Update poll events */
        loop->poll_fds[idx].events = 0;

        if (loop->events[idx].mask & XPOLL_READABLE) {
            loop->poll_fds[idx].events |= POLLIN;
        }
        if (loop->events[idx].mask & XPOLL_WRITABLE) {
            loop->poll_fds[idx].events |= POLLOUT;
        }
    }

    /* Recalculate maxfd */
    if (loop->maxfd == (int)fd) {
        loop->maxfd = -1;
        for (int i = 0; i < loop->nfds; i++) {
#ifdef _WIN32
            if (loop->events[i].fd != INVALID_SOCKET && (int)loop->events[i].fd > loop->maxfd) {
#else
            if (loop->events[i].fd != -1 && (int)loop->events[i].fd > loop->maxfd) {
#endif
                loop->maxfd = (int)loop->events[i].fd;
            }
        }
    }
}

/* Poll for events and invoke callbacks */
int xpoll_poll(xPollState *loop, int timeout_ms) {
    if (!loop)
        return -1;

    int num_events = 0;
    int nfds = loop->nfds; // lock poll len
#ifdef _WIN32
    num_events = WSAPoll(loop->poll_fds, nfds, timeout_ms);
#else
    num_events = poll(loop->poll_fds, nfds, timeout_ms);
#endif

    if (num_events < 0) {
        if (errno == EINTR) {
            return 0;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        fprintf(stderr, "Error polling file descriptors: pool_nfds=%d, %s\n", loop->nfds, strerror(errno));
        return -1;
    }

    if (num_events == 0)
        return 0;

    /* Process fired events and invoke callbacks */
    int num_processed = 0; void* ud; xPoolFD * fe;
    xFileProc rfileProc, wfileProc, efileProc;   /* callback for read event */
    for (int i = nfds-1; i >= 0; i--) {
        if (loop->poll_fds[i].fd == INVALID_SOCKET)
            continue;

        short revents = loop->poll_fds[i].revents;
        if (revents == 0)
            continue;

        int mask = 0;
        if (revents & POLLIN)
            mask |= XPOLL_READABLE;
        if (revents & POLLOUT)
            mask |= XPOLL_WRITABLE;
        if (revents & (POLLERR | POLLHUP | POLLNVAL))
            mask |= XPOLL_ERROR | XPOLL_CLOSE;
        loop->poll_fds[i].revents = 0;

        SOCKET_T fd = loop->poll_fds[i].fd;
        int idx = i;//xpoll_find_fd(loop, fd);
        if(fd!=loop->events[i].fd)
            fprintf(stderr, "xpoll mismatch fd=%d, idx=%d, i=%d\n", (int)fd, idx, i);

        fe = &loop->events[idx];
        rfileProc = fe->rfileProc;
        wfileProc = fe->wfileProc;
        efileProc = fe->efileProc;
        ud = fe->clientData;

        /* Invoke write callback */
        if ((mask & XPOLL_WRITABLE) && wfileProc)
            wfileProc(loop, fd, XPOLL_WRITABLE, ud);

        /* Invoke read callback */
        if ((mask & XPOLL_READABLE) && rfileProc)
            rfileProc(loop, fd, XPOLL_READABLE, ud);

        /* Invoke error callback */
        if ((mask & (XPOLL_ERROR | XPOLL_CLOSE)) && efileProc) {
            fprintf(stderr, "xpoll to close fd=%d, idx=%d, i=%d, err=%d, hub=%d, nval=%d\n", (int)fd, idx, i, revents&XPOLL_ERROR?1:0, revents&POLLHUP?1:0, revents&POLLNVAL?1:0);
            efileProc(loop, fd, mask & (XPOLL_ERROR | XPOLL_CLOSE), ud);
        }

        num_processed++;
    }

    return num_processed;
}

/* Check if a file descriptor is registered */
int xpoll_get_fd(xPollState *loop, SOCKET_T fd) {
    if (!loop)
        return -1;
    return xpoll_find_fd(loop, fd);
}

/* Set client data for a file descriptor */
void xpoll_set_client_data(xPollState *loop, SOCKET_T fd, void *clientData) {
    if (!loop)
        return;

    int idx = xpoll_find_fd(loop, fd);
    if (idx >= 0)
        loop->events[idx].clientData = clientData;
}

/* Get client data for a file descriptor */
void* xpoll_get_client_data(xPollState *loop, SOCKET_T fd) {
    if (!loop)
        return NULL;

    int idx = xpoll_find_fd(loop, fd);
    if (idx >= 0)
        return loop->events[idx].clientData;
    return NULL;
}

/* Return the poll implementation name */
const char* xpoll_name(void) {
#ifdef _WIN32
    return "wsapoll";
#else
    return "poll";
#endif
}
