/* xpoll.c – I/O multiplexing: epoll / kqueue / WSAPoll / poll
 *
 * Backend is selected at compile time (see xpoll.h):
 *   Linux              → epoll
 *   macOS / *BSD       → kqueue
 *   Windows            → WSAPoll
 *   Others / fallback  → poll   (define XPOLL_USE_POLL to force this)
 *
 * epoll / kqueue design notes
 * ──────────────────────────
 *   events[]  is indexed directly by fd value, giving O(1) lookup.
 *   The result buffer (ep_events / kq_events) is allocated to `setsize`
 *   entries and grows together with the events array.
 *
 * poll / WSAPoll design notes
 * ───────────────────────────
 *   events[] and poll_fds[] are kept as compact parallel arrays (same
 *   layout as the original implementation).  Slot compaction on delete
 *   preserves this invariant.
 *
 * Copyright (C) 2024 – Released under the BSD licence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#   include <unistd.h>
#   include <sys/time.h>
#endif

#include "xpoll.h"

/* ── Default initial capacity ─────────────────────────────────────────── */
#define XPOLL_SETSIZE 1024

/* ── Per-fd registration record ──────────────────────────────────────── */
typedef struct xPoolFD {
    SOCKET_T    fd;
    int         mask;         /* active XPOLL_* flags               */
    xFileProc   rfileProc;
    xFileProc   wfileProc;
    xFileProc   efileProc;
    void       *clientData;
} xPoolFD;

/* ── Internal state ───────────────────────────────────────────────────── */
struct xPollState {
    xPoolFD    *events;       /* registration table                  */
    int         setsize;      /* allocated length of events[]        */
    int         nfds;         /* number of currently registered fds  */
    int         maxfd;        /* highest fd value seen               */
    void        *ud;          /* user data */

#if defined(XPOLL_BACKEND_EPOLL)
    int                  epfd;
    struct epoll_event  *ep_events;   /* result buffer for epoll_wait  */

#elif defined(XPOLL_BACKEND_KQUEUE)
    int            kqfd;
    struct kevent *kq_events;         /* result buffer for kevent()    */

#elif defined(XPOLL_BACKEND_WSAPOLL)
    WSAPOLLFD     *poll_fds;

#else /* XPOLL_BACKEND_POLL */
    struct pollfd *poll_fds;
#endif
};

/* ── Thread-local default instance ───────────────────────────────────── */
#ifdef _MSC_VER
    static __declspec(thread) xPollState *_xpoll = NULL;
#else
    static __thread xPollState *_xpoll = NULL;
#endif

/* ═══════════════════════════════════════════════════════════════════════
 *  Internal helpers
 * ═══════════════════════════════════════════════════════════════════════ */

/* Initialize a single xPoolFD slot to "empty" */
static void _fe_clear(xPoolFD *fe) {
    fe->fd         = INVALID_SOCKET;
    fe->mask       = XPOLL_NONE;
    fe->rfileProc  = NULL;
    fe->wfileProc  = NULL;
    fe->efileProc  = NULL;
    fe->clientData = NULL;
}

/* ── epoll / kqueue: find by fd value (O(1)) ── */
#if defined(XPOLL_BACKEND_EPOLL) || defined(XPOLL_BACKEND_KQUEUE)

static int xpoll_find_fd(xPollState *loop, SOCKET_T fd) {
    if (!loop || (int)fd < 0 || (int)fd >= loop->setsize)
        return -1;
    return (loop->events[(int)fd].mask != XPOLL_NONE) ? (int)fd : -1;
}

#else /* poll / WSAPoll: linear scan through compact array */

static int xpoll_find_fd(xPollState *loop, SOCKET_T fd) {
    if (!loop) return -1;
    for (int i = 0; i < loop->nfds; i++) {
        if (loop->events[i].fd == fd)
            return i;
    }
    return -1;
}

/* Find the first unused compact slot */
static int xpoll_find_free_slot(xPollState *loop) {
    if (!loop) return -1;
    for (int i = 0; i < loop->setsize; i++) {
#ifdef XPOLL_BACKEND_WSAPOLL
        if (loop->events[i].fd == INVALID_SOCKET)
#else
        if (loop->events[i].fd == (SOCKET_T)-1)
#endif
            return i;
    }
    return -1;
}

/* Initialise one poll_fds entry */
static void _pfd_clear(xPollState *loop, int i) {
#ifdef XPOLL_BACKEND_WSAPOLL
    loop->poll_fds[i].fd      = INVALID_SOCKET;
#else
    loop->poll_fds[i].fd      = -1;
#endif
    loop->poll_fds[i].events  = 0;
    loop->poll_fds[i].revents = 0;
}

/* Rebuild poll_fds[idx].events from events[idx].mask */
static void _pfd_sync(xPollState *loop, int idx) {
    loop->poll_fds[idx].events = 0;
    if (loop->events[idx].mask & XPOLL_READABLE)
        loop->poll_fds[idx].events |= POLLIN;
    if (loop->events[idx].mask & XPOLL_WRITABLE)
        loop->poll_fds[idx].events |= POLLOUT;
}

#endif /* backend selection */

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_create
 * ═══════════════════════════════════════════════════════════════════════ */
int xpoll_init(void) {
    if (_xpoll) return 0;

    xPollState *loop = (xPollState*)calloc(1, sizeof(xPollState));
    if (!loop) return -1;

    /* Allocate the shared events table */
    loop->events = (xPoolFD*)malloc(sizeof(xPoolFD) * XPOLL_SETSIZE);
    if (!loop->events) { free(loop); return -2; }
    for (int i = 0; i < XPOLL_SETSIZE; i++) _fe_clear(&loop->events[i]);

    loop->setsize = XPOLL_SETSIZE;
    loop->nfds    = 0;
    loop->maxfd   = -1;

    /* ── backend-specific init ── */
#if defined(XPOLL_BACKEND_EPOLL)

    loop->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epfd < 0) goto fail_events;

    loop->ep_events = (struct epoll_event*)
        malloc(sizeof(struct epoll_event) * XPOLL_SETSIZE);
    if (!loop->ep_events) { close(loop->epfd); goto fail_events; }

#elif defined(XPOLL_BACKEND_KQUEUE)

    loop->kqfd = kqueue();
    if (loop->kqfd < 0) goto fail_events;

    loop->kq_events = (struct kevent*)
        malloc(sizeof(struct kevent) * XPOLL_SETSIZE);
    if (!loop->kq_events) { close(loop->kqfd); goto fail_events; }

#elif defined(XPOLL_BACKEND_WSAPOLL)

    loop->poll_fds = (WSAPOLLFD*)malloc(sizeof(WSAPOLLFD) * XPOLL_SETSIZE);
    if (!loop->poll_fds) goto fail_events;
    for (int i = 0; i < XPOLL_SETSIZE; i++) _pfd_clear(loop, i);

#else /* XPOLL_BACKEND_POLL */

    loop->poll_fds = (struct pollfd*)malloc(sizeof(struct pollfd) * XPOLL_SETSIZE);
    if (!loop->poll_fds) goto fail_events;
    for (int i = 0; i < XPOLL_SETSIZE; i++) _pfd_clear(loop, i);

#endif

    _xpoll = loop;
    return 0;

fail_events:
    free(loop->events);
    free(loop);
    return -3;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_free
 * ═══════════════════════════════════════════════════════════════════════ */
void xpoll_uninit(void) {
    xPollState *loop = _xpoll;
    if (!loop) return;

#if defined(XPOLL_BACKEND_EPOLL)
    if (loop->epfd >= 0)    close(loop->epfd);
    free(loop->ep_events);
#elif defined(XPOLL_BACKEND_KQUEUE)
    if (loop->kqfd >= 0)    close(loop->kqfd);
    free(loop->kq_events);
#else
    free(loop->poll_fds);
#endif

    free(loop->events);
    free(loop);
    _xpoll = NULL;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_get_default
 * ═══════════════════════════════════════════════════════════════════════ */
xPollState* xpoll_get_default(void) {
    return _xpoll;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_resize
 * ═══════════════════════════════════════════════════════════════════════ */
int xpoll_resize(int setsize) {
    xPollState *loop = _xpoll;
    if (!loop || setsize <= loop->setsize) return 0;

    /* Grow the events table */
    xPoolFD *ne = (xPoolFD*)realloc(loop->events, sizeof(xPoolFD) * setsize);
    if (!ne) return -1;
    loop->events = ne;
    for (int i = loop->setsize; i < setsize; i++) _fe_clear(&loop->events[i]);

    /* Grow the backend-specific result / compact buffer */
#if defined(XPOLL_BACKEND_EPOLL)
    struct epoll_event *nep = (struct epoll_event*)
        realloc(loop->ep_events, sizeof(struct epoll_event) * setsize);
    if (!nep) return -1;
    loop->ep_events = nep;

#elif defined(XPOLL_BACKEND_KQUEUE)
    struct kevent *nkq = (struct kevent*)
        realloc(loop->kq_events, sizeof(struct kevent) * setsize);
    if (!nkq) return -1;
    loop->kq_events = nkq;

#else /* POLL / WSAPOLL */
    void *npfd = realloc(loop->poll_fds, sizeof(loop->poll_fds[0]) * setsize);
    if (!npfd) return -1;
    loop->poll_fds = npfd;
    for (int i = loop->setsize; i < setsize; i++) _pfd_clear(loop, i);
#endif

    loop->setsize = setsize;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_add_event
 * ═══════════════════════════════════════════════════════════════════════ */
int xpoll_add_event(SOCKET_T fd, int mask,
                    xFileProc rfileProc, xFileProc wfileProc,
                    xFileProc efileProc, void *clientData) {
    xPollState *loop = _xpoll;
    if (!loop) return -1;

/* ── epoll backend ────────────────────────────────────────────────────── */
#if defined(XPOLL_BACKEND_EPOLL)

    /* Grow fd-indexed array if needed */
    if ((int)fd >= loop->setsize) {
        int newsize = loop->setsize;
        while (newsize <= (int)fd) newsize *= 2;
        if (xpoll_resize(newsize) < 0) return -1;
    }

    xPoolFD *fe = &loop->events[(int)fd];
    int old_mask = fe->mask;
    int new_mask = old_mask | mask;

    if (new_mask == old_mask) return 0;   /* nothing new to register */

    /* Merge callbacks */
    if (rfileProc) fe->rfileProc = rfileProc;
    if (wfileProc) fe->wfileProc = wfileProc;
    if (efileProc) fe->efileProc = efileProc;
    fe->clientData = clientData;
    fe->fd         = fd;
    fe->mask       = new_mask;

    struct epoll_event ee;
    memset(&ee, 0, sizeof(ee));
    ee.data.fd = (int)fd;
    if (new_mask & XPOLL_READABLE)  ee.events |= EPOLLIN;
    if (new_mask & XPOLL_WRITABLE)  ee.events |= EPOLLOUT;
    ee.events |= EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    int op = (old_mask == XPOLL_NONE) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl(loop->epfd, op, (int)fd, &ee) < 0) {
        fe->mask = old_mask;   /* rollback */
        return -1;
    }

    if (old_mask == XPOLL_NONE) loop->nfds++;
    if ((int)fd > loop->maxfd) loop->maxfd = (int)fd;
    return 0;

/* ── kqueue backend ───────────────────────────────────────────────────── */
#elif defined(XPOLL_BACKEND_KQUEUE)

    if ((int)fd >= loop->setsize) {
        int newsize = loop->setsize;
        while (newsize <= (int)fd) newsize *= 2;
        if (xpoll_resize(newsize) < 0) return -1;
    }

    xPoolFD *fe = &loop->events[(int)fd];
    int old_mask = fe->mask;
    int new_mask = old_mask | mask;

    if (new_mask == old_mask) return 0;

    /* Build changelist for newly added filters only */
    struct kevent changes[2];
    int nchanges = 0;
    if ((new_mask & XPOLL_READABLE) && !(old_mask & XPOLL_READABLE))
        EV_SET(&changes[nchanges++], (uintptr_t)fd,
               EVFILT_READ,  EV_ADD | EV_ENABLE, 0, 0, NULL);
    if ((new_mask & XPOLL_WRITABLE) && !(old_mask & XPOLL_WRITABLE))
        EV_SET(&changes[nchanges++], (uintptr_t)fd,
               EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);

    if (nchanges > 0 &&
        kevent(loop->kqfd, changes, nchanges, NULL, 0, NULL) < 0)
        return -1;

    if (rfileProc) fe->rfileProc = rfileProc;
    if (wfileProc) fe->wfileProc = wfileProc;
    if (efileProc) fe->efileProc = efileProc;
    fe->clientData = clientData;
    fe->fd         = fd;
    fe->mask       = new_mask;

    if (old_mask == XPOLL_NONE) loop->nfds++;
    if ((int)fd > loop->maxfd) loop->maxfd = (int)fd;
    return 0;

/* ── poll / WSAPoll backend ───────────────────────────────────────────── */
#else

    int idx = xpoll_find_fd(loop, fd);
    if (idx < 0) {
        /* New fd: find a free compact slot */
        idx = xpoll_find_free_slot(loop);
        if (idx < 0) {
            /* Array full: double capacity */
            if (xpoll_resize(loop->setsize * 2) < 0) return -1;
            idx = loop->nfds;   /* first slot in newly allocated area */
        }
        loop->events[idx].fd   = fd;
        loop->events[idx].mask = XPOLL_NONE;
        loop->poll_fds[idx].fd = fd;
        loop->nfds++;
    } else {
        if ((loop->events[idx].mask & mask) == mask)
            return 0;   /* already registered */
    }

    loop->events[idx].mask |= mask;
    if (rfileProc) loop->events[idx].rfileProc = rfileProc;
    if (wfileProc) loop->events[idx].wfileProc = wfileProc;
    if (efileProc) loop->events[idx].efileProc = efileProc;
    loop->events[idx].clientData = clientData;

    _pfd_sync(loop, idx);

    if ((int)fd > loop->maxfd) loop->maxfd = (int)fd;
    return 0;

#endif /* backend */
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_del_event
 * ═══════════════════════════════════════════════════════════════════════ */
void xpoll_del_event(SOCKET_T fd, int mask) {
    xPollState *loop = _xpoll;
    if (!loop) return;

    int idx = xpoll_find_fd(loop, fd);
    if (idx < 0) return;

/* ── epoll backend ────────────────────────────────────────────────────── */
#if defined(XPOLL_BACKEND_EPOLL)

    xPoolFD *fe   = &loop->events[(int)fd];
    int old_mask  = fe->mask;
    int new_mask  = old_mask & ~mask;

    if (new_mask == old_mask) return;   /* nothing to remove */

    fe->mask = new_mask;

    if (new_mask == XPOLL_NONE) {
        epoll_ctl(loop->epfd, EPOLL_CTL_DEL, (int)fd, NULL);
        _fe_clear(fe);
        loop->nfds--;
    } else {
        struct epoll_event ee;
        memset(&ee, 0, sizeof(ee));
        ee.data.fd = (int)fd;
        if (new_mask & XPOLL_READABLE)  ee.events |= EPOLLIN;
        if (new_mask & XPOLL_WRITABLE)  ee.events |= EPOLLOUT;
        ee.events |= EPOLLERR | EPOLLHUP | EPOLLRDHUP;
        epoll_ctl(loop->epfd, EPOLL_CTL_MOD, (int)fd, &ee);
    }

    /* Recalculate maxfd */
    if (loop->maxfd == (int)fd && new_mask == XPOLL_NONE) {
        loop->maxfd = -1;
        /* Scan all possible fds (epoll keeps no compact list) */
        int limit = (int)fd;
        for (int i = 0; i < limit; i++) {
            if (loop->events[i].mask != XPOLL_NONE &&
                i > loop->maxfd)
                loop->maxfd = i;
        }
    }

/* ── kqueue backend ───────────────────────────────────────────────────── */
#elif defined(XPOLL_BACKEND_KQUEUE)

    xPoolFD *fe  = &loop->events[(int)fd];
    int old_mask = fe->mask;
    int new_mask = old_mask & ~mask;

    if (new_mask == old_mask) return;

    /* Delete only filters that are actually being removed */
    struct kevent changes[2];
    int nchanges = 0;
    if ((old_mask & XPOLL_READABLE) && !(new_mask & XPOLL_READABLE))
        EV_SET(&changes[nchanges++], (uintptr_t)fd,
               EVFILT_READ,  EV_DELETE, 0, 0, NULL);
    if ((old_mask & XPOLL_WRITABLE) && !(new_mask & XPOLL_WRITABLE))
        EV_SET(&changes[nchanges++], (uintptr_t)fd,
               EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

    if (nchanges > 0)
        kevent(loop->kqfd, changes, nchanges, NULL, 0, NULL);

    fe->mask = new_mask;

    if (new_mask == XPOLL_NONE) {
        _fe_clear(fe);
        loop->nfds--;
    }

    /* Recalculate maxfd */
    if (loop->maxfd == (int)fd && new_mask == XPOLL_NONE) {
        loop->maxfd = -1;
        int limit = (int)fd;
        for (int i = 0; i < limit; i++) {
            if (loop->events[i].mask != XPOLL_NONE &&
                i > loop->maxfd)
                loop->maxfd = i;
        }
    }

/* ── poll / WSAPoll backend ───────────────────────────────────────────── */
#else

    /* Sanity check */
    if (loop->events[idx].fd != fd || loop->poll_fds[idx].fd != fd) {
        fprintf(stderr,
            "[xpoll] warn: fd mismatch – find fd=%d but events[%d].fd=%d\n",
            (int)fd, idx, (int)loop->events[idx].fd);
        return;
    }

    loop->events[idx].mask &= ~mask;

    if (loop->events[idx].mask == XPOLL_NONE) {
        /* Slot is now empty; compact by swapping with the tail entry */
        if (idx != loop->nfds - 1) {
            loop->poll_fds[idx] = loop->poll_fds[loop->nfds - 1];
            loop->events[idx]   = loop->events[loop->nfds - 1];
        }
        /* Clear the vacated tail slot */
        _fe_clear(&loop->events[loop->nfds - 1]);
        _pfd_clear(loop, loop->nfds - 1);
        loop->nfds--;
    } else {
        _pfd_sync(loop, idx);
    }

    /* Recalculate maxfd */
    if (loop->maxfd == (int)fd) {
        loop->maxfd = -1;
        for (int i = 0; i < loop->nfds; i++) {
            if (loop->events[i].fd != INVALID_SOCKET &&
                (int)loop->events[i].fd > loop->maxfd)
                loop->maxfd = (int)loop->events[i].fd;
        }
    }

#endif /* backend */
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_poll  – wait for events and dispatch callbacks
 * ═══════════════════════════════════════════════════════════════════════ */
int xpoll_poll(int timeout_ms) {
    xPollState *loop = _xpoll;
    if (!loop) return -1;

    int num_ready     = 0;
    int num_processed = 0;

/* ── epoll backend ────────────────────────────────────────────────────── */
#if defined(XPOLL_BACKEND_EPOLL)

    int maxevents = (loop->nfds > 0) ? loop->nfds : 1;
    num_ready = epoll_wait(loop->epfd, loop->ep_events, maxevents, timeout_ms);

    if (num_ready < 0) {
        if (errno == EINTR) return 0;
        perror("[xpoll] epoll_wait");
        return -1;
    }

    for (int i = 0; i < num_ready; i++) {
        struct epoll_event *e = &loop->ep_events[i];
        int sfd  = e->data.fd;

        if (sfd < 0 || sfd >= loop->setsize) continue;
        xPoolFD *fe = &loop->events[sfd];
        if (fe->mask == XPOLL_NONE) continue;

        int mask = 0;
        if (e->events & (EPOLLIN  | EPOLLRDHUP))  mask |= XPOLL_READABLE;
        if (e->events & EPOLLOUT)                  mask |= XPOLL_WRITABLE;
        if (e->events & (EPOLLERR | EPOLLHUP))     mask |= XPOLL_ERROR | XPOLL_CLOSE;

        /* Save callbacks (handler may modify the state) */
        xFileProc rp = fe->rfileProc;
        xFileProc wp = fe->wfileProc;
        xFileProc ep = fe->efileProc;
        void     *ud = fe->clientData;
        SOCKET_T  fd = fe->fd;

        if ((mask & XPOLL_WRITABLE) && wp)
            wp(fd, XPOLL_WRITABLE, ud);
        if ((mask & XPOLL_READABLE) && rp)
            rp(fd, XPOLL_READABLE, ud);
        if ((mask & (XPOLL_ERROR | XPOLL_CLOSE)) && ep) {
            fprintf(stderr,
                "[xpoll] epoll close/error fd=%d events=0x%x\n",
                sfd, e->events);
            ep(fd, mask & (XPOLL_ERROR | XPOLL_CLOSE), ud);
        }
        num_processed++;
    }

/* ── kqueue backend ───────────────────────────────────────────────────── */
#elif defined(XPOLL_BACKEND_KQUEUE)

    struct timespec ts, *tsp = NULL;
    if (timeout_ms >= 0) {
        ts.tv_sec  =  timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }

    int maxevents = (loop->nfds > 0) ? loop->nfds : 1;
    num_ready = kevent(loop->kqfd, NULL, 0, loop->kq_events, maxevents, tsp);

    if (num_ready < 0) {
        if (errno == EINTR) return 0;
        perror("[xpoll] kevent");
        return -1;
    }

    for (int i = 0; i < num_ready; i++) {
        struct kevent *ke = &loop->kq_events[i];
        int sfd = (int)ke->ident;

        if (sfd < 0 || sfd >= loop->setsize) continue;
        xPoolFD *fe = &loop->events[sfd];
        if (fe->mask == XPOLL_NONE) continue;

        int mask = 0;
        if (ke->filter == EVFILT_READ)   mask |= XPOLL_READABLE;
        if (ke->filter == EVFILT_WRITE)  mask |= XPOLL_WRITABLE;
        if (ke->flags  & EV_EOF)         mask |= XPOLL_CLOSE;
        if (ke->flags  & EV_ERROR)       mask |= XPOLL_ERROR;

        xFileProc rp = fe->rfileProc;
        xFileProc wp = fe->wfileProc;
        xFileProc ep = fe->efileProc;
        void     *ud = fe->clientData;
        SOCKET_T  fd = fe->fd;

        if ((mask & XPOLL_WRITABLE) && wp)
            wp(fd, XPOLL_WRITABLE, ud);
        if ((mask & XPOLL_READABLE) && rp)
            rp(fd, XPOLL_READABLE, ud);
        if ((mask & (XPOLL_ERROR | XPOLL_CLOSE)) && ep) {
            fprintf(stderr,
                "[xpoll] kqueue close/error fd=%d flags=0x%x\n",
                sfd, ke->flags);
            ep(fd, mask & (XPOLL_ERROR | XPOLL_CLOSE), ud);
        }
        num_processed++;
    }

/* ── poll / WSAPoll backend ───────────────────────────────────────────── */
#else

    int nfds = loop->nfds;   /* snapshot before callbacks may modify */

#ifdef XPOLL_BACKEND_WSAPOLL
    num_ready = WSAPoll(loop->poll_fds, nfds, timeout_ms);
#else
    num_ready = poll(loop->poll_fds, nfds, timeout_ms);
#endif

    if (num_ready < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        fprintf(stderr,
            "[xpoll] poll error nfds=%d: %s\n", nfds, strerror(errno));
        return -1;
    }
    if (num_ready == 0) return 0;

    /* Iterate in reverse so compaction during delete does not skip entries */
    for (int i = nfds - 1; i >= 0; i--) {
        if (loop->poll_fds[i].fd == INVALID_SOCKET) continue;

        short revents = loop->poll_fds[i].revents;
        if (revents == 0) continue;

        int mask = 0;
        if (revents & POLLIN)                       mask |= XPOLL_READABLE;
        if (revents & POLLOUT)                      mask |= XPOLL_WRITABLE;
        if (revents & (POLLERR | POLLHUP | POLLNVAL))
                                                    mask |= XPOLL_ERROR | XPOLL_CLOSE;
        loop->poll_fds[i].revents = 0;

        xPoolFD  *fe = &loop->events[i];
        xFileProc rp = fe->rfileProc;
        xFileProc wp = fe->wfileProc;
        xFileProc ep = fe->efileProc;
        void     *ud = fe->clientData;
        SOCKET_T  fd = fe->fd;

        if ((int)fd != (int)loop->poll_fds[i].fd)
            fprintf(stderr,
                "[xpoll] warn: fd mismatch events[%d].fd=%d poll_fds[%d].fd=%d\n",
                i, (int)fd, i, (int)loop->poll_fds[i].fd);

        if ((mask & XPOLL_WRITABLE) && wp)
            wp(fd, XPOLL_WRITABLE, ud);
        if ((mask & XPOLL_READABLE) && rp)
            rp(fd, XPOLL_READABLE, ud);
        if ((mask & (XPOLL_ERROR | XPOLL_CLOSE)) && ep) {
            fprintf(stderr,
                "[xpoll] poll close/error fd=%d revents=0x%x\n",
                (int)fd, (unsigned)revents);
            ep(fd, mask & (XPOLL_ERROR | XPOLL_CLOSE), ud);
        }
        num_processed++;
    }

#endif /* backend */

    return num_processed;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Utility helpers
 * ═══════════════════════════════════════════════════════════════════════ */
int xpoll_get_fd(SOCKET_T fd) {
    xPollState *loop = _xpoll;
    if (!loop) return -1;
    return xpoll_find_fd(loop, fd);
}

void xpoll_set_client_data(SOCKET_T fd, void *clientData) {
    xPollState *loop = _xpoll;
    if (!loop) return;
    int idx = xpoll_find_fd(loop, fd);
    if (idx >= 0)
        loop->events[idx].clientData = clientData;
}

void* xpoll_get_client_data(SOCKET_T fd) {
    xPollState *loop = _xpoll;
    if (!loop) return NULL;
    int idx = xpoll_find_fd(loop, fd);
    if (idx >= 0)
        return loop->events[idx].clientData;
    return NULL;
}

/* Return the active backend name */
const char* xpoll_name(void) {
#if   defined(XPOLL_BACKEND_EPOLL)
    return "epoll";
#elif defined(XPOLL_BACKEND_KQUEUE)
    return "kqueue";
#elif defined(XPOLL_BACKEND_WSAPOLL)
    return "wsapoll";
#else
    return "poll";
#endif
}
