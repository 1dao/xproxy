/* xpoll.c – I/O multiplexing: epoll / kqueue / WSAPoll / poll
 *
 * Backend is selected at compile time (see xpoll.h):
 *   Linux              → epoll
 *   macOS / *BSD       → kqueue
 *   Windows            → WSAPoll
 *   Others / fallback  → poll   (define XPOLL_USE_POLL to force this)
 *
 * Unified fd registry
 * ──────────────────────────
 *   All backends store xPoolFD records in a single hash table:
 *       fd_map : SOCKET_T fd -> xPoolFD*
 *
 *   epoll / kqueue
 *       Look up fe via fd_map directly; no flat events[fd] array, so
 *       large fd values do not force a wasteful resize.
 *
 *   poll / WSAPoll
 *       fd_map gives O(1) fd -> xPoolFD*.  poll_fds[] / poll_fes[] keep a
 *       compact view for the system call: poll_fds[idx] is what the kernel
 *       sees, poll_fes[idx] is the matching xPoolFD*; xPoolFD::idx points
 *       back so deletion is O(1) (swap with tail, fix moved->idx).
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
#include "xhash.h"

#if defined(XPOLL_WITH_IO_URING)
#   include <liburing.h>
#   include <poll.h>
#endif

/* ── Default initial capacity ─────────────────────────────────────────── */
#define XPOLL_SETSIZE 1024

/* ── Per-fd registration record ──────────────────────────────────────── */
typedef struct xPoolFD {
    SOCKET_T    fd;
    int         mask;         /* active XPOLL_* flags                     */
    int         idx;          /* poll/WSAPoll compact slot, others = -1   */
    xFileProc   rfileProc;
    xFileProc   wfileProc;
    xFileProc   efileProc;
    void       *clientData;
} xPoolFD;

#if defined(XPOLL_WITH_IO_URING)
struct xPollRequest {
    SOCKET_T          fd;
    int               op;
    int               mask;
    int               flags;
    void             *buffer;
    size_t            length;
    xPollCompleteProc completeProc;
    void             *clientData;
};
#endif

/* ── Internal state ───────────────────────────────────────────────────── */
struct xPollState {
    xhash      *fd_map;       /* fd -> xPoolFD*                           */
    int         setsize;      /* current backend buffer capacity          */
    int         nfds;         /* number of currently registered fds       */
    int         maxfd;        /* highest fd value seen                    */
    void       *ud;           /* user data                                */

#if defined(XPOLL_BACKEND_EPOLL)
    int                  epfd;
    struct epoll_event  *ep_events;   /* result buffer for epoll_wait     */
#if defined(XPOLL_WITH_IO_URING)
    struct io_uring      uring;
    int                  uring_fd;
    int                  uring_ready;
#endif

#elif defined(XPOLL_BACKEND_KQUEUE)
    int            kqfd;
    struct kevent *kq_events;         /* result buffer for kevent()       */

#elif defined(XPOLL_BACKEND_WSAPOLL)
    WSAPOLLFD     *poll_fds;
    xPoolFD      **poll_fes;          /* idx -> xPoolFD*                  */

#else /* XPOLL_BACKEND_POLL */
    struct pollfd *poll_fds;
    xPoolFD      **poll_fes;          /* idx -> xPoolFD*                  */
#endif
};

/* ── Thread-local default instance ───────────────────────────────────── */
#ifdef _MSC_VER
    static __declspec(thread) xPollState *_xpoll = NULL;
#else
    static __thread xPollState *_xpoll = NULL;
#endif

/* ═══════════════════════════════════════════════════════════════════════
 *  fd_map helpers
 * ═══════════════════════════════════════════════════════════════════════ */

#if defined(XPOLL_WITH_IO_URING)
static int _uring_poll_events_from_mask(int mask) {
    int events = 0;
    if (mask & XPOLL_READABLE) events |= POLLIN;
    if (mask & XPOLL_WRITABLE) events |= POLLOUT;
    if (mask & XPOLL_ERROR)    events |= POLLERR;
    if (mask & XPOLL_CLOSE)    events |= POLLHUP;
#ifdef POLLRDHUP
    if (mask & XPOLL_CLOSE)    events |= POLLRDHUP;
#endif
    return events;
}

static int _uring_mask_from_poll_events(int events) {
    int mask = 0;
    if (events & POLLIN)  mask |= XPOLL_READABLE;
    if (events & POLLOUT) mask |= XPOLL_WRITABLE;
    if (events & POLLERR) mask |= XPOLL_ERROR;
    if (events & POLLHUP) mask |= XPOLL_CLOSE;
#ifdef POLLNVAL
    if (events & POLLNVAL) mask |= XPOLL_ERROR | XPOLL_CLOSE;
#endif
#ifdef POLLRDHUP
    if (events & POLLRDHUP) mask |= XPOLL_CLOSE;
#endif
    return mask;
}

static int _uring_mask_from_completion(const xPollRequest *req, int res) {
    if (!req) return XPOLL_NONE;
    if (res < 0) return XPOLL_ERROR;

    if (req->op == XPOLL_OP_POLL)
        return _uring_mask_from_poll_events(res);
    if (req->op == XPOLL_OP_RECV)
        return res == 0 ? XPOLL_CLOSE : XPOLL_READABLE;
    if (req->op == XPOLL_OP_SEND)
        return XPOLL_WRITABLE;
    return XPOLL_NONE;
}

static int _uring_drain(xPollState *loop) {
    if (!loop || !loop->uring_ready) return 0;

    int processed = 0;
    struct io_uring_cqe *cqe = NULL;
    while (io_uring_peek_cqe(&loop->uring, &cqe) == 0 && cqe) {
        xPollRequest *req = (xPollRequest*)(uintptr_t)cqe->user_data;
        if (req) {
            xPollCompletion completion;
            memset(&completion, 0, sizeof(completion));
            completion.fd      = req->fd;
            completion.op      = req->op;
            completion.res     = cqe->res;
            completion.flags   = cqe->flags;
            completion.mask    = _uring_mask_from_completion(req, cqe->res);
            completion.buffer  = req->buffer;
            completion.length  = req->length;
            completion.request = req;

            xPollCompleteProc proc = req->completeProc;
            void *clientData = req->clientData;
            if (proc) proc(&completion, clientData);
            free(req);
            processed++;
        }
        io_uring_cqe_seen(&loop->uring, cqe);
        cqe = NULL;
    }
    return processed;
}

static int _uring_attach_to_epoll(xPollState *loop) {
    struct epoll_event ee;
    memset(&ee, 0, sizeof(ee));
    ee.events = EPOLLIN;
    ee.data.fd = loop->uring_fd;
    if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->uring_fd, &ee) < 0)
        return -1;
    return 0;
}

static int _uring_loop_init(xPollState *loop) {
    if (!loop) return -1;
    loop->uring_fd = -1;
    loop->uring_ready = 0;

    int rc = io_uring_queue_init((unsigned)XPOLL_SETSIZE, &loop->uring, 0);
    if (rc < 0) {
        errno = -rc;
        return -1;
    }

    loop->uring_fd = loop->uring.ring_fd;
    loop->uring_ready = 1;
    if (_uring_attach_to_epoll(loop) != 0) {
        io_uring_queue_exit(&loop->uring);
        loop->uring_ready = 0;
        loop->uring_fd = -1;
        return -1;
    }
    return 0;
}

static void _uring_loop_uninit(xPollState *loop) {
    if (!loop || !loop->uring_ready) return;
    _uring_drain(loop);
    io_uring_queue_exit(&loop->uring);
    loop->uring_ready = 0;
    loop->uring_fd = -1;
}

static xPollRequest* _uring_request_new(SOCKET_T fd, int op, int mask,
                                        int flags, void *buffer, size_t length,
                                        xPollCompleteProc completeProc,
                                        void *clientData) {
    xPollRequest *req = (xPollRequest*)calloc(1, sizeof(*req));
    if (!req) return NULL;
    req->fd = fd;
    req->op = op;
    req->mask = mask;
    req->flags = flags;
    req->buffer = buffer;
    req->length = length;
    req->completeProc = completeProc;
    req->clientData = clientData;
    return req;
}

static xPollRequest* _uring_submit_request(xPollRequest *req) {
    xPollState *loop = _xpoll;
    if (!req) {
        errno = ENOMEM;
        return NULL;
    }
    if (!loop || !loop->uring_ready) {
        free(req);
        errno = ENOSYS;
        return NULL;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->uring);
    if (!sqe) {
        int rc = io_uring_submit(&loop->uring);
        if (rc < 0) {
            free(req);
            errno = -rc;
            return NULL;
        }
        sqe = io_uring_get_sqe(&loop->uring);
        if (!sqe) {
            free(req);
            errno = EAGAIN;
            return NULL;
        }
    }

    if (req->op == XPOLL_OP_RECV) {
        io_uring_prep_recv(sqe, (int)req->fd, req->buffer,
                           (unsigned)req->length, req->flags);
    } else if (req->op == XPOLL_OP_SEND) {
        io_uring_prep_send(sqe, (int)req->fd, req->buffer,
                           (unsigned)req->length, req->flags);
    } else if (req->op == XPOLL_OP_POLL) {
        io_uring_prep_poll_add(sqe, (int)req->fd,
                               _uring_poll_events_from_mask(req->mask));
    } else {
        free(req);
        errno = EINVAL;
        return NULL;
    }

    io_uring_sqe_set_data(sqe, req);
    int rc = io_uring_submit(&loop->uring);
    if (rc < 0) {
        free(req);
        errno = -rc;
        return NULL;
    }
    return req;
}
#endif

static inline long long _fd_key(SOCKET_T fd) {
#if defined(_WIN32)
    return (long long)(uintptr_t)fd;
#else
    return (long long)fd;
#endif
}

static xhash* _fd_map_create(size_t size) {
#if defined(_WIN32)
    /* Windows SOCKET values are arbitrary handles, not contiguous ints. */
    return xhash_create(size, XHASH_KEY_INT);
#else
    return xhash_create(size, XHASH_KEY_INT); // xhash_fd_create(size); // for single thread.
#endif
}

static void _fe_init(xPoolFD *fe, SOCKET_T fd) {
    fe->fd         = fd;
    fe->mask       = XPOLL_NONE;
    fe->idx        = -1;
    fe->rfileProc  = NULL;
    fe->wfileProc  = NULL;
    fe->efileProc  = NULL;
    fe->clientData = NULL;
}

static xPoolFD* _fe_get(xPollState *loop, SOCKET_T fd) {
    if (!loop || !loop->fd_map) return NULL;
    return (xPoolFD*)xhash_get_int(loop->fd_map, _fd_key(fd));
}

/* During callback dispatch, handlers may delete/recreate the same fd.
 * Ensure we only continue dispatching if the exact same entry is still alive.
 */
static xPoolFD* _fe_get_same(xPollState *loop, SOCKET_T fd, xPoolFD *expect) {
    xPoolFD *fe = _fe_get(loop, fd);
    if (!fe || fe != expect || fe->mask == XPOLL_NONE) return NULL;
    return fe;
}

static xPoolFD* _fe_create(xPollState *loop, SOCKET_T fd) {
    xPoolFD *fe = (xPoolFD*)malloc(sizeof(xPoolFD));
    if (!fe) return NULL;
    _fe_init(fe, fd);
    if (!xhash_set_int(loop->fd_map, _fd_key(fd), fe)) {
        free(fe);
        return NULL;
    }
    return fe;
}

static void _fe_destroy(xPollState *loop, xPoolFD *fe) {
    if (!loop || !fe) return;
    xhash_remove_int(loop->fd_map, _fd_key(fe->fd), false);
    free(fe);
}

/* ── poll / WSAPoll-only helpers ── */
#if defined(XPOLL_BACKEND_POLL) || defined(XPOLL_BACKEND_WSAPOLL)

static void _pfd_clear(xPollState *loop, int i) {
#ifdef XPOLL_BACKEND_WSAPOLL
    loop->poll_fds[i].fd = INVALID_SOCKET;
#else
    loop->poll_fds[i].fd = -1;
#endif
    loop->poll_fds[i].events  = 0;
    loop->poll_fds[i].revents = 0;
}

/* Rebuild poll_fds[idx] from the matching fe. */
static void _pfd_sync(xPollState *loop, int idx) {
    xPoolFD *fe = loop->poll_fes[idx];
    loop->poll_fds[idx].events = 0;
    if (!fe) return;
    if (fe->mask & XPOLL_READABLE) loop->poll_fds[idx].events |= POLLIN;
    if (fe->mask & XPOLL_WRITABLE) loop->poll_fds[idx].events |= POLLOUT;
}

#endif /* poll / WSAPoll */

/* ── maxfd recalculation (via fd_map) ── */
static bool _maxfd_cb(xhashKey key, void *value, void *ctx) {
    (void)value;
    int *maxfd = (int*)ctx;
    if ((int)key.i > *maxfd) *maxfd = (int)key.i;
    return true;
}

static void _maxfd_recalc(xPollState *loop) {
    int maxfd = -1;
    if (loop && loop->fd_map)
        xhash_foreach(loop->fd_map, _maxfd_cb, &maxfd);
    loop->maxfd = maxfd;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_init
 * ═══════════════════════════════════════════════════════════════════════ */
int xpoll_init(void) {
    if (_xpoll) return 0;

    xPollState *loop = (xPollState*)calloc(1, sizeof(xPollState));
    if (!loop) return -1;

    loop->fd_map = _fd_map_create(XPOLL_SETSIZE);
    if (!loop->fd_map) { free(loop); return -2; }

    loop->setsize = XPOLL_SETSIZE;
    loop->nfds    = 0;
    loop->maxfd   = -1;

#if defined(XPOLL_BACKEND_EPOLL)

    loop->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epfd < 0) goto fail;

    loop->ep_events = (struct epoll_event*)
        malloc(sizeof(struct epoll_event) * XPOLL_SETSIZE);
    if (!loop->ep_events) { close(loop->epfd); goto fail; }

#if defined(XPOLL_WITH_IO_URING)
    if (_uring_loop_init(loop) != 0) {
        free(loop->ep_events);
        close(loop->epfd);
        goto fail;
    }
#endif

#elif defined(XPOLL_BACKEND_KQUEUE)

    loop->kqfd = kqueue();
    if (loop->kqfd < 0) goto fail;

    loop->kq_events = (struct kevent*)
        malloc(sizeof(struct kevent) * XPOLL_SETSIZE);
    if (!loop->kq_events) { close(loop->kqfd); goto fail; }

#elif defined(XPOLL_BACKEND_WSAPOLL)

    loop->poll_fds = (WSAPOLLFD*) malloc(sizeof(WSAPOLLFD) * XPOLL_SETSIZE);
    loop->poll_fes = (xPoolFD**) calloc(XPOLL_SETSIZE, sizeof(xPoolFD*));
    if (!loop->poll_fds || !loop->poll_fes) {
        free(loop->poll_fds); free(loop->poll_fes); goto fail;
    }
    for (int i = 0; i < XPOLL_SETSIZE; i++) _pfd_clear(loop, i);

#else /* XPOLL_BACKEND_POLL */

    loop->poll_fds = (struct pollfd*) malloc(sizeof(struct pollfd) * XPOLL_SETSIZE);
    loop->poll_fes = (xPoolFD**) calloc(XPOLL_SETSIZE, sizeof(xPoolFD*));
    if (!loop->poll_fds || !loop->poll_fes) {
        free(loop->poll_fds); free(loop->poll_fes); goto fail;
    }
    for (int i = 0; i < XPOLL_SETSIZE; i++) _pfd_clear(loop, i);

#endif

    _xpoll = loop;
    return 0;

fail:
    xhash_destroy(loop->fd_map, true);
    free(loop);
    return -3;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_uninit
 * ═══════════════════════════════════════════════════════════════════════ */
void xpoll_uninit(void) {
    xPollState *loop = _xpoll;
    if (!loop) return;

#if defined(XPOLL_BACKEND_EPOLL)
#if defined(XPOLL_WITH_IO_URING)
    _uring_loop_uninit(loop);
#endif
    if (loop->epfd >= 0) close(loop->epfd);
    free(loop->ep_events);
#elif defined(XPOLL_BACKEND_KQUEUE)
    if (loop->kqfd >= 0) close(loop->kqfd);
    free(loop->kq_events);
#else
    free(loop->poll_fds);
    free(loop->poll_fes);
#endif

    /* fd_map owns every xPoolFD allocation. */
    xhash_destroy(loop->fd_map, true);
    free(loop);
    _xpoll = NULL;
}

int xpoll_inited(void) {
    return _xpoll != NULL ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_get_default
 * ═══════════════════════════════════════════════════════════════════════ */
xPollState* xpoll_get_default(void) {
    return _xpoll;
}

int xpoll_fd_count(void) {
    return _xpoll ? _xpoll->nfds : 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  xpoll_resize
 * ═══════════════════════════════════════════════════════════════════════ */
int xpoll_resize(int setsize) {
    xPollState *loop = _xpoll;
    if (!loop || setsize <= loop->setsize) return 0;

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

    xPoolFD **nfes = (xPoolFD**)realloc(loop->poll_fes, sizeof(xPoolFD*) * setsize);
    if (!nfes) return -1;
    loop->poll_fes = nfes;

    for (int i = loop->setsize; i < setsize; i++) {
        _pfd_clear(loop, i);
        loop->poll_fes[i] = NULL;
    }

#endif

    if (loop->fd_map && loop->fd_map->size < (size_t)setsize)
        xhash_resize(loop->fd_map, (size_t)setsize);

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

    xPoolFD *fe = _fe_get(loop, fd);
    int is_new = 0;

    if (!fe) {
        fe = _fe_create(loop, fd);
        if (!fe) return -1;
        is_new = 1;
    }

    int old_mask = fe->mask;
    int new_mask = old_mask | mask;

    /* Save originals for rollback. */
    xFileProc old_rp = fe->rfileProc;
    xFileProc old_wp = fe->wfileProc;
    xFileProc old_ep = fe->efileProc;
    void     *old_ud = fe->clientData;

    if (rfileProc) fe->rfileProc = rfileProc;
    if (wfileProc) fe->wfileProc = wfileProc;
    if (efileProc) fe->efileProc = efileProc;
    fe->clientData = clientData;

    if (new_mask == old_mask && !is_new) return 0;

    fe->mask       = new_mask;

    struct epoll_event ee;
    memset(&ee, 0, sizeof(ee));
    /* Store fd, not fe pointer, so handler-side fd removal can't dangle. */
    ee.data.fd = (int)fd;
    if (new_mask & XPOLL_READABLE)  ee.events |= EPOLLIN;
    if (new_mask & XPOLL_WRITABLE)  ee.events |= EPOLLOUT;
    ee.events |= EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    int op = is_new ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl(loop->epfd, op, (int)fd, &ee) < 0) {
        if (is_new) {
            _fe_destroy(loop, fe);
        } else {
            fe->mask       = old_mask;
            fe->rfileProc  = old_rp;
            fe->wfileProc  = old_wp;
            fe->efileProc  = old_ep;
            fe->clientData = old_ud;
        }
        return -1;
    }

    if (is_new) loop->nfds++;
    if ((int)fd > loop->maxfd) loop->maxfd = (int)fd;
    return 0;

/* ── kqueue backend ───────────────────────────────────────────────────── */
#elif defined(XPOLL_BACKEND_KQUEUE)

    xPoolFD *fe = _fe_get(loop, fd);
    int is_new = 0;

    if (!fe) {
        fe = _fe_create(loop, fd);
        if (!fe) return -1;
        is_new = 1;
    }

    int old_mask = fe->mask;
    int new_mask = old_mask | mask;
    if (new_mask == old_mask && !is_new) {
        if (rfileProc) fe->rfileProc = rfileProc;
        if (wfileProc) fe->wfileProc = wfileProc;
        if (efileProc) fe->efileProc = efileProc;
        fe->clientData = clientData;
        return 0;
    }

    struct kevent changes[2];
    int nchanges = 0;
    if ((new_mask & XPOLL_READABLE) && !(old_mask & XPOLL_READABLE))
        EV_SET(&changes[nchanges++], (uintptr_t)fd,
               EVFILT_READ,  EV_ADD | EV_ENABLE, 0, 0, NULL);
    if ((new_mask & XPOLL_WRITABLE) && !(old_mask & XPOLL_WRITABLE))
        EV_SET(&changes[nchanges++], (uintptr_t)fd,
               EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);

    if (nchanges > 0 &&
        kevent(loop->kqfd, changes, nchanges, NULL, 0, NULL) < 0) {
        if (is_new) _fe_destroy(loop, fe);
        return -1;
    }

    if (rfileProc) fe->rfileProc = rfileProc;
    if (wfileProc) fe->wfileProc = wfileProc;
    if (efileProc) fe->efileProc = efileProc;
    fe->clientData = clientData;
    fe->mask       = new_mask;

    if (is_new) loop->nfds++;
    if ((int)fd > loop->maxfd) loop->maxfd = (int)fd;
    return 0;

/* ── poll / WSAPoll backend ───────────────────────────────────────────── */
#else

    xPoolFD *fe = _fe_get(loop, fd);

    if (!fe) {
        if (loop->nfds >= loop->setsize) {
            if (xpoll_resize(loop->setsize * 2) < 0) return -1;
        }

        fe = _fe_create(loop, fd);
        if (!fe) return -1;

        int idx = loop->nfds;
        fe->idx = idx;
        loop->poll_fds[idx].fd = fd;
        loop->poll_fes[idx]    = fe;
        loop->nfds++;
    } else if ((fe->mask & mask) == mask) {
        if (rfileProc) fe->rfileProc = rfileProc;
        if (wfileProc) fe->wfileProc = wfileProc;
        if (efileProc) fe->efileProc = efileProc;
        fe->clientData = clientData;
        return 0;
    }

    fe->mask |= mask;
    if (rfileProc) fe->rfileProc = rfileProc;
    if (wfileProc) fe->wfileProc = wfileProc;
    if (efileProc) fe->efileProc = efileProc;
    fe->clientData = clientData;

    _pfd_sync(loop, fe->idx);

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

    xPoolFD *fe = _fe_get(loop, fd);
    if (!fe) return;

/* ── epoll backend ────────────────────────────────────────────────────── */
#if defined(XPOLL_BACKEND_EPOLL)

    int old_mask = fe->mask;
    int new_mask = old_mask & ~mask;
    if (new_mask == old_mask) return;

    if (new_mask == XPOLL_NONE) {
        epoll_ctl(loop->epfd, EPOLL_CTL_DEL, (int)fd, NULL);
        _fe_destroy(loop, fe);
        loop->nfds--;
        if (loop->maxfd == (int)fd) _maxfd_recalc(loop);
    } else {
        struct epoll_event ee;
        memset(&ee, 0, sizeof(ee));
        ee.data.fd = (int)fd;
        if (new_mask & XPOLL_READABLE)  ee.events |= EPOLLIN;
        if (new_mask & XPOLL_WRITABLE)  ee.events |= EPOLLOUT;
        ee.events |= EPOLLERR | EPOLLHUP | EPOLLRDHUP;
        if (epoll_ctl(loop->epfd, EPOLL_CTL_MOD, (int)fd, &ee) == 0)
            fe->mask = new_mask;
    }

/* ── kqueue backend ───────────────────────────────────────────────────── */
#elif defined(XPOLL_BACKEND_KQUEUE)

    int old_mask = fe->mask;
    int new_mask = old_mask & ~mask;
    if (new_mask == old_mask) return;

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
        _fe_destroy(loop, fe);
        loop->nfds--;
        if (loop->maxfd == (int)fd) _maxfd_recalc(loop);
    }

/* ── poll / WSAPoll backend ───────────────────────────────────────────── */
#else

    fe->mask &= ~mask;

    if (fe->mask == XPOLL_NONE) {
        int idx  = fe->idx;
        int last = loop->nfds - 1;
        SOCKET_T removed_fd = fe->fd;

        _fe_destroy(loop, fe);

        if (idx != last) {
            xPoolFD *moved = loop->poll_fes[last];
            loop->poll_fds[idx] = loop->poll_fds[last];
            loop->poll_fes[idx] = moved;
            if (moved) moved->idx = idx;
        }

        _pfd_clear(loop, last);
        loop->poll_fes[last] = NULL;
        loop->nfds--;
        if (loop->maxfd == (int)removed_fd) _maxfd_recalc(loop);
    } else {
        _pfd_sync(loop, fe->idx);
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
#if defined(XPOLL_WITH_IO_URING)
    num_processed += _uring_drain(loop);
    if (num_processed > 0) return num_processed;
    if (loop->uring_ready) maxevents++;
#endif

    if (maxevents > loop->setsize) maxevents = loop->setsize;
    num_ready = epoll_wait(loop->epfd, loop->ep_events, maxevents, timeout_ms);

    if (num_ready < 0) {
        if (errno == EINTR) return 0;
        perror("[xpoll] epoll_wait");
        return -1;
    }

    for (int i = 0; i < num_ready; i++) {
        struct epoll_event *e = &loop->ep_events[i];
        SOCKET_T sfd = (SOCKET_T)e->data.fd;

#if defined(XPOLL_WITH_IO_URING)
        if (loop->uring_ready && (int)sfd == loop->uring_fd) {
            num_processed += _uring_drain(loop);
            continue;
        }
#endif

        xPoolFD *fe = _fe_get(loop, sfd);
        if (!fe || fe->mask == XPOLL_NONE) continue;

        int mask = 0;
        if (e->events & (EPOLLIN  | EPOLLRDHUP)) mask |= XPOLL_READABLE;
        if (e->events & EPOLLOUT)                 mask |= XPOLL_WRITABLE;
        if (e->events & (EPOLLERR | EPOLLHUP))    mask |= XPOLL_ERROR | XPOLL_CLOSE;

        SOCKET_T fd = fe->fd;

        if ((mask & XPOLL_WRITABLE) && fe->wfileProc)
            fe->wfileProc(fd, XPOLL_WRITABLE, fe->clientData);

        fe = _fe_get_same(loop, sfd, fe);
        if (!fe) { num_processed++; continue; }

        if ((mask & XPOLL_READABLE) && fe->rfileProc)
            fe->rfileProc(fd, XPOLL_READABLE, fe->clientData);

        fe = _fe_get_same(loop, sfd, fe);
        if (!fe) { num_processed++; continue; }

        if ((mask & (XPOLL_ERROR | XPOLL_CLOSE)) && fe->efileProc) {
            fprintf(stderr,
                "[xpoll] epoll close/error fd=%d events=0x%x\n",
                (int)sfd, e->events);
            fe->efileProc(fd, mask & (XPOLL_ERROR | XPOLL_CLOSE), fe->clientData);
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
    if (maxevents > loop->setsize) maxevents = loop->setsize;
    num_ready = kevent(loop->kqfd, NULL, 0, loop->kq_events, maxevents, tsp);

    if (num_ready < 0) {
        if (errno == EINTR) return 0;
        perror("[xpoll] kevent");
        return -1;
    }

    for (int i = 0; i < num_ready; i++) {
        struct kevent *ke = &loop->kq_events[i];
        SOCKET_T sfd = (SOCKET_T)ke->ident;

        xPoolFD *fe = _fe_get(loop, sfd);
        if (!fe || fe->mask == XPOLL_NONE) continue;

        int mask = 0;
        if (ke->filter == EVFILT_READ)   mask |= XPOLL_READABLE;
        if (ke->filter == EVFILT_WRITE)  mask |= XPOLL_WRITABLE;
        if (ke->flags  & EV_EOF)         mask |= XPOLL_CLOSE;
        if (ke->flags  & EV_ERROR)       mask |= XPOLL_ERROR;

        SOCKET_T fd = fe->fd;

        if ((mask & XPOLL_WRITABLE) && fe->wfileProc)
            fe->wfileProc(fd, XPOLL_WRITABLE, fe->clientData);

        fe = _fe_get_same(loop, sfd, fe);
        if (!fe) { num_processed++; continue; }

        if ((mask & XPOLL_READABLE) && fe->rfileProc)
            fe->rfileProc(fd, XPOLL_READABLE, fe->clientData);

        fe = _fe_get_same(loop, sfd, fe);
        if (!fe) { num_processed++; continue; }

        if ((mask & (XPOLL_ERROR | XPOLL_CLOSE)) && fe->efileProc) {
            fprintf(stderr,
                "[xpoll] kqueue close/error fd=%d flags=0x%x\n",
                (int)sfd, ke->flags);
            fe->efileProc(fd, mask & (XPOLL_ERROR | XPOLL_CLOSE), fe->clientData);
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

    /* Iterate in reverse so compaction during delete doesn't skip entries. */
    for (int i = nfds - 1; i >= 0; i--) {
#ifdef XPOLL_BACKEND_WSAPOLL
        if (loop->poll_fds[i].fd == INVALID_SOCKET) continue;
#else
        if (loop->poll_fds[i].fd < 0) continue;
#endif
        short revents = loop->poll_fds[i].revents;
        if (revents == 0) continue;

        int mask = 0;
        if (revents & POLLIN)                       mask |= XPOLL_READABLE;
        if (revents & POLLOUT)                      mask |= XPOLL_WRITABLE;
        if (revents & (POLLERR | POLLHUP | POLLNVAL))
                                                    mask |= XPOLL_ERROR | XPOLL_CLOSE;
        loop->poll_fds[i].revents = 0;

        xPoolFD *fe = loop->poll_fes[i];
        if (!fe) continue;

        SOCKET_T  fd = fe->fd;

        if ((mask & XPOLL_WRITABLE) && fe->wfileProc)
            fe->wfileProc(fd, XPOLL_WRITABLE, fe->clientData);

        fe = _fe_get_same(loop, fd, fe);
        if (!fe) { num_processed++; continue; }

        if ((mask & XPOLL_READABLE) && fe->rfileProc)
            fe->rfileProc(fd, XPOLL_READABLE, fe->clientData);

        fe = _fe_get_same(loop, fd, fe);
        if (!fe) { num_processed++; continue; }

        if ((mask & (XPOLL_ERROR | XPOLL_CLOSE)) && fe->efileProc) {
            fprintf(stderr,
                "[xpoll] poll close/error fd=%d revents=0x%x\n",
                (int)fd, (unsigned)revents);
            fe->efileProc(fd, mask & (XPOLL_ERROR | XPOLL_CLOSE), fe->clientData);
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

    xPoolFD *fe = _fe_get(loop, fd);
    if (!fe) return -1;

#if defined(XPOLL_BACKEND_EPOLL) || defined(XPOLL_BACKEND_KQUEUE)
    return (int)fd;
#else
    return fe->idx;
#endif
}

void xpoll_set_client_data(SOCKET_T fd, void *clientData) {
    xPollState *loop = _xpoll;
    if (!loop) return;
    xPoolFD *fe = _fe_get(loop, fd);
    if (fe) fe->clientData = clientData;
}

void* xpoll_get_client_data(SOCKET_T fd) {
    xPollState *loop = _xpoll;
    if (!loop) return NULL;
    xPoolFD *fe = _fe_get(loop, fd);
    return fe ? fe->clientData : NULL;
}

#if defined(XPOLL_WITH_IO_URING)
int xpoll_uring_enabled(void) {
    xPollState *loop = _xpoll;
    return (loop && loop->uring_ready) ? 1 : 0;
}

xPollRequest* xpoll_submit_recv(SOCKET_T fd, void *buf, size_t len, int flags,
                                xPollCompleteProc completeProc,
                                void *clientData) {
    if (!buf || len == 0) {
        errno = EINVAL;
        return NULL;
    }
    return _uring_submit_request(
        _uring_request_new(fd, XPOLL_OP_RECV, XPOLL_READABLE, flags,
                           buf, len, completeProc, clientData));
}

xPollRequest* xpoll_submit_send(SOCKET_T fd, const void *buf, size_t len,
                                int flags,
                                xPollCompleteProc completeProc,
                                void *clientData) {
    if (!buf || len == 0) {
        errno = EINVAL;
        return NULL;
    }
    return _uring_submit_request(
        _uring_request_new(fd, XPOLL_OP_SEND, XPOLL_WRITABLE, flags,
                           (void*)buf, len, completeProc, clientData));
}

xPollRequest* xpoll_submit_poll(SOCKET_T fd, int mask,
                                xPollCompleteProc completeProc,
                                void *clientData) {
    if ((mask & XPOLL_ALL) == 0) {
        errno = EINVAL;
        return NULL;
    }
    return _uring_submit_request(
        _uring_request_new(fd, XPOLL_OP_POLL, mask, 0,
                           NULL, 0, completeProc, clientData));
}

int xpoll_cancel_request(xPollRequest *request) {
    xPollState *loop = _xpoll;
    if (!loop || !loop->uring_ready || !request) {
        errno = EINVAL;
        return -1;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->uring);
    if (!sqe) {
        int rc = io_uring_submit(&loop->uring);
        if (rc < 0) {
            errno = -rc;
            return -1;
        }
        sqe = io_uring_get_sqe(&loop->uring);
        if (!sqe) {
            errno = EAGAIN;
            return -1;
        }
    }

    io_uring_prep_cancel(sqe, request, 0);
    io_uring_sqe_set_data(sqe, NULL);
    int rc = io_uring_submit(&loop->uring);
    if (rc < 0) {
        errno = -rc;
        return -1;
    }
    return 0;
}
#endif

/* Return the active backend name */
const char* xpoll_name(void) {
#if   defined(XPOLL_WITH_IO_URING)
    return "epoll+io_uring";
#elif defined(XPOLL_BACKEND_EPOLL)
    return "epoll";
#elif defined(XPOLL_BACKEND_KQUEUE)
    return "kqueue";
#elif defined(XPOLL_BACKEND_WSAPOLL)
    return "wsapoll";
#else
    return "poll";
#endif
}
