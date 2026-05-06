#include "xchannel.h"

#include "xpoll.h"

#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(XCHANNEL_USE_IO_URING) && defined(XPOLL_WITH_IO_URING)
#define XCHANNEL_WITH_IO_URING 1
#endif

#ifdef __linux__
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#elif !defined(_WIN32)
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#ifndef XCHANNEL_READ_CHUNK
#define XCHANNEL_READ_CHUNK 8192
#endif

#ifndef XCHANNEL_DEFAULT_MAX_PACKET
#define XCHANNEL_DEFAULT_MAX_PACKET (10u * 1024u * 1024u)
#endif

#ifndef XCHANNEL_DEFAULT_BUFFER_MAX
#define XCHANNEL_DEFAULT_BUFFER_MAX (10u * 1024u * 1024u + 4)
#endif

typedef struct xBuffer {
    char*  data;
    size_t off;   /* read position; valid bytes are data[off .. len) */
    size_t len;   /* write position (end of valid data, NOT length) */
    size_t cap;
    size_t max;   /* backpressure threshold; 0 = unlimited */
} xBuffer;

struct xChannel {
    SOCKET_T fd;
    int refcount;
    bool closed;
    bool attached;
    bool connected;
    bool connect_pending;

#if defined(XCHANNEL_WITH_IO_URING)
    bool read_pending;
    bool write_pending;
    xPollRequest* read_req;
    xPollRequest* write_req;
#endif

    xChannelFrame frame;
    size_t max_packet;

    xBuffer in;
    xBuffer out;

#ifdef __linux__
    int file_fd;
    long long file_offset;
#else
    FILE* file_fp;
#endif
    bool file_pending;
    long long file_remaining;

    uint64_t bytes_sent;
    uint64_t bytes_recv;

    xChannelConnectProc connect_cb;
    xChannelPacketProc packet_cb;
    xChannelCloseProc close_cb;
    void* userdata;
};

static void xchannel_read_event(SOCKET_T fd, int mask,
                                void* clientData, xPollRequest* submit_arg);
static void xchannel_write_event(SOCKET_T fd, int mask,
                                 void* clientData, xPollRequest* submit_arg);
static void xchannel_connect_event(SOCKET_T fd, int mask,
                                   void* clientData, xPollRequest* submit_arg);
static void xchannel_error_event(SOCKET_T fd, int mask,
                                 void* clientData, xPollRequest* submit_arg);
#if defined(XCHANNEL_WITH_IO_URING)
static int xchannel_uring_arm_read(xChannel* ch);
static int xchannel_uring_arm_write(xChannel* ch);
static void xchannel_uring_read_done(SOCKET_T fd, int mask,
                                     void* clientData, xPollRequest* submit_arg);
static void xchannel_uring_write_done(SOCKET_T fd, int mask,
                                      void* clientData, xPollRequest* submit_arg);
#endif

static inline size_t xbuf_size(const xBuffer* b) {
    return b->len - b->off;
}

static void xbuf_consume(xBuffer* b, size_t n) {
    size_t avail = b->len - b->off;
    if (n >= avail) {
        b->off = 0;
        b->len = 0;
        return;
    }
    b->off += n;
}

static bool xbuf_reserve(xBuffer* b, size_t need) {
    if (need == 0) return true;
    if (b->cap - b->len >= need) return true;

    size_t used = b->len - b->off;

    /* Try compacting first — avoids realloc when there's stale head space. */
    if (b->off > 0) {
        if (used > 0) memmove(b->data, b->data + b->off, used);
        b->len = used;
        b->off = 0;
        if (b->cap - b->len >= need) return true;
    }

    if (used > SIZE_MAX - need) return false;
    size_t target = used + need;
    size_t ncap = b->cap > 0 ? b->cap : 4096;
    while (ncap < target) {
        if (ncap > SIZE_MAX / 2) return false;
        ncap *= 2;
    }
    char* nbuf = (char*)realloc(b->data, ncap);
    if (!nbuf) return false;
    b->data = nbuf;
    b->cap = ncap;
    return true;
}

static bool xbuf_append(xBuffer* b, const char* data, size_t len) {
    if (len == 0) return true;
    if (!xbuf_reserve(b, len)) return false;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return true;
}

static void xbuf_free(xBuffer* b) {
    free(b->data);
    b->data = NULL;
    b->off = 0;
    b->len = 0;
    b->cap = 0;
    b->max = 0;
}

static bool has_pending_file(xChannel* ch) {
    return ch && ch->file_pending && ch->file_remaining > 0;
}

static void close_pending_file(xChannel* ch) {
    if (!ch) return;
    if (!ch->file_pending) {
#ifdef __linux__
        ch->file_fd = -1;
#else
        ch->file_fp = NULL;
#endif
        ch->file_remaining = 0;
        return;
    }
#ifdef __linux__
    if (ch->file_fd >= 0) {
        close(ch->file_fd);
        ch->file_fd = -1;
    }
#else
    if (ch->file_fp) {
        fclose(ch->file_fp);
    }
    ch->file_fp = NULL;
#endif
    ch->file_pending = false;
    ch->file_remaining = 0;
}

static bool valid_frame(xChannelFrame frame) {
    return frame == XCHANNEL_FRAME_RAW ||
           frame == XCHANNEL_FRAME_LEN32 ||
           frame == XCHANNEL_FRAME_CRLF;
}

static void write_u32be(char* p, uint32_t v) {
    p[0] = (char)((v >> 24) & 0xff);
    p[1] = (char)((v >> 16) & 0xff);
    p[2] = (char)((v >> 8) & 0xff);
    p[3] = (char)(v & 0xff);
}

static uint32_t read_u32be(const char* p) {
    const unsigned char* b = (const unsigned char*)p;
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) |
           (uint32_t)b[3];
}

static void xchannel_retain(xChannel* ch) {
    if (ch) ch->refcount++;
}

static void xchannel_free_storage(xChannel* ch) {
    if (!ch) return;
    close_pending_file(ch);
    xbuf_free(&ch->in);
    xbuf_free(&ch->out);
    free(ch);
}

static void xchannel_release(xChannel* ch) {
    if (!ch) return;
    ch->refcount--;
    if (ch->refcount <= 0) {
        xchannel_free_storage(ch);
    }
}

static size_t find_crlf(const char* buf, size_t len) {
    if (len < 2) return SIZE_MAX;
    for (size_t i = 0; i <= len - 2; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
    }
    return SIZE_MAX;
}

static size_t emit_packet(xChannel* ch, const char* data, size_t len) {
    if (!ch || ch->closed || !ch->packet_cb) return 0;
    xchannel_retain(ch);
    size_t consumed = ch->packet_cb(ch, data, len, ch->userdata);
    xchannel_release(ch);
    return consumed;
}

static void close_internal(xChannel* ch, const char* reason, bool notify) {
    if (!ch || ch->closed) return;

    ch->closed = true;
    ch->attached = false;
    ch->connected = false;
    ch->connect_pending = false;

#if defined(XCHANNEL_WITH_IO_URING)
    if (ch->read_req) {
        xpoll_cancel_request(ch->read_req);
        ch->read_req = NULL;
    }
    ch->read_pending = false;
    if (ch->write_req) {
        xpoll_cancel_request(ch->write_req);
        ch->write_req = NULL;
    }
    ch->write_pending = false;
#endif

    if (ch->fd != INVALID_SOCKET_VAL) {
        xpoll_del_event(ch->fd, XPOLL_ALL);
        xsock_close(ch->fd);
        ch->fd = INVALID_SOCKET_VAL;
    }
    close_pending_file(ch);

    if (notify && ch->close_cb) {
        ch->close_cb(ch, reason ? reason : "closed", ch->userdata);
    }
}

static int check_send_limit(xChannel* ch, size_t alen, size_t blen) {
    if (!ch || ch->closed || ch->fd == INVALID_SOCKET_VAL) return -1;
    if (alen == 0 && blen == 0) return 0;
    if (has_pending_file(ch)) return -1;
    if (ch->out.max > 0 && xbuf_size(&ch->out) >= ch->out.max) return -2;
    if (alen > SIZE_MAX - blen) return -1;
    return 0;
}

static int process_input(xChannel* ch) {
    int rc = 0;
    while (ch && !ch->closed && xbuf_size(&ch->in) > 0) {
        if (ch->frame == XCHANNEL_FRAME_LEN32) {
            size_t avail = xbuf_size(&ch->in);
            if (avail < 4) return rc;

            uint32_t body_len = read_u32be(ch->in.data + ch->in.off);
            if ((size_t)body_len > ch->max_packet) {
                xchannel_close(ch, "packet_too_large");
                return rc;
            }
            if (avail < (size_t)body_len + 4) return rc;

            const char* body = ch->in.data + ch->in.off + 4;
            emit_packet(ch, body_len > 0 ? body : "", body_len);
            if (ch->closed) return rc;
            xbuf_consume(&ch->in, (size_t)body_len + 4);
            rc += 1;
            continue;
        } else if (ch->frame == XCHANNEL_FRAME_CRLF) {
            size_t avail = xbuf_size(&ch->in);
            const char* base = ch->in.data + ch->in.off;
            size_t pos = find_crlf(base, avail);
            if (pos == SIZE_MAX) {
                if (avail > ch->max_packet) {
                    xchannel_close(ch, "packet_too_large");
                }
                return rc;
            }
            if (pos > ch->max_packet) {
                xchannel_close(ch, "packet_too_large");
                return rc;
            }

            emit_packet(ch, pos > 0 ? base : "", pos);
            if (ch->closed) return rc;
            xbuf_consume(&ch->in, pos + 2);
            rc += 1;
            continue;
        } else if (ch->frame == XCHANNEL_FRAME_RAW) {
            size_t avail = xbuf_size(&ch->in);
            if (avail > ch->max_packet) {
                xchannel_close(ch, "packet_too_large");
                return rc;
            }

            size_t consumed = emit_packet(ch, ch->in.data + ch->in.off, avail);
            if (ch->closed) return rc;
            if (consumed == 0) return rc;
            if (consumed > avail) {
                xchannel_close(ch, "consume_error");
                return rc;
            }

            xbuf_consume(&ch->in, consumed);
            rc += 1;
            continue;
        }

        xchannel_close(ch, "bad_frame");
        return rc;
    }
    return rc;
}

/* Try to send up to two segments in a single syscall.
 * On success returns 0 and writes total bytes sent (possibly 0 on EAGAIN) to
 * *sent_out. Returns -1 only on a hard error. */
static int try_send_iov(SOCKET_T fd,
                        const char* a, size_t alen,
                        const char* b, size_t blen,
                        size_t* sent_out) {
    *sent_out = 0;
    
#ifdef _WIN32
    WSABUF bufs[2];
    DWORD nbufs = 0;
    if (alen > 0) {
        bufs[nbufs].buf = (CHAR*)a;
        bufs[nbufs].len = (ULONG)((alen > ULONG_MAX) ? ULONG_MAX : alen);
        nbufs++;
    }
    if (blen > 0) {
        bufs[nbufs].buf = (CHAR*)b;
        bufs[nbufs].len = (ULONG)((blen > ULONG_MAX) ? ULONG_MAX : blen);
        nbufs++;
    }
    DWORD sent = 0;
    int rc = WSASend(fd, bufs, nbufs, &sent, 0, NULL, NULL);
    if (rc == 0) {
        *sent_out = (size_t)sent;
        return 0;
    }
    if (socket_check_eagain()) return 0;
    return -1;
#else
    if (alen == 0 || blen == 0) {
        const char* data = alen > 0 ? a : b;
        size_t len = alen > 0 ? alen : blen;
        int chunk = (len > INT_MAX) ? INT_MAX : (int)len;
        ssize_t n = send(fd, data, chunk, 0);
        if (n >= 0) { *sent_out = (size_t)n; return 0; }
        if (socket_check_eagain()) return 0;
        return -1;
    }

    struct iovec iov[2];
    iov[0].iov_base = (void*)a;
    iov[0].iov_len = alen;
    iov[1].iov_base = (void*)b;
    iov[1].iov_len = blen;
    ssize_t n = writev(fd, iov, 2);
    if (n >= 0) { *sent_out = (size_t)n; return 0; }
    if (socket_check_eagain()) return 0;
    return -1;
#endif
}

static int arm_writable(xChannel* ch, bool while_connecting) {
#if defined(XCHANNEL_WITH_IO_URING)
    (void)while_connecting;
    return xchannel_uring_arm_write(ch);
#else
    xFileProc writable = while_connecting ? xchannel_connect_event
                                          : xchannel_write_event;
    if (xpoll_add_event(ch->fd, XPOLL_WRITABLE, NULL,
                        writable, xchannel_error_event, ch) != 0) {
        xchannel_close(ch, "poll_error");
        return -1;
    }
    return 0;
#endif
}

#if defined(XCHANNEL_WITH_IO_URING)
static int xchannel_uring_arm_read(xChannel* ch) {
    if (!ch || ch->closed || !ch->attached ||
        ch->fd == INVALID_SOCKET_VAL || ch->read_pending) {
        return 0;
    }
    if (ch->in.max > 0 && xbuf_size(&ch->in) > ch->in.max)
        return 0;

    xchannel_retain(ch);
    ch->read_pending = true;
    ch->read_req = xpoll_submit_poll(ch->fd,
                                     XPOLL_READABLE | XPOLL_ERROR | XPOLL_CLOSE,
                                     xchannel_uring_read_done, ch);
    if (!ch->read_req) {
        ch->read_pending = false;
        xchannel_release(ch);
        xchannel_close(ch, "poll_error");
        return -1;
    }
    return 0;
}

static int xchannel_uring_arm_write(xChannel* ch) {
    if (!ch || ch->closed || !ch->attached ||
        ch->fd == INVALID_SOCKET_VAL || ch->write_pending) {
        return 0;
    }

    xchannel_retain(ch);
    ch->write_pending = true;
    ch->write_req = xpoll_submit_poll(ch->fd,
                                      XPOLL_WRITABLE | XPOLL_ERROR | XPOLL_CLOSE,
                                      xchannel_uring_write_done, ch);
    if (!ch->write_req) {
        ch->write_pending = false;
        xchannel_release(ch);
        xchannel_close(ch, "poll_error");
        return -1;
    }
    return 0;
}
#endif

static void flush_output(xChannel* ch) {
    if (!ch || ch->closed || ch->connect_pending) return;

    while (xbuf_size(&ch->out) > 0) {
        size_t remaining = xbuf_size(&ch->out);
        int chunk = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
        int n = send(ch->fd, ch->out.data + ch->out.off, chunk, 0);
        if (n > 0) {
            xbuf_consume(&ch->out, (size_t)n);
            ch->bytes_sent += (size_t)n;
            continue;
        }
        if (n < 0 && socket_check_eagain()) return;
        xchannel_close(ch, "write_error");
        return;
    }

    while (!ch->closed && has_pending_file(ch)) {
#ifdef __linux__
        off_t off = (off_t)ch->file_offset;
        size_t chunk = ch->file_remaining > 1024 * 1024
            ? 1024 * 1024
            : (size_t)ch->file_remaining;
        ssize_t n = sendfile((int)ch->fd, ch->file_fd, &off, chunk);
        if (n > 0) {
            ch->file_offset = (long long)off;
            ch->file_remaining -= (long long)n;
            continue;
        }
        if (n == 0) {
            close_pending_file(ch);
            break;
        }
        if (socket_check_eagain()) return;
        xchannel_close(ch, "sendfile_error");
        return;
#else
        char buf[64 * 1024];
        size_t want = ch->file_remaining > (long long)sizeof(buf)
            ? sizeof(buf)
            : (size_t)ch->file_remaining;
        size_t got = fread(buf, 1, want, ch->file_fp);
        if (got == 0) {
            if (ferror(ch->file_fp)) {
                xchannel_close(ch, "sendfile_read_error");
                return;
            }
            close_pending_file(ch);
            break;
        }

        size_t off = 0;
        while (off < got) {
            size_t remaining = got - off;
            int chunk = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
            int n = send(ch->fd, buf + off, chunk, 0);
            if (n > 0) {
                off += (size_t)n;
                ch->file_remaining -= (long long)n;
                continue;
            }
            if (n == 0 || socket_check_eagain()) {
                long long rewind_bytes = (long long)(got - off);
                if (rewind_bytes > 0) {
#ifdef _WIN32
                    _fseeki64(ch->file_fp, -rewind_bytes, SEEK_CUR);
#else
                    fseeko(ch->file_fp, (off_t)-rewind_bytes, SEEK_CUR);
#endif
                }
                return;
            }
            xchannel_close(ch, "sendfile_write_error");
            return;
        }
#endif
    }

    if (!ch->closed && !has_pending_file(ch)) {
        close_pending_file(ch);
        xpoll_del_event(ch->fd, XPOLL_WRITABLE);
    }
}

/* Atomically queue or send a (head, body) pair. Either segment may be empty.
** Returns -2 when the send buffer is already at/over its backpressure max. */
static int queue_or_send_iov(xChannel* ch,
                             const char* a, size_t alen,
                             const char* b, size_t blen) {
    if ((!a && alen > 0) || (!b && blen > 0)) return -1;
    if (alen == 0 && blen == 0) return 0;                                 
    int rc = check_send_limit(ch, alen, blen);
    if (rc != 0) return rc;
    
    /* Anything in the queue must drain first to preserve ordering. */
    if (ch->connect_pending || xbuf_size(&ch->out) > 0 || !ch->connected) {
        size_t queued = xbuf_size(&ch->out);
        if (alen > 0 && !xbuf_append(&ch->out, a, alen)) {
            xchannel_close(ch, "out_of_memory");
            return -1;
        }
        if (blen > 0 && !xbuf_append(&ch->out, b, blen)) {
            xchannel_close(ch, "out_of_memory");
            return -1;
        }
        if (queued == 0)
            return arm_writable(ch, ch->connect_pending);
        else
            return 0;
    }

    size_t total = alen + blen;
    size_t sent = 0;
    if (try_send_iov(ch->fd, a, alen, b, blen, &sent) < 0) {
        xchannel_close(ch, "write_error");
        return -1;
    }
    ch->bytes_sent += sent;

    if (sent >= total) return 0;

    if (sent < alen) {
        if (!xbuf_append(&ch->out, a + sent, alen - sent)) {
            xchannel_close(ch, "out_of_memory");
            return -1;
        }
        if (blen > 0 && !xbuf_append(&ch->out, b, blen)) {
            xchannel_close(ch, "out_of_memory");
            return -1;
        }
    } else {
        size_t b_skip = sent - alen;
        if (!xbuf_append(&ch->out, b + b_skip, blen - b_skip)) {
            xchannel_close(ch, "out_of_memory");
            return -1;
        }
    }
    return arm_writable(ch, false);
}

static bool finish_connect(xChannel* ch) {
    int err = 0;
#ifdef _WIN32
    int err_len = sizeof(err);
    int rc = getsockopt(ch->fd, SOL_SOCKET, SO_ERROR, (char*)&err, &err_len);
#else
    socklen_t err_len = sizeof(err);
    int rc = getsockopt(ch->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
#endif
    if (rc != 0 || err != 0) {
        xchannel_close(ch, "connect_error");
        return false;
    }

    ch->connect_pending = false;
    ch->connected = true;
    xpoll_del_event(ch->fd, XPOLL_WRITABLE);

    if (xchannel_attach(ch) != 0) {
        xchannel_close(ch, "poll_error");
        return false;
    }

    if(!ch->closed) {
        if (ch->connect_cb) {
            ch->connect_cb(ch, ch->userdata);
        }
        flush_output(ch);

        if (xbuf_size(&ch->out) > 0 || has_pending_file(ch)) {
            if (arm_writable(ch, false) != 0)
                return false;
        }
    }
    return !ch->closed;
}

static void xchannel_read_event(SOCKET_T fd, int mask,
                                void* clientData, xPollRequest* submit_arg) {
    (void)fd;
    (void)mask;
    (void)submit_arg;
    xChannel* ch = (xChannel*)clientData;
    if (!ch || ch->closed) return;

    xchannel_retain(ch);

    bool close_after = false;
    const char* close_reason = NULL;

    int retry = 0;
    while (!ch->closed) {
        if (!xbuf_reserve(&ch->in, XCHANNEL_READ_CHUNK)) {
            xchannel_close(ch, "out_of_memory");
            break;
        }
        size_t space = ch->in.cap - ch->in.len;
        int chunk = (space > INT_MAX) ? INT_MAX : (int)space;
        int n = recv(ch->fd, ch->in.data + ch->in.len, chunk, 0);
        if (n > 0) {
            ch->in.len += (size_t)n;
            ch->bytes_recv += (size_t)n;
            if (ch->in.max > 0 && xbuf_size(&ch->in) > ch->in.max) break;
            if (++retry < 3)
                continue;
            else break;
        }
        if (n == 0) {
            close_after = true;
            close_reason = "eof";
            break;
        }
        if (socket_check_eagain()) break;
        close_after = true;
        close_reason = "read_error";
        break;
    }

    bool over_before = !ch->closed
        && ch->in.max > 0 && xbuf_size(&ch->in) > ch->in.max;
#if !defined(XCHANNEL_WITH_IO_URING)
    if (over_before) xpoll_del_event(ch->fd, XPOLL_READABLE);
#endif

    int n = process_input(ch);
    if (n==0 && over_before)
        xchannel_close(ch, "over_consume_error"); 
    if (over_before && !ch->closed && xbuf_size(&ch->in) <= ch->in.max) {
#if defined(XCHANNEL_WITH_IO_URING)
        if (xchannel_uring_arm_read(ch) != 0) {
            xchannel_close(ch, "poll_error");
        }
#else
        if (xpoll_add_event(ch->fd, XPOLL_READABLE,
                            xchannel_read_event, NULL,
                            xchannel_error_event, ch) != 0) {
            xchannel_close(ch, "poll_error");
        }
#endif
    }

    if (close_after && !ch->closed) xchannel_close(ch, close_reason);

    xchannel_release(ch);
}

static void xchannel_write_event(SOCKET_T fd, int mask,
                                 void* clientData, xPollRequest* submit_arg) {
    (void)fd;
    (void)mask;
    (void)submit_arg;
    xChannel* ch = (xChannel*)clientData;
    if (!ch || ch->closed) return;
    xchannel_retain(ch);
    flush_output(ch);
    xchannel_release(ch);
}

static void xchannel_connect_event(SOCKET_T fd, int mask,
                                   void* clientData, xPollRequest* submit_arg) {
    (void)fd;
    (void)mask;
    (void)submit_arg;
    xChannel* ch = (xChannel*)clientData;
    if (!ch || ch->closed) return;
    xchannel_retain(ch);
    finish_connect(ch);
    xchannel_release(ch);
}

static void xchannel_error_event(SOCKET_T fd, int mask,
                                 void* clientData, xPollRequest* submit_arg) {
    (void)fd;
    (void)mask;
    (void)submit_arg;
    xChannel* ch = (xChannel*)clientData;
    if (!ch || ch->closed) return;
    xchannel_retain(ch);
    xchannel_close(ch, "socket_error");
    xchannel_release(ch);
}

#if defined(XCHANNEL_WITH_IO_URING)
static void xchannel_uring_read_done(SOCKET_T fd, int mask,
                                     void* clientData, xPollRequest* submit_arg) {
    (void)fd;
    xChannel* ch = (xChannel*)clientData;
    if (!ch) return;

    if (!submit_arg || submit_arg != ch->read_req) {
        xchannel_release(ch);
        return;
    }

    ch->read_pending = false;
    ch->read_req = NULL;

    if (!ch->closed && ch->attached) {
        if (xpoll_req_res(submit_arg) < 0 || (mask & XPOLL_ERROR)) {
            xchannel_error_event(ch->fd, XPOLL_ERROR, ch, NULL);
        } else if (mask & (XPOLL_READABLE | XPOLL_CLOSE)) {
            xchannel_read_event(ch->fd, mask, ch, NULL);
        }

        if (!ch->closed && ch->attached &&
            (ch->in.max == 0 || xbuf_size(&ch->in) <= ch->in.max)) {
            xchannel_uring_arm_read(ch);
        }
    }

    xchannel_release(ch);
}

static void xchannel_uring_write_done(SOCKET_T fd, int mask,
                                      void* clientData, xPollRequest* submit_arg) {
    (void)fd;
    xChannel* ch = (xChannel*)clientData;
    if (!ch) return;

    if (!submit_arg || submit_arg != ch->write_req) {
        xchannel_release(ch);
        return;
    }

    ch->write_pending = false;
    ch->write_req = NULL;

    if (!ch->closed && ch->attached) {
        if (xpoll_req_res(submit_arg) < 0 || (mask & XPOLL_ERROR)) {
            xchannel_error_event(ch->fd, XPOLL_ERROR, ch, NULL);
        } else if (ch->connect_pending) {
            xchannel_connect_event(ch->fd, mask, ch, NULL);
        } else if (mask & (XPOLL_WRITABLE | XPOLL_CLOSE)) {
            xchannel_write_event(ch->fd, mask, ch, NULL);
        }

        if (!ch->closed && ch->attached &&
            (ch->connect_pending || xbuf_size(&ch->out) > 0 || has_pending_file(ch))) {
            xchannel_uring_arm_write(ch);
        }
    }

    xchannel_release(ch);
}
#endif

xChannel* xchannel_create(SOCKET_T fd, const xChannelConfig* cfg) {
    xChannel* ch = (xChannel*)calloc(1, sizeof(*ch));
    if (!ch) return NULL;
    ch->fd = fd;
    ch->refcount = 1;
    ch->closed = false;
    ch->attached = false;
    ch->connected = true;
    ch->connect_pending = false;
    ch->frame = XCHANNEL_FRAME_RAW;
    ch->max_packet = XCHANNEL_DEFAULT_MAX_PACKET;
    ch->in.max = XCHANNEL_DEFAULT_BUFFER_MAX;
    ch->out.max = XCHANNEL_DEFAULT_BUFFER_MAX;
#ifdef __linux__
    ch->file_fd = -1;
#endif

    if (cfg) {
        if (!valid_frame(cfg->frame)) {
            free(ch);
            return NULL;
        }
        ch->frame = cfg->frame;
        if (cfg->max_packet > 0) ch->max_packet = cfg->max_packet;
        if (cfg->connect_cb) ch->connect_cb = cfg->connect_cb;
        if (cfg->packet_cb) ch->packet_cb = cfg->packet_cb;
        if (cfg->close_cb) ch->close_cb = cfg->close_cb;
        if (cfg->userdata) ch->userdata = cfg->userdata;
    }

    return ch;
}

void xchannel_destroy(xChannel* ch) {
    if (!ch) return;
    if (!ch->closed) {
        ch->closed = true;
        ch->attached = false;
        ch->connected = false;
        ch->connect_pending = false;
#if defined(XCHANNEL_WITH_IO_URING)
        if (ch->read_req) {
            xpoll_cancel_request(ch->read_req);
            ch->read_req = NULL;
        }
        ch->read_pending = false;
        if (ch->write_req) {
            xpoll_cancel_request(ch->write_req);
            ch->write_req = NULL;
        }
        ch->write_pending = false;
#endif
        if (ch->fd != INVALID_SOCKET_VAL) {
            xpoll_del_event(ch->fd, XPOLL_ALL);
            xsock_close(ch->fd);
            ch->fd = INVALID_SOCKET_VAL;
        }
        close_pending_file(ch);
    }
    xchannel_release(ch);
}

int xchannel_set_framing(xChannel* ch, const xChannelConfig* cfg) {
    if (!ch || ch->closed || !cfg || !valid_frame(cfg->frame)) return -1;
    if (cfg->max_packet > 0) ch->max_packet = cfg->max_packet;
    ch->frame = cfg->frame;
    return 0;
}

SOCKET_T xchannel_fd(xChannel* ch) {
    return ch ? ch->fd : INVALID_SOCKET_VAL;
}

bool xchannel_is_closed(xChannel* ch) {
    return !ch || ch->closed;
}

bool xchannel_is_connected(xChannel* ch) {
    return ch && ch->connected && !ch->closed;
}

void xchannel_set_userdata(xChannel* ch, void* ud) {
    if (ch) ch->userdata = ud;
}

void* xchannel_get_userdata(xChannel* ch) {
    return ch ? ch->userdata : NULL;
}

void xchannel_set_max_packet(xChannel* ch, size_t max_packet) {
    if (ch && max_packet > 0) ch->max_packet = max_packet;
}

void xchannel_set_max_send(xChannel* ch, size_t max) {
    if (ch) ch->out.max = max;
}

void xchannel_set_max_recv(xChannel* ch, size_t max) {
    if (ch) ch->in.max = max;
}

int xchannel_attach(xChannel* ch) {
    if (!ch || ch->closed || ch->fd == INVALID_SOCKET_VAL) return -1;
#if defined(XCHANNEL_WITH_IO_URING)
    ch->attached = true;
    ch->connected = true;
    if (xchannel_uring_arm_read(ch) != 0) {
        ch->attached = false;
        return -1;
    }
    return 0;
#else
    if (xpoll_add_event(ch->fd, XPOLL_READABLE,
                        xchannel_read_event, NULL, xchannel_error_event, ch) != 0) {
        return -1;
    }
    ch->attached = true;
    ch->connected = true;
    return 0;
#endif
}

int xchannel_attach_connect(xChannel* ch) {
    if (!ch || ch->closed || ch->fd == INVALID_SOCKET_VAL) return -1;
    ch->connect_pending = true;
    ch->connected = false;
#if defined(XCHANNEL_WITH_IO_URING)
    ch->attached = true;
    if (xchannel_uring_arm_write(ch) != 0) {
        ch->attached = false;
        return -1;
    }
    return 0;
#else
    if (xpoll_add_event(ch->fd, XPOLL_WRITABLE,
                        NULL, xchannel_connect_event, xchannel_error_event, ch) != 0) {
        return -1;
    }
    ch->attached = true;
    return 0;
#endif
}

void xchannel_detach(xChannel* ch) {
    if (!ch || ch->fd == INVALID_SOCKET_VAL) return;
#if defined(XCHANNEL_WITH_IO_URING)
    ch->attached = false;
    if (ch->read_req) {
        xpoll_cancel_request(ch->read_req);
        ch->read_req = NULL;
    }
    ch->read_pending = false;
    if (ch->write_req) {
        xpoll_cancel_request(ch->write_req);
        ch->write_req = NULL;
    }
    ch->write_pending = false;
#else
    xpoll_del_event(ch->fd, XPOLL_ALL);
    ch->attached = false;
#endif
}

int xchannel_send_raw(xChannel* ch, const char* data, size_t len) {
    return queue_or_send_iov(ch, data, len, NULL, 0);
}

int xchannel_send_packet(xChannel* ch, const char* data, size_t len) {
    if (!ch || ch->closed || (!data && len > 0)) return -1;
    if (has_pending_file(ch)) return -1;
    
    if (ch->frame == XCHANNEL_FRAME_LEN32) {
        if (len > UINT32_MAX) return -1;
        char hdr[4];
        write_u32be(hdr, (uint32_t)len);
        return queue_or_send_iov(ch, hdr, 4, data, len);
    }

    if (ch->frame == XCHANNEL_FRAME_CRLF) {
        static const char trailer[2] = {'\r', '\n'};
        return queue_or_send_iov(ch, data, len, trailer, 2);
    }

    return queue_or_send_iov(ch, data, len, NULL, 0);
}

int xchannel_send_file_raw(xChannel* ch,
                           const char* header, size_t header_len,
                           const char* path,
                           long long offset, long long length) {
    if (!ch || ch->closed || ch->fd == INVALID_SOCKET_VAL || !path) return -1;
    if (!header && header_len > 0) return -1;
    if (has_pending_file(ch)) return -1;
    // if (ch->out.max > 0 && xbuf_size(&ch->out) >= ch->out.max) return -2;
    if (offset < 0) offset = 0;

#ifdef __linux__
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }

    long long size = (long long)st.st_size;
    if (offset > size) offset = size;
    long long available = size - offset;
    if (length < 0 || length > available) length = available;
    if (length == 0) {
        close(fd);
        return queue_or_send_iov(ch, header, header_len, NULL, 0);
    }
#else
    FILE* fp = fopen(path, "rb");
    if (!fp) return -1;

#ifdef _WIN32
    if (_fseeki64(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long long size = _ftelli64(fp);
#else
    if (fseeko(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long long size = (long long)ftello(fp);
#endif
    if (size < 0) {
        fclose(fp);
        return -1;
    }
    if (offset > size) offset = size;
    long long available = size - offset;
    if (length < 0 || length > available) length = available;
    if (length == 0) {
        fclose(fp);
        return queue_or_send_iov(ch, header, header_len, NULL, 0);
    }
#ifdef _WIN32
    if (_fseeki64(fp, offset, SEEK_SET) != 0) {
#else
    if (fseeko(fp, (off_t)offset, SEEK_SET) != 0) {
#endif
        fclose(fp);
        return -1;
    }
#endif

    if (header_len > 0 && !xbuf_append(&ch->out, header, header_len)) {
#ifdef __linux__
        close(fd);
#else
        fclose(fp);
#endif
        xchannel_close(ch, "out_of_memory");
        return -1;
    }

#ifdef __linux__
    ch->file_fd = fd;
    ch->file_offset = offset;
#else
    ch->file_fp = fp;
#endif
    ch->file_pending = true;
    ch->file_remaining = length;

    flush_output(ch);
    if (!ch->closed && (xbuf_size(&ch->out) > 0 || has_pending_file(ch))) {
        if (arm_writable(ch, false) != 0) return -1;
    }
    return ch->closed ? -1 : 0;
}

void xchannel_close(xChannel* ch, const char* reason) {
    if (!ch) return;
    xchannel_retain(ch);
    close_internal(ch, reason, true);
    xchannel_release(ch);
}

void xchannel_get_stats(xChannel* ch,
                        size_t* send_buf, size_t* recv_buf,
                        uint64_t* bytes_sent, uint64_t* bytes_recv) {
    if (!ch) return;
    if (send_buf)   *send_buf   = xbuf_size(&ch->out);
    if (recv_buf)   *recv_buf   = xbuf_size(&ch->in);
    if (bytes_sent) *bytes_sent = ch->bytes_sent;
    if (bytes_recv) *bytes_recv = ch->bytes_recv;
}
