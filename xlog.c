#include "xlog.h"

#ifndef __ANDROID__

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <direct.h>
#include <windows.h>
#else
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

/* Guarded so this file drops straight into a tree without xmacro.h (../xproxy). */
#if defined(__has_include)
#  if __has_include("xmacro.h")
#    include "xmacro.h" /* malloc/free -> rpmalloc when available */
#  endif
#else
#  include "xmacro.h"
#endif

#if defined(_MSC_VER)
#define XLOG_TLS __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define XLOG_TLS _Thread_local
#else
#define XLOG_TLS __thread
#endif

/* Cached seconds-resolution timestamp ("YYYY-MM-DD HH:MM:SS" = 19 chars + NUL). */
#define XLOG_TS_CACHE_LEN 24u

/* One log file plus the bookkeeping its roll-over needs. A thread owns a sink
** only after xlog_enable_thread_file(); everyone else shares g_shared. */
typedef struct {
    FILE* file;
    /* Running size of the active file; drives the size roll-over. A per-thread
    ** sink is owned by that thread alone, so the hot path is a single add +
    ** compare, no lock. */
    unsigned long long bytes;
    unsigned int seq;           /* the _NNN suffix currently open */
    int open_attempted;
    char base[384];             /* "<dir>/<proc>_<thread>", without _NNN.log */
    char path[512];
} xLogSink;

typedef struct {
    int id;
    int own_file;               /* xlog_enable_thread_file() was called here */
    int tls_cleanup_registered;
    char name[64];
    char file_name[64];         /* file-name component derived from name/id */
    char tag[96];
    xLogSink sink;
    /* Per-thread localtime cache: skips libc tz-conversion lock for repeat seconds. */
    time_t ts_cached_sec;
    char ts_cached_str[XLOG_TS_CACHE_LEN];
} xLogThreadState;

static char g_log_dir[256] = "logs";
static char g_process_name[64] = "xnet";
static volatile int g_configured = 0;
/* The process log. Every thread that never asked for its own file writes here,
** the main thread included, so a worker emitting two framework lines no longer
** leaves an almost-empty file of its own behind. */
static xLogSink g_shared;
static unsigned long long g_max_file_bytes = XLOG_MAX_FILE_BYTES;
/* Reads of aligned int are atomic on all targets we ship to; volatile blocks
** compiler reordering / caching across reads. Writes are infrequent. */
static volatile int g_min_level = XLOG_LEVEL_VERBOSE;
static volatile int g_console_enabled = 1;

static XLOG_TLS xLogThreadState g_thread_log;

/* ---------- Thread-exit cleanup: close per-thread file handles automatically ---------- */

#ifdef _WIN32
static DWORD g_fls_index = FLS_OUT_OF_INDEXES;
static INIT_ONCE g_fls_once = INIT_ONCE_STATIC_INIT;

static VOID NTAPI xlog_fls_callback(PVOID p) {
    xLogThreadState* st = (xLogThreadState*)p;
    if (!st) return;
    if (st->sink.file) {
        fflush(st->sink.file);
        fclose(st->sink.file);
        st->sink.file = NULL;
    }
}

static BOOL CALLBACK xlog_fls_init(PINIT_ONCE once, PVOID param, PVOID* ctx) {
    (void)once; (void)param; (void)ctx;
    g_fls_index = FlsAlloc(xlog_fls_callback);
    return TRUE;
}

static void xlog_register_tls_cleanup(xLogThreadState* st) {
    if (st->tls_cleanup_registered) return;
    InitOnceExecuteOnce(&g_fls_once, xlog_fls_init, NULL, NULL);
    if (g_fls_index != FLS_OUT_OF_INDEXES) {
        FlsSetValue(g_fls_index, st);
        st->tls_cleanup_registered = 1;
    }
}

static void xlog_unregister_tls_cleanup(xLogThreadState* st) {
    if (!st->tls_cleanup_registered) return;
    if (g_fls_index != FLS_OUT_OF_INDEXES) {
        FlsSetValue(g_fls_index, NULL);
    }
    st->tls_cleanup_registered = 0;
}
#else
static pthread_key_t g_tls_key;
static pthread_once_t g_tls_once = PTHREAD_ONCE_INIT;
static int g_tls_key_ok = 0;

static void xlog_tls_destructor(void* p) {
    xLogThreadState* st = (xLogThreadState*)p;
    if (!st) return;
    if (st->sink.file) {
        fflush(st->sink.file);
        fclose(st->sink.file);
        st->sink.file = NULL;
    }
}

static void xlog_tls_init(void) {
    g_tls_key_ok = (pthread_key_create(&g_tls_key, xlog_tls_destructor) == 0);
}

static void xlog_register_tls_cleanup(xLogThreadState* st) {
    if (st->tls_cleanup_registered) return;
    pthread_once(&g_tls_once, xlog_tls_init);
    if (g_tls_key_ok) {
        pthread_setspecific(g_tls_key, st);
        st->tls_cleanup_registered = 1;
    }
}

static void xlog_unregister_tls_cleanup(xLogThreadState* st) {
    if (!st->tls_cleanup_registered) return;
    if (g_tls_key_ok) {
        pthread_setspecific(g_tls_key, NULL);
    }
    st->tls_cleanup_registered = 0;
}
#endif

/* ---------- Console serialization lock ---------- */

#ifdef _WIN32
static SRWLOCK g_console_lock = SRWLOCK_INIT;
static void xlog_console_lock(void)   { AcquireSRWLockExclusive(&g_console_lock); }
static void xlog_console_unlock(void) { ReleaseSRWLockExclusive(&g_console_lock); }
static SRWLOCK g_shared_lock = SRWLOCK_INIT;
static void xlog_shared_lock(void)    { AcquireSRWLockExclusive(&g_shared_lock); }
static void xlog_shared_unlock(void)  { ReleaseSRWLockExclusive(&g_shared_lock); }
#else
static pthread_mutex_t g_console_lock = PTHREAD_MUTEX_INITIALIZER;
static void xlog_console_lock(void)   { pthread_mutex_lock(&g_console_lock); }
static void xlog_console_unlock(void) { pthread_mutex_unlock(&g_console_lock); }
static pthread_mutex_t g_shared_lock = PTHREAD_MUTEX_INITIALIZER;
static void xlog_shared_lock(void)    { pthread_mutex_lock(&g_shared_lock); }
static void xlog_shared_unlock(void)  { pthread_mutex_unlock(&g_shared_lock); }
#endif

/* ---------- Small utilities ---------- */

static void xlog_mkdir(const char* dir) {
    if (!dir || !dir[0]) return;
#ifdef _WIN32
    _mkdir(dir);
#else
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) return;
#endif
}

static void xlog_copy(char* dst, size_t cap, const char* src, const char* fallback) {
    const char* s = (src && src[0]) ? src : fallback;
    if (!dst || cap == 0) return;
    if (!s) s = "";
    snprintf(dst, cap, "%.*s", (int)(cap - 1), s);
}

static int xlog_is_word_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static int xlog_token_is_worker(const char* tok, size_t len) {
    static const char kWorker[] = "worker";
    size_t i;
    if (len != sizeof(kWorker) - 1u) return 0;
    for (i = 0; i < len; ++i) {
        char c = tok[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != kWorker[i]) return 0;
    }
    return 1;
}

/* Fold `src` into a log-file name component: alphanumeric runs become tokens
** joined by '_', so '-' and every other separator end up as one underscore
** ("xagent-viz-01" -> "xagent_viz_01"). With `drop_worker` the meaningless
** "worker" token is dropped too, which is what turns the framework's
** "xmysql-worker" into "xmysql" and "gate-worker-06" into "gate_06".
** Writes an empty string when nothing usable survives (e.g. a CJK-only name),
** leaving the caller to fall back to the numeric thread form. */
static void xlog_name_component(char* dst, size_t cap, const char* src, int drop_worker) {
    size_t out = 0;
    if (!dst || cap == 0) return;
    dst[0] = '\0';
    if (!src) return;
    while (*src && out + 1u < cap) {
        const char* tok;
        size_t tok_len = 0;
        size_t i;
        while (*src && !xlog_is_word_char((unsigned char)*src)) ++src;
        tok = src;
        while (xlog_is_word_char((unsigned char)*src)) { ++src; ++tok_len; }
        if (tok_len == 0) break;
        if (drop_worker && xlog_token_is_worker(tok, tok_len)) continue;
        if (out > 0 && out + 1u < cap) dst[out++] = '_';
        for (i = 0; i < tok_len && out + 1u < cap; ++i) dst[out++] = tok[i];
    }
    dst[out] = '\0';
}

#ifdef _WIN32
static int g_vt_enabled = 0;

static void xlog_enable_vt100(void) {
    if (g_vt_enabled) return;
    HANDLE handles[2] = {
        GetStdHandle(STD_OUTPUT_HANDLE),
        GetStdHandle(STD_ERROR_HANDLE),
    };
    for (int i = 0; i < 2; ++i) {
        HANDLE h = handles[i];
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD mode = 0;
        if (!GetConsoleMode(h, &mode)) continue;
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(h, mode);
    }
    g_vt_enabled = 1;
}
#else
static void xlog_enable_vt100(void) {}
#endif

static int xlog_is_system_level_name(const char* level_name) {
    return level_name && strcmp(level_name, XLOG_LEVEL_NAME_SYSM) == 0;
}

static FILE* xlog_console_stream(int level, const char* level_name) {
    if (xlog_is_system_level_name(level_name)) return stdout;
    return (level >= XLOG_LEVEL_WARN) ? stderr : stdout;
}

/* Only sync to OS for levels worth crash-preserving. Lower-severity records
** ride the libc block buffer and flush on natural boundaries / process exit. */
static int xlog_should_flush(int level) {
    return level >= XLOG_LEVEL_WARN;
}

/* ---------- Timestamp with millisecond precision + per-thread second cache ---------- */

static void xlog_wall_clock(time_t* sec, int* msec) {
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER li;
    uint64_t hns;
    GetSystemTimePreciseAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    /* FILETIME counts 100ns intervals since 1601-01-01; convert to Unix epoch. */
    hns = li.QuadPart - 116444736000000000ULL;
    *sec = (time_t)(hns / 10000000ULL);
    *msec = (int)((hns / 10000ULL) % 1000ULL);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        *sec = ts.tv_sec;
        *msec = (int)(ts.tv_nsec / 1000000);
    } else {
        *sec = time(NULL);
        *msec = 0;
    }
#endif
}

static void xlog_now(char* buf, size_t cap) {
    xLogThreadState* st = &g_thread_log;
    time_t sec;
    int msec;
    xlog_wall_clock(&sec, &msec);

    /* Refresh the cached "YYYY-MM-DD HH:MM:SS" only when the second rolls over.
    ** Saves ~one tz-conversion lock per log line under bursty traffic. */
    if (sec != st->ts_cached_sec || st->ts_cached_str[0] == '\0') {
        struct tm tmv;
#ifdef _WIN32
        localtime_s(&tmv, &sec);
#else
        localtime_r(&sec, &tmv);
#endif
        strftime(st->ts_cached_str, sizeof(st->ts_cached_str), "%Y-%m-%d %H:%M:%S", &tmv);
        st->ts_cached_sec = sec;
    }
    snprintf(buf, cap, "%s.%03d", st->ts_cached_str, msec);
}

/* ---------- Record context ---------- */

typedef struct {
    char ts[32];
    const char* level_name;
    const char* console_tag;
    char thread_tag[96];
} xLogRecordContext;

static void xlog_make_thread_tag(char* dst, size_t cap, int id, const char* name, const char* thread_label) {
    const char* safe_name = (name && name[0]) ? name : "unknown";
    if (!dst || cap == 0) return;

    if (thread_label && thread_label[0]) {
        snprintf(dst, cap, "[%.*s]", (int)(cap - 3), thread_label);
        return;
    }

    if (id > 0) {
        int id_len = snprintf(NULL, 0, "%d", id);
        int name_max = (int)cap - 5 - id_len;
        if (name_max < 1) name_max = 1;
        snprintf(dst, cap, "[T%d:%.*s]", id, name_max, safe_name);
    } else {
        snprintf(dst, cap, "[T0:%.*s]", (int)(cap - 6), safe_name);
    }
}

static void xlog_record_context(const char* level_name, const char* console_tag, xLogRecordContext* ctx) {
    xLogThreadState* st = &g_thread_log;
    xlog_now(ctx->ts, sizeof(ctx->ts));
    ctx->level_name = (level_name && level_name[0]) ? level_name : "LOG";
    ctx->console_tag = (console_tag && console_tag[0]) ? console_tag : NULL;
    if (st->tag[0]) {
        xlog_copy(ctx->thread_tag, sizeof(ctx->thread_tag), st->tag, "[T0:unknown]");
    } else {
        xlog_make_thread_tag(ctx->thread_tag, sizeof(ctx->thread_tag),
                             st->id, st->name, NULL);
    }
}

static int xlog_format_needs_newline(const char* fmt) {
    size_t len = strlen(fmt);
    return len == 0 || fmt[len - 1] != '\n';
}

static size_t xlog_record_max_bytes(void) {
    size_t max = (size_t)XLOG_RECORD_MAX_BYTES;
    if (max < (size_t)XLOG_RECORD_STACK_BYTES) {
        max = (size_t)XLOG_RECORD_STACK_BYTES;
    }
    return max;
}

/* ---------- Prefix builder (small, always fits on stack) ---------- */

/* Renders "<tag> [ts] <thread_tag> " into buf. Returns bytes written (clamped to cap-1).
** `console` selects the colored tag vs the plain "[LEVEL]" form. */
static size_t xlog_build_prefix(const xLogRecordContext* ctx, int console, char* buf, size_t cap) {
    int n;
    if (cap == 0) return 0;
    if (console && ctx->console_tag) {
        n = snprintf(buf, cap, "%s [%s] %s ", ctx->console_tag, ctx->ts, ctx->thread_tag);
    } else {
        n = snprintf(buf, cap, "[%s] [%s] %s ", ctx->level_name, ctx->ts, ctx->thread_tag);
    }
    if (n < 0) return 0;
    if ((size_t)n >= cap) return cap - 1;
    return (size_t)n;
}

/* ---------- Body buffer (the user's formatted message, formatted ONCE) ---------- */

typedef struct {
    const char* data;       /* points into either inline_buf or heap */
    char* heap;             /* non-NULL if message was promoted to heap */
    size_t len;              /* actual bytes available at data */
} xLogBody;

static void xlog_body_free(xLogBody* body) {
    if (body->heap) {
        free(body->heap);
        body->heap = NULL;
    }
    body->data = NULL;
    body->len = 0;
}

/* Format the user's fmt+ap into `inline_buf` (with `inline_cap` writable bytes).
** If the formatted output overflows the stack buffer, allocate a heap buffer
** sized to fit (capped at xlog_record_max_bytes). On heap-alloc failure, falls
** back to the truncated stack output. Total format invocations: 1 or 2 (never 4). */
static void xlog_format_body(const char* fmt, va_list ap,
                             char* inline_buf, size_t inline_cap,
                             xLogBody* body) {
    va_list ap2;
    int need;

    body->heap = NULL;
    body->data = inline_buf;
    body->len = 0;

    if (inline_cap == 0) return;

    va_copy(ap2, ap);
    need = vsnprintf(inline_buf, inline_cap, fmt, ap2);
    va_end(ap2);

    if (need < 0) {
        static const char err[] = "(log format error)";
        size_t n = sizeof(err) - 1u;
        if (n >= inline_cap) n = inline_cap - 1u;
        memcpy(inline_buf, err, n);
        inline_buf[n] = '\0';
        body->len = n;
        return;
    }

    if ((size_t)need < inline_cap) {
        /* Fit in inline; vsnprintf already wrote the NUL. */
        body->len = (size_t)need;
        return;
    }

    /* Promotion path: stack buffer was too small for the full body. */
    {
        size_t want = (size_t)need + 1u;
        size_t cap_max = xlog_record_max_bytes();
        if (want > cap_max) want = cap_max;
        body->heap = (char*)malloc(want);
        if (!body->heap) {
            /* Use the truncated stack contents. */
            body->len = inline_cap - 1u;
            return;
        }
        va_copy(ap2, ap);
        need = vsnprintf(body->heap, want, fmt, ap2);
        va_end(ap2);
        if (need < 0) {
            free(body->heap);
            body->heap = NULL;
            body->len = inline_cap - 1u;
            return;
        }
        body->data = body->heap;
        body->len = ((size_t)need < want) ? (size_t)need : want - 1u;
    }
}

/* ---------- Output emission ----------
**
** Both file and console sinks share the same `body` bytes — we never re-run
** vsnprintf for the second sink, only re-render the small prefix. */

static size_t xlog_emit_to_file(FILE* out, const xLogRecordContext* ctx,
                                const char* body, size_t body_len,
                                int append_newline, int do_flush) {
    char prefix[256];
    size_t plen = xlog_build_prefix(ctx, 0, prefix, sizeof(prefix));
    if (plen) fwrite(prefix, 1, plen, out);
    if (body_len) fwrite(body, 1, body_len, out);
    if (append_newline) fputc('\n', out);
    if (do_flush) fflush(out);
    return plen + body_len + (append_newline ? 1u : 0u);
}

static void xlog_emit_to_console(FILE* out, const xLogRecordContext* ctx,
                                 const char* body, size_t body_len,
                                 int append_newline) {
    char prefix[256];
    size_t plen = xlog_build_prefix(ctx, 1, prefix, sizeof(prefix));
    xlog_console_lock();
    if (plen) fwrite(prefix, 1, plen, out);
    if (body_len) fwrite(body, 1, body_len, out);
    if (append_newline) fputc('\n', out);
    /* Console always flushes for liveness — humans expect immediate output. */
    fflush(out);
    xlog_console_unlock();
}

/* ---------- Log files: "<dir>/<proc>_<thread>_<seq>.log" ----------
**
** <proc>   SERVER_NAME when the runner was given one, else "xnet".
** <thread> the registered thread name (minus the noise "worker" token), or
**          "tNNN" for a thread that was never named.
** <seq>    001 upward: when a file reaches the size cap the next number is
**          opened rather than the old file being renamed aside, so history
**          reads in order and live tails never follow a rename.
*/

/* Current size of an already-open file. With "ab" mode writes always land at
** EOF regardless of the read cursor, so this is only consulted once at open to
** seed sink->bytes (a freshly appended-to file may already hold prior data). */
static unsigned long long xlog_stream_size(FILE* f) {
#ifdef _WIN32
    if (_fseeki64(f, 0, SEEK_END) == 0) {
        __int64 p = _ftelli64(f);
        if (p > 0) return (unsigned long long)p;
    }
#else
    if (fseeko(f, 0, SEEK_END) == 0) {
        off_t p = ftello(f);
        if (p > 0) return (unsigned long long)p;
    }
#endif
    return 0;
}

/* Existence + size probe for a path we have not opened. Returns 0 when absent. */
static int xlog_path_size(const char* path, unsigned long long* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    if (size) *size = xlog_stream_size(f);
    fclose(f);
    return 1;
}

static void xlog_sink_make_base(char* dst, size_t cap, const char* file_name) {
    char proc[64];
    xlog_name_component(proc, sizeof(proc), g_process_name, 0);
    if (!proc[0]) xlog_copy(proc, sizeof(proc), "xnet", "xnet");
    snprintf(dst, cap, "%s/%s_%s", g_log_dir, proc, (file_name && file_name[0]) ? file_name : "thread");
}

static void xlog_sink_path(const xLogSink* s, unsigned seq, char* out, size_t cap) {
    snprintf(out, cap, "%s_%03u.log", s->base, seq);
}

/* Highest sequence number already on disk (0 when none). Doubling probe plus a
** bisect, so a directory holding N files costs ~2*log2(N) opens once, not N. */
static unsigned xlog_sink_last_seq(const xLogSink* s) {
    char path[sizeof(s->path)];
    unsigned lo = 0, hi = 1;
    for (;;) {
        xlog_sink_path(s, hi, path, sizeof(path));
        if (!xlog_path_size(path, NULL)) break;
        lo = hi;
        if (hi >= (1u << 20)) break;   /* a million files is not a deployment */
        hi <<= 1;
    }
    while (hi - lo > 1u) {
        unsigned mid = lo + (hi - lo) / 2u;
        xlog_sink_path(s, mid, path, sizeof(path));
        if (xlog_path_size(path, NULL)) lo = mid; else hi = mid;
    }
    return lo;
}

static void xlog_sink_close(xLogSink* s) {
    if (!s->file) return;
    fflush(s->file);
    fclose(s->file);
    s->file = NULL;
}

/* Resume the newest file that still has room, else start the next number.
** open_attempted keeps a failing path (bad dir, no permission) from re-trying
** fopen on every single record. */
static void xlog_sink_open(xLogSink* s) {
    unsigned long long size = 0;
    unsigned seq;
    if (s->file || s->open_attempted) return;
    s->open_attempted = 1;
    if (!s->base[0]) return;

    seq = xlog_sink_last_seq(s);
    if (seq == 0) {
        seq = 1;
    } else {
        xlog_sink_path(s, seq, s->path, sizeof(s->path));
        if (!xlog_path_size(s->path, &size) || size >= g_max_file_bytes) ++seq;
    }
    s->seq = seq;
    xlog_sink_path(s, seq, s->path, sizeof(s->path));
    s->file = fopen(s->path, "ab");
    if (!s->file) return;
    /* Seed the roll-over counter from any pre-existing content so an already
    ** large file rolls promptly instead of growing past the cap. */
    s->bytes = xlog_stream_size(s->file);
}

/* The filled file keeps its name; logging simply moves on to the next number. */
static void xlog_sink_roll(xLogSink* s) {
    xlog_sink_close(s);
    ++s->seq;
    xlog_sink_path(s, s->seq, s->path, sizeof(s->path));
    s->file = fopen(s->path, "ab");
    if (!s->file) {
        /* Allow a later write to retry from a clean slate instead of silently
        ** dropping this sink forever. */
        s->open_attempted = 0;
        s->bytes = 0;
        return;
    }
    s->bytes = xlog_stream_size(s->file);
}

/* Hot-path accountant: add the bytes just written and roll if over cap. */
static void xlog_sink_account(xLogSink* s, size_t bytes) {
    s->bytes += bytes;
    if (s->bytes >= g_max_file_bytes) xlog_sink_roll(s);
}

/* Pick the sink this record belongs to, opening it on first use. The shared
** sink is returned locked -- xlog_sink_release() must follow every non-NULL
** return, and the caller writes inside that window. */
static xLogSink* xlog_sink_acquire(void) {
    xLogThreadState* st = &g_thread_log;
    if (!g_configured) xlog_init(NULL, NULL, 1);
    if (st->own_file) {
        xlog_sink_open(&st->sink);
        if (!st->sink.file) return NULL;
        /* Register thread-exit cleanup so a thread that never calls
        ** xlog_clear_thread() (e.g. raw pthread_exit, std::thread join) won't
        ** leak the FD. */
        xlog_register_tls_cleanup(st);
        return &st->sink;
    }
    xlog_shared_lock();
    xlog_sink_open(&g_shared);
    if (!g_shared.file) {
        xlog_shared_unlock();
        return NULL;
    }
    return &g_shared;
}

static void xlog_sink_release(xLogSink* s) {
    if (s == &g_shared) xlog_shared_unlock();
}

/* ---------- Public API ---------- */

void xlog_init(const char* log_dir, const char* process_name, int enable_console) {
    char base[sizeof(g_shared.base)];
    xlog_copy(g_log_dir, sizeof(g_log_dir), log_dir, "logs");
    xlog_copy(g_process_name, sizeof(g_process_name), process_name, "xnet");
    xlog_mkdir(g_log_dir);
    g_console_enabled = enable_console ? 1 : 0;
    if (g_console_enabled) xlog_enable_vt100();
    g_configured = 1;

    /* The process log doubles as the main thread's file: main writes here, and
    ** so does every thread that never claimed one of its own. */
    xlog_sink_make_base(base, sizeof(base), "main");
    xlog_shared_lock();
    if (strcmp(base, g_shared.base) != 0) {
        xlog_sink_close(&g_shared);
        memset(&g_shared, 0, sizeof(g_shared));
        xlog_copy(g_shared.base, sizeof(g_shared.base), base, "");
    }
    xlog_shared_unlock();

    /* Only claim the caller as the main thread when it has no identity yet: a
    ** worker that reached the lazy-init path must keep the name xthread gave
    ** it instead of being relabelled T1:MAIN. */
    if (g_thread_log.id == 0 && g_thread_log.tag[0] == '\0') {
        xlog_set_thread(1, "main", "T1:MAIN");
    }
}

void xlog_uninit(void) {
    xlog_clear_thread();
    xlog_shared_lock();
    xlog_sink_close(&g_shared);
    memset(&g_shared, 0, sizeof(g_shared));
    xlog_shared_unlock();
    g_configured = 0;
}

/* File-name component for a thread: its registered name when it has one,
** otherwise the numeric "tNNN" form. */
static void xlog_thread_file_name(char* dst, size_t cap, int id, const char* name) {
    xlog_name_component(dst, cap, name, 1);
    if (dst[0]) return;
    snprintf(dst, cap, "t%03d", id > 0 ? id : 0);
}

void xlog_set_thread(int id, const char* name, const char* thread_label) {
    xLogThreadState* st = &g_thread_log;
    char display_name[64];
    char file_name[64];
    char thread_tag[96];
    xlog_copy(display_name, sizeof(display_name), name, id == 1 ? "main" : "thread");
    xlog_make_thread_tag(thread_tag, sizeof(thread_tag), id, display_name, thread_label);
    xlog_thread_file_name(file_name, sizeof(file_name), id, name);

    if (st->id == id &&
        strcmp(st->name, display_name) == 0 &&
        strcmp(st->file_name, file_name) == 0 &&
        strcmp(st->tag, thread_tag) == 0) {
        return;
    }
    /* Identity really changed: drop any file opened under the old name. */
    xlog_clear_thread();
    st->id = id;
    xlog_copy(st->name, sizeof(st->name), display_name, id == 1 ? "main" : "thread");
    xlog_copy(st->file_name, sizeof(st->file_name), file_name, st->name);
    xlog_copy(st->tag, sizeof(st->tag), thread_tag, "[T0:unknown]");
}

void xlog_enable_thread_file(void) {
    xLogThreadState* st = &g_thread_log;
    char base[sizeof(st->sink.base)];
    if (!g_configured) xlog_init(NULL, NULL, 1);
    xlog_sink_make_base(base, sizeof(base), st->file_name);
    /* The main thread's file IS the process log; keep it on the shared sink so
    ** the same path is never opened through two handles. */
    if (strcmp(base, g_shared.base) == 0) return;
    if (st->own_file && strcmp(base, st->sink.base) == 0) return;
    xlog_sink_close(&st->sink);
    memset(&st->sink, 0, sizeof(st->sink));
    xlog_copy(st->sink.base, sizeof(st->sink.base), base, "");
    st->own_file = 1;
}

void xlog_clear_thread(void) {
    xLogThreadState* st = &g_thread_log;
    xlog_sink_close(&st->sink);
    xlog_unregister_tls_cleanup(st);
    memset(st, 0, sizeof(*st));
}

void xlog_set_max_file_bytes(unsigned long long bytes) {
    g_max_file_bytes = bytes ? bytes : (unsigned long long)XLOG_MAX_FILE_BYTES;
}

unsigned long long xlog_get_max_file_bytes(void) {
    return g_max_file_bytes;
}

void xlog_set_level(int min_level) {
    if (min_level < XLOG_LEVEL_VERBOSE) min_level = XLOG_LEVEL_VERBOSE;
    if (min_level > XLOG_LEVEL_FATAL) min_level = XLOG_LEVEL_FATAL;
    g_min_level = min_level;
}

int xlog_get_level(void) {
    return g_min_level;
}

int xlog_is_enabled(int level) {
    return level >= g_min_level;
}

void xlog_write(int level, const char* level_name, const char* console_tag, const char* msg, size_t len, int append_newline) {
    if (!xlog_is_enabled(level)) return;

    xLogRecordContext ctx;
    xlog_record_context(level_name, console_tag, &ctx);

    if (!msg) {
        msg = "";
        len = 0;
    }
    int need_newline = append_newline && (len == 0 || msg[len - 1] != '\n');

    xLogSink* sink = xlog_sink_acquire();
    if (sink) {
        size_t n = xlog_emit_to_file(sink->file, &ctx, msg, len, need_newline,
                                     xlog_should_flush(level));
        xlog_sink_account(sink, n);
        xlog_sink_release(sink);
    }
    if (g_console_enabled) {
        FILE* console = xlog_console_stream(level, ctx.level_name);
        xlog_emit_to_console(console, &ctx, msg, len, need_newline);
    }
}

void xlog_printf(int level, const char* level_name, const char* console_tag, const char* fmt, ...) {
    if (!xlog_is_enabled(level)) return;
    if (!fmt) fmt = "";

    xLogRecordContext ctx;
    xlog_record_context(level_name, console_tag, &ctx);
    int append_newline = xlog_format_needs_newline(fmt);

    /* Single-format path: render the body once, reuse for both sinks. Done
    ** before the sink is acquired so the shared lock never covers a vsnprintf. */
    char inline_buf[XLOG_RECORD_STACK_BYTES + 1u];
    xLogBody body;
    va_list ap;
    va_start(ap, fmt);
    xlog_format_body(fmt, ap, inline_buf, sizeof(inline_buf), &body);
    va_end(ap);

    xLogSink* sink = xlog_sink_acquire();
    if (sink) {
        size_t n = xlog_emit_to_file(sink->file, &ctx, body.data, body.len,
                                     append_newline, xlog_should_flush(level));
        xlog_sink_account(sink, n);
        xlog_sink_release(sink);
    }
    if (g_console_enabled) {
        FILE* console = xlog_console_stream(level, ctx.level_name);
        xlog_emit_to_console(console, &ctx, body.data, body.len, append_newline);
    }
    xlog_body_free(&body);
}

#else /* __ANDROID__ */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static volatile int g_android_min_level = XLOG_LEVEL_VERBOSE;

void xlog_init(const char* log_dir, const char* process_name, int enable_console) {
    (void)log_dir;
    (void)process_name;
    (void)enable_console;
}

void xlog_uninit(void) {}
void xlog_set_thread(int id, const char* name, const char* thread_label) { (void)id; (void)name; (void)thread_label; }
void xlog_clear_thread(void) {}
void xlog_enable_thread_file(void) {}
void xlog_set_max_file_bytes(unsigned long long bytes) { (void)bytes; }
unsigned long long xlog_get_max_file_bytes(void) { return 0; }
void xlog_set_level(int min_level) {
    if (min_level < XLOG_LEVEL_VERBOSE) min_level = XLOG_LEVEL_VERBOSE;
    if (min_level > XLOG_LEVEL_FATAL) min_level = XLOG_LEVEL_FATAL;
    g_android_min_level = min_level;
}
int xlog_get_level(void) { return g_android_min_level; }
int xlog_is_enabled(int level) { return level >= g_android_min_level; }

static int xlog_is_system_level_name(const char* level_name) {
    return level_name && strcmp(level_name, XLOG_LEVEL_NAME_SYSM) == 0;
}

static int xlog_android_level(int level, const char* level_name) {
    if (xlog_is_system_level_name(level_name)) return ANDROID_LOG_INFO;
    switch (level) {
    case XLOG_LEVEL_VERBOSE: return ANDROID_LOG_VERBOSE;
    case XLOG_LEVEL_DEBUG:   return ANDROID_LOG_DEBUG;
    case XLOG_LEVEL_INFO:    return ANDROID_LOG_INFO;
    case XLOG_LEVEL_WARN:    return ANDROID_LOG_WARN;
    case XLOG_LEVEL_ERROR:   return ANDROID_LOG_ERROR;
    case XLOG_LEVEL_FATAL:   return ANDROID_LOG_FATAL;
    default:                 return ANDROID_LOG_INFO;
    }
}

void xlog_write(int level, const char* level_name, const char* console_tag, const char* msg, size_t len, int append_newline) {
    if (!xlog_is_enabled(level)) return;
    (void)console_tag;
    (void)append_newline;
    if (!msg) msg = "";
    __android_log_print(xlog_android_level(level, level_name), LOG_TAG, "%.*s", (int)len, msg);
}

void xlog_printf(int level, const char* level_name, const char* console_tag, const char* fmt, ...) {
    if (!xlog_is_enabled(level)) return;
    (void)console_tag;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt ? fmt : "", ap);
    va_end(ap);
    /* Single format → dispatch to both logcat and the JNI bridge. */
    __android_log_write(xlog_android_level(level, level_name), LOG_TAG, buf);
    native_log_to_java(level, LOG_TAG, buf);
}

/* Helper used by the xlog_* macros so __VA_ARGS__ is evaluated exactly once. */
void xlog_android_emit(int level, int android_prio, const char* fmt, ...) {
    if (!xlog_is_enabled(level)) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt ? fmt : "", ap);
    va_end(ap);
    __android_log_write(android_prio, LOG_TAG, buf);
    native_log_to_java(level, LOG_TAG, buf);
}

#endif /* __ANDROID__ */
