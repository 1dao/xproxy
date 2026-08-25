#include "socks5_server.h"
#include "xsock.h"
#include "xchannel.h"
#include "ssh_tunnel.h"
#include "xpac_server.h"

#include "xpoll.h"
#include "xhash.h"
#ifdef LOG_TAG
    #undef LOG_TAG
#endif
#define LOG_TAG "xsocks5"
#include "xlog.h"
#include <limits.h>

#define MAX_CONCURRENT_CONNECTIONS 8192
#define MAX_REOPEN_COUNT 10 // wait for 3min
#define SOCKS5_WRITE_BUFFER_INITIAL 65536u
#define SOCKS5_WRITE_BUFFER_MAX (16u * 1024u * 1024u)
/* High/low watermarks for SSH write backlog (upload: client -> SSH). */
#define SOCKS5_WBUF_HIGH_WATER (4u * 1024u * 1024u)
#define SOCKS5_WBUF_LOW_WATER  (1u * 1024u * 1024u)
/* High/low watermarks for the client send buffer (download: SSH -> io_ch).
 * High water sits below io_ch's 16 MB max_send so we pause SSH-channel reads
 * before xchannel_send_raw could ever reject with -2. */
#define SOCKS5_IO_SEND_HIGH_WATER (8u * 1024u * 1024u)
#define SOCKS5_IO_SEND_LOW_WATER  (2u * 1024u * 1024u)
#define SOCKS5_WRITE_PUMP_BYTE_BUDGET (4u * 1024u * 1024u)
#define SOCKS5_WRITE_PUMP_ITER_BUDGET 256
/* Returned by socks5_send_reply / socks5_client_send_raw / socks5_reply_and_close
 * to tell callers "the client is now in a terminal state — stop further work". */
#define SOCKS5_SEND_CLOSED (-3)

/* 事件循环里的日志点冷却。POLLOUT 是水平触发的，一次拥塞就能让同一条日志每秒
 * 打几万遍（实测 29958 条/秒、约 3 MB/s，一次会话就写出 16 MB 日志）。同一个
 * 调用点最多 interval_ms 打一条，期间压掉的条数在下一条尾部带出来 —— 不然节流
 * 之后就看不出真实频率，而频率本身正是这里要诊断的东西。
 * 每个展开点各有一份 static 状态，所以互不影响。 */
#define XLOG_CD(interval_ms, logfn, fmt, ...)                          \
    do {                                                               \
        static long64 _cd_next = 0;                                    \
        static unsigned long _cd_dropped = 0;                          \
        long64 _cd_now = time_get_ms();                                \
        if (_cd_now >= _cd_next) {                                     \
            unsigned long _cd_n = _cd_dropped;                         \
            _cd_next = _cd_now + (interval_ms);                        \
            _cd_dropped = 0;                                           \
            if (_cd_n)                                                 \
                logfn(fmt " [+%lu suppressed]", ##__VA_ARGS__, _cd_n); \
            else                                                       \
                logfn(fmt, ##__VA_ARGS__);                             \
        } else {                                                       \
            _cd_dropped++;                                             \
        }                                                              \
    } while (0)
/* 上面这些点统一用 1 秒的冷却。 */
#define SOCKS5_LOG_CD_MS 1000

/* ---- SOCKS5 wire protocol (RFC 1928) -------------------------------------
 * These were public in socks5_server.h, but no caller of the public API ever
 * referenced them — they're an internal protocol detail. */
#define SOCKS5_VERSION                  0x05
#define SOCKS5_RESERVED                 0x00  /* RFC 1928 RSV byte */

#define SOCKS5_AUTH_NONE                0x00
#define SOCKS5_AUTH_GSSAPI              0x01
#define SOCKS5_AUTH_PASSWORD            0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE       0xFF

#define SOCKS5_CMD_CONNECT              0x01
#define SOCKS5_CMD_BIND                 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE        0x03

#define SOCKS5_ATYP_IPV4                0x01
#define SOCKS5_ATYP_DOMAIN              0x03
#define SOCKS5_ATYP_IPV6                0x04

#define SOCKS5_REP_SUCCESS              0x00
#define SOCKS5_REP_GENERAL_FAILURE      0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE  0x03
#define SOCKS5_REP_HOST_UNREACHABLE     0x04
#define SOCKS5_REP_CONNECTION_REFUSED   0x05
#define SOCKS5_REP_TTL_EXPIRED          0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_NOT_SUPPORTED 0x08

/* ---- RFC 1929 user/password sub-negotiation ------------------------------
 * Distinct from SOCKS5_AUTH_*: same byte values overlap across the two
 * protocols by coincidence, so the names matter. */
#define SOCKS5_USERPASS_VERSION         0x01
#define SOCKS5_USERPASS_OK              0x00
#define SOCKS5_USERPASS_FAIL            0x01

typedef enum {
    SOCKS5_STATE_INIT,
    SOCKS5_STATE_AUTH,
    SOCKS5_STATE_AUTH_PASSWORD,
    SOCKS5_STATE_REQUEST,
    SOCKS5_STATE_OPENING,
    SOCKS5_STATE_CONNECTED,
    SOCKS5_STATE_ERROR
} Socks5ClientState;

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;

/* 两条到同一服务器的 SSH 会话：MAIN 走普通流量，BULK 走 @bulk 命中的
 * 大流量域名（视频/下载）。大流量把自己那条 TCP 连接灌满时，MAIN 上的
 * 新通道建立和小流量不再排在它后面。BULK 创建失败或断开时回退 MAIN，
 * 更新 tick 里按需重建。 */
enum { SSH_SLOT_MAIN = 0, SSH_SLOT_BULK = 1, SSH_SLOT_COUNT = 2 };
typedef struct {
    WOLFSSH* session;
    const char* name;
} SshSessionSlot;
static SshSessionSlot g_ssh_slots[SSH_SLOT_COUNT] = {
    { NULL, "main" },
    { NULL, "bulk" },
};
static SOCKET_T g_listen_sock = INVALID_SOCKET;

static WOLFSSH* socks5_main_session(void) {
    return g_ssh_slots[SSH_SLOT_MAIN].session;
}

/* 会话指针 -> 槽位；也用来校验一个 client 记下的会话指针是否仍然存活
 * （会话销毁重建后 client->ssh_session 可能悬空）。 */
static SshSessionSlot* socks5_slot_for_session(WOLFSSH* session) {
    if (!session) return NULL;
    for (int i = 0; i < SSH_SLOT_COUNT; i++) {
        if (g_ssh_slots[i].session == session) return &g_ssh_slots[i];
    }
    return NULL;
}

static SshSessionSlot* socks5_slot_for_socket(SOCKET_T fd) {
    if (fd == INVALID_SOCKET) return NULL;
    for (int i = 0; i < SSH_SLOT_COUNT; i++) {
        if (g_ssh_slots[i].session &&
            wolfSSH_session_get_socket(g_ssh_slots[i].session) == fd) {
            return &g_ssh_slots[i];
        }
    }
    return NULL;
}

static WOLFSSH* socks5_session_for_socket(SOCKET_T fd) {
    SshSessionSlot* slot = socks5_slot_for_socket(fd);
    return slot ? slot->session : NULL;
}

/* CONNECT 时按目标域名选会话：@bulk 命中且 BULK 存活走 BULK，否则 MAIN。 */
static WOLFSSH* socks5_pick_session(const char* host) {
    if (host && g_ssh_slots[SSH_SLOT_BULK].session &&
        xpac_is_bulk_domain(host)) {
        return g_ssh_slots[SSH_SLOT_BULK].session;
    }
    return socks5_main_session();
}

static void ssh_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void ssh_write_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void ssh_error_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static int ssh_channel_close_callback(WOLFSSH_CHANNEL* channel, void* ctx);
static int ssh_channel_open_fini_callback(WOLFSSH_CHANNEL* channel, void* ctx);
static int ssh_channel_open_fail_callback(WOLFSSH_CHANNEL* channel, void* ctx);
static void client_channel_eof_cb(xChannel* ch, const char* reason, void* ud);

static int socks5_arm_ssh_writable(SOCKET_T ssh_socket, xhash* hash_table,
                                   int force, const char* reason) {
    WOLFSSH* session = socks5_session_for_socket(ssh_socket);
    if (!session) return 0;

    if (!hash_table) {
        hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
    }
    if (!hash_table) return 0;

    if (!force && !wolfSSH_session_has_pending_output(session)) {
        return 0;
    }

    if (xpoll_add_event(ssh_socket, XPOLL_WRITABLE,
                        NULL, ssh_write_cb, NULL, hash_table) != 0) {
        XLOGE("Failed to arm SSH writable fd=%d reason=%s",
              (int)ssh_socket, reason ? reason : "pending_output");
        return -1;
    }

    /* xpoll_add_event() 在 mask 没变时是空操作（xpoll.c 里直接 return 0），
     * 但这条日志原来无条件打，而 socks5_server_update() 每轮循环都会调一次
     * arm ——刷屏的头号来源就是它。 */
    XLOG_CD(SOCKS5_LOG_CD_MS, XLOGD, "Armed SSH writable fd=%d reason=%s",
            (int)ssh_socket, reason ? reason : "pending_output");
    return 1;
}

static int socks5_active_connections(void) {
    int total = 0;
    for (int i = 0; i < SSH_SLOT_COUNT; i++) {
        if (!g_ssh_slots[i].session) continue;
        SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_slots[i].session);
        xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
        if (hash_table) total += (int)xhash_size(hash_table);
    }
    return total;
}

static bool socks5_userpass_configured(void) {
    const char* u = g_server_config.proxy_username;
    const char* p = g_server_config.proxy_password;
    return u && p && u[0] != '\0' && p[0] != '\0';
}

static bool socks5_equal_token(const char* a, size_t alen, const char* b) {
    if (!a || !b) return false;
    size_t blen = strlen(b);
    if (alen != blen) return false;
    return memcmp(a, b, alen) == 0;
}

typedef struct {
    SOCKET_T client_sock;
    Socks5ClientState state;
    uint8_t auth_method;
    char target_host[256];
    uint16_t target_port;
    WOLFSSH *ssh_session;
    WOLFSSH_CHANNEL *ssh_channel;
    char client_host[256];
    uint16_t client_port;

    // SSH write backlog and client I/O channel
    char *wbuf; // ssh write backlog
    size_t wlen;
    size_t wcap;
    xChannel *io_ch;
    bool io_recv_paused;  // true when io_ch reads are paused due to SSH wbuf backpressure (upload)
    bool io_send_paused;  // true when SSH-channel reads are paused due to io_ch send backpressure (download)
    bool client_read_eof; // true after the client half-closes its write side
    bool ssh_eof_sent;    // true after forwarding EOF to the SSH channel

    // reopen cd
    long64 last_retry_time;  // retry time
    int retry_error_count;
} Socks5Client;

static void socks5_client_cleanup(SOCKET_T fd, Socks5Client *client);

static void socks5_client_fail(Socks5Client* client, const char* reason) {
    if (!client) return;
    const char* why = reason ? reason : "client_error";
    client->state = SOCKS5_STATE_ERROR;
    XLOGE("Client marked error: fd=%d, reason=%s",
          (int)client->client_sock, why);

    if (client->io_ch) {
        xchannel_close(client->io_ch, why);
        return;
    }

    if (client->client_sock != INVALID_SOCKET) {
        socks5_client_cleanup(client->client_sock, client);
    }
}

static int socks5_client_close_after_send(Socks5Client* client, const char* reason) {
    if (!client) return SOCKS5_SEND_CLOSED;
    const char* why = reason ? reason : "close_after_send";

    if (!client->io_ch) {
        /* No xchannel attached: client is alive, take the immediate-fail path. */
        socks5_client_fail(client, why);
    } else {
        client->state = SOCKS5_STATE_ERROR;
        /* IMPORTANT: xchannel_close_after_flush can synchronously fire close_cb,
         * which routes through socks5_client_cleanup -> free(client). After this
         * call returns, `client` may be a dangling pointer — do NOT touch it. */
        xchannel_close_after_flush(client->io_ch, why);
    }
    return SOCKS5_SEND_CLOSED;
}

static WOLFSSH* socks5_create_shared_session(const Socks5ServerConfig* config) {
    if (!config) return NULL;

    WOLFSSH *ssh_session = wolfSSH_session_open(
        config->ssh_host,
        config->ssh_port,
        config->ssh_username,
        config->ssh_password);
    if (!ssh_session) {
        return NULL;
    }

    SOCKET_T ssh_socket = wolfSSH_session_get_socket(ssh_session);
    xhash *hash_table = xhash_create(512, XHASH_KEY_INT);
    if (!hash_table) {
        wolfSSH_session_close(ssh_session);
        return NULL;
    }

    if (xpoll_add_event(ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                        ssh_read_cb, ssh_write_cb, ssh_error_cb, hash_table) != 0) {
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        return NULL;
    }

    wolfSSH_channel_callback(ssh_session,
                             ssh_channel_close_callback,
                             ssh_channel_open_fini_callback,
                             ssh_channel_open_fail_callback,
                             hash_table);
    return ssh_session;
}

static void socks5_destroy_shared_session(WOLFSSH* session) {
    if (!session) return;
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(session);
    xhash *hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
    xpoll_del_event(ssh_socket, XPOLL_ALL);
    if (hash_table) {
        xhash_destroy(hash_table, false);
    }
    wolfSSH_session_close(session);
}

static void socks5_client_wbuf_reset(Socks5Client* client) {
    if (!client) return;
    free(client->wbuf);
    client->wbuf = NULL;
    client->wlen = 0;
    client->wcap = 0;
}

static int socks5_client_wbuf_append(Socks5Client* client, const char* data, size_t len) {
    if (!client || (!data && len > 0)) return -1;
    if (len == 0) return 0;
    if (client->wlen > SOCKS5_WRITE_BUFFER_MAX ||
        len > SOCKS5_WRITE_BUFFER_MAX - client->wlen) {
        return -1;
    }

    size_t need = client->wlen + len;
    if (need > client->wcap) {
        size_t ncap = client->wcap ? client->wcap : SOCKS5_WRITE_BUFFER_INITIAL;
        while (ncap < need) {
            if (ncap > SOCKS5_WRITE_BUFFER_MAX / 2) {
                ncap = SOCKS5_WRITE_BUFFER_MAX;
                break;
            }
            ncap *= 2;
        }
        if (ncap < need) return -1;
        char *nbuf = (char*)realloc(client->wbuf, ncap);
        if (!nbuf) return -1;
        client->wbuf = nbuf;
        client->wcap = ncap;
    }

    memcpy(client->wbuf + client->wlen, data, len);
    client->wlen += len;
    return 0;
}

static void socks5_client_wbuf_consume(Socks5Client* client, size_t len) {
    if (!client || len == 0) return;
    if (len >= client->wlen) {
        socks5_client_wbuf_reset(client);
        return;
    }
    memmove(client->wbuf, client->wbuf + len, client->wlen - len);
    client->wlen -= len;
}

static int socks5_client_send_raw(Socks5Client* client,
                                  const void* data, size_t len,
                                  const char* what) {
    if (!client || !client->io_ch || (!data && len > 0)) return -1;
    if (len == 0) return 0;

    SOCKET_T client_fd = client->client_sock;
    int rc = xchannel_send_raw(client->io_ch, (const char*)data, len);
    if (rc != 0) {
        XLOGE("Failed to send %s to client fd=%d, len=%zu, rc=%d",
              what ? what : "data", (int)client_fd, len, rc);
        return rc == -2 ? -1 : SOCKS5_SEND_CLOSED;
    }
    return 0;
}

/* Send a small terminal response over io_ch, then schedule a graceful close.
 * Always returns SOCKS5_SEND_CLOSED. Caller MUST NOT touch `client` after
 * this — close_cb may have fired synchronously and freed it. */
static int socks5_send_raw_and_close(Socks5Client* client,
                                     const void* data, size_t len,
                                     const char* what,
                                     const char* close_reason) {
    int sr = socks5_client_send_raw(client, data, len, what);
    if (sr == SOCKS5_SEND_CLOSED) return SOCKS5_SEND_CLOSED;
    if (sr != 0) {
        socks5_client_fail(client, "reply_send_error");
        return SOCKS5_SEND_CLOSED;
    }
    return socks5_client_close_after_send(client, close_reason);
}

/* Build a SOCKS5 reply packet into `out` (must hold at least 22 bytes).
 * Returns the byte length. */
static int build_socks5_reply(uint8_t* out, uint8_t rep) {
    int len = 0;
    out[len++] = SOCKS5_VERSION;
    out[len++] = rep;
    out[len++] = SOCKS5_RESERVED;

    if (rep == SOCKS5_REP_SUCCESS) {
        out[len++] = SOCKS5_ATYP_IPV4;

        struct in_addr ip_addr;
        if (inet_pton(AF_INET, g_server_config.ssh_host, &ip_addr) == 1) {
            memcpy(&out[len], &ip_addr, 4);
        } else {
            memset(&out[len], 0, 4);  // fall back to 0.0.0.0
        }
        len += 4;

        uint16_t ssh_port = htons(g_server_config.ssh_port);
        memcpy(&out[len], &ssh_port, 2);
        len += 2;
    } else {
        out[len++] = SOCKS5_ATYP_IPV4;
        memset(&out[len], 0, 6);      // BND.ADDR + BND.PORT zeroed
        len += 6;
    }
    return len;
}

static int socks5_send_reply(Socks5Client* client, uint8_t rep) {
    uint8_t response[22];
    int len = build_socks5_reply(response, rep);
    return socks5_client_send_raw(client, response, (size_t)len, "socks5_reply");
}

/* Send a SOCKS5 reply with rep code, then schedule a graceful close.
 * Returns SOCKS5_SEND_CLOSED in every case (success-with-graceful-close or
 * send failure that already escalated to socks5_client_fail). Callers should
 * propagate this as a terminal indicator and stop touching the client. */
static int socks5_reply_and_close(Socks5Client* client, uint8_t rep, const char* reason) {
    uint8_t response[22];
    int len = build_socks5_reply(response, rep);
    return socks5_send_raw_and_close(client, response, (size_t)len,
                                     "socks5_reply", reason);
}

#ifdef _MSC_VER
    #define UNUSED_FUNCTION
#else
    #define UNUSED_FUNCTION __attribute__((unused))
#endif
UNUSED_FUNCTION static int socks5_accout_auth(Socks5Client* client) {
    if (client->auth_method == SOCKS5_AUTH_NONE) {
        client->state = SOCKS5_STATE_REQUEST;
        return 0;
    }
    return -1;
}

// static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud);
// static void client_channel_close_cb(xChannel* ch, const char* reason, void* ud);
static int socks5_client_stage(Socks5Client* client) {
    if (!client || !client->ssh_session) return -1;

    SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
    xhash *hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
    if (!hash_table) {
        XLOGE("SSH hash table missing, cannot stage client fd=%d", (int)client->client_sock);
        return -1;
    }

    if (!xhash_set_int(hash_table, (long)client->client_sock, client)) {
        XLOGE("Failed to stage client fd=%d into SSH hash table", (int)client->client_sock);
        return -1;
    }

    XLOGI("Client fd=%d added to SSH socket hash table", (int)client->client_sock);
    if (xhash_size(hash_table) == 1) {
        if (xpoll_add_event(ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                            ssh_read_cb, NULL, ssh_error_cb, hash_table) != 0) {
            xhash_remove_int(hash_table, (long)client->client_sock, false);
            XLOGE("Failed to register SSH readable/error events for fd=%d", (int)ssh_socket);
            return -1;
        }
        XLOGD("SSH socket fd=%d added to XPOLL_ALL event", (int)ssh_socket);
    }

    return 0;
}

/* 把 client 从当前会话的哈希表迁到 target 会话（CONNECT 时按域名分流）。
 * 先加入新表再从旧表摘除，失败则原样留在旧会话上。 */
static int socks5_client_restage(Socks5Client* client, WOLFSSH* target) {
    if (!client || !target || client->ssh_session == target) return 0;

    WOLFSSH* old_session = client->ssh_session;
    client->ssh_session = target;
    if (socks5_client_stage(client) != 0) {
        client->ssh_session = old_session;
        return -1;
    }

    if (socks5_slot_for_session(old_session)) {
        SOCKET_T old_socket = wolfSSH_session_get_socket(old_session);
        xhash* old_hash = (xhash*)xpoll_get_client_data(old_socket);
        if (old_hash) {
            xhash_remove_int(old_hash, (long)client->client_sock, false);
            if (xhash_size(old_hash) <= 0) {
                xpoll_del_event(old_socket, XPOLL_READABLE);
            }
        }
    }
    return 0;
}

static int socks5_client_open_channel(Socks5Client* client) {
    client->ssh_channel = wolfSSH_channel_open(
        client->ssh_session,
        client->target_host, client->target_port,
        g_server_config.ssh_host, client->client_port);
    if (!client->ssh_channel) {
        if (!wolfSSH_check_fatal(wolfSSH_get_error(client->ssh_session))) {
            SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
            xhash* hash_table = xpoll_get_client_data(ssh_socket);
            socks5_arm_ssh_writable(ssh_socket, hash_table, 1,
                                    "channel_open_retry");
            client->last_retry_time = time_get_ms() + 200;
            return 0;
        }

        return socks5_reply_and_close(client, SOCKS5_REP_GENERAL_FAILURE,
                                      "channel_open_failed");
    }

    return 1;
}

static int socks5_consume_auth(Socks5Client* client, const uint8_t* buf,
                               size_t len, size_t* consumed) {
    if (!client || !buf || !consumed) return -1;
    *consumed = 0;
    if (len < 2) return 0;

    uint8_t nmethods = buf[1];
    size_t need = 2u + (size_t)nmethods;
    if (len < need) return 0;
    *consumed = need;

    if (buf[0] != SOCKS5_VERSION) {
        XLOGE("SOCKS5 version mismatch 0x%02X, fd=%d",
              buf[0], (int)client->client_sock);
        return -1;
    }

    uint8_t selected = SOCKS5_AUTH_NO_ACCEPTABLE;
    const bool need_userpass = socks5_userpass_configured();
    for (size_t i = 0; i < (size_t)nmethods; i++) {
        uint8_t method = buf[2 + i];
        if (need_userpass) {
            if (method == SOCKS5_AUTH_PASSWORD) {
                selected = SOCKS5_AUTH_PASSWORD;
                break;
            }
        } else {
            if (method == SOCKS5_AUTH_NONE) {
                selected = SOCKS5_AUTH_NONE;
                break;
            }
        }
    }

    if (selected == SOCKS5_AUTH_NO_ACCEPTABLE) {
        XLOGE("No acceptable auth method, fd=%d", (int)client->client_sock);
        uint8_t resp[2] = {SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE};
        return socks5_send_raw_and_close(client, resp, sizeof(resp),
                                         "auth_no_acceptable",
                                         "auth_no_acceptable");
    }

    {
        uint8_t resp[2] = {SOCKS5_VERSION, selected};
        int sr = socks5_client_send_raw(client, resp, sizeof(resp),
                                        "auth_response");
        if (sr != 0) return sr;
    }

    client->auth_method = selected;
    client->state = (selected == SOCKS5_AUTH_PASSWORD)
        ? SOCKS5_STATE_AUTH_PASSWORD
        : SOCKS5_STATE_REQUEST;
    return 1;
}

static int socks5_consume_userpass_auth(Socks5Client* client, const uint8_t* buf,
                                        size_t len, size_t* consumed) {
    if (!client || !buf || !consumed) return -1;
    *consumed = 0;
    if (len < 2) return 0;

    if (buf[0] != SOCKS5_USERPASS_VERSION) {
        XLOGE("Invalid RFC1929 auth version=0x%02X, fd=%d",
              buf[0], (int)client->client_sock);
        return -1;
    }

    size_t ulen = (size_t)buf[1];
    size_t pos = 2;
    if (len < pos + ulen + 1) return 0;

    const char* uname = (const char*)&buf[pos];
    pos += ulen;

    size_t plen = (size_t)buf[pos++];
    if (len < pos + plen) return 0;

    const char* passwd = (const char*)&buf[pos];
    pos += plen;
    *consumed = pos;

    bool ok = socks5_equal_token(uname, ulen, g_server_config.proxy_username) &&
              socks5_equal_token(passwd, plen, g_server_config.proxy_password);
    uint8_t resp[2] = {SOCKS5_USERPASS_VERSION,
                       ok ? SOCKS5_USERPASS_OK : SOCKS5_USERPASS_FAIL};
    int sr = socks5_client_send_raw(client, resp, sizeof(resp),
                                    "userpass_response");
    if (sr != 0) return sr;

    if (!ok) {
        XLOGE("SOCKS5 username/password auth failed, fd=%d", (int)client->client_sock);
        return socks5_client_close_after_send(client, "auth_userpass_failed");
    }

    client->state = SOCKS5_STATE_REQUEST;
    return 1;
}

static int socks5_consume_request(Socks5Client* client, const uint8_t* buf,
                                  size_t len, size_t* consumed) {
    if (!client || !buf || !consumed) return -1;
    *consumed = 0;
    if (len < 4) return 0;

    if (buf[0] != SOCKS5_VERSION) {
        XLOGE("SOCKS5 request version mismatch, fd=%d", (int)client->client_sock);
        return -1;
    }
    if (buf[1] != SOCKS5_CMD_CONNECT) {
        XLOGE("Unsupported cmd=0x%02X, fd=%d", buf[1], (int)client->client_sock);
        return socks5_reply_and_close(client, SOCKS5_REP_COMMAND_NOT_SUPPORTED,
                                      "cmd_not_supported");
    }

    uint8_t atyp = buf[3];
    size_t pos = 4;
    size_t addr_len = 0;

    switch (atyp) {
    case SOCKS5_ATYP_IPV4: addr_len = 4;    break;
    case SOCKS5_ATYP_IPV6: addr_len = 16;   break;
    case SOCKS5_ATYP_DOMAIN:
        if (len < pos + 1) return 0;
        addr_len = 1u + (size_t)buf[pos];
        break;
    default:
        XLOGE("Unsupported ATYP=0x%02X, fd=%d", atyp, (int)client->client_sock);
        return socks5_reply_and_close(client, SOCKS5_REP_ADDRESS_NOT_SUPPORTED,
                                      "address_not_supported");
    }

    if (addr_len > SIZE_MAX - pos - 2u) return -1;
    size_t need = pos + addr_len + 2u;
    if (len < need) return 0;
    *consumed = need;

    {
        char target_host[256];
        switch (atyp) {
        case SOCKS5_ATYP_IPV4: {
            struct in_addr addr;
            memcpy(&addr, &buf[pos], 4);
            inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
            pos += 4;
            break;
        }
        case SOCKS5_ATYP_IPV6: {
            struct in6_addr addr6;
            memcpy(&addr6, &buf[pos], 16);
            inet_ntop(AF_INET6, &addr6, target_host, sizeof(target_host));
            pos += 16;
            break;
        }
        case SOCKS5_ATYP_DOMAIN: {
            size_t domain_len = (size_t)buf[pos++];
            if (domain_len >= sizeof(target_host)) {
                XLOGE("Domain too long, fd=%d", (int)client->client_sock);
                return -1;
            }
            memcpy(target_host, &buf[pos], domain_len);
            target_host[domain_len] = '\0';
            pos += domain_len;
            break;
        }
        default:
            /* Unreachable: ATYP was validated by the switch above. */
            return -1;
        }

        uint16_t net_port = 0;
        uint16_t target_port = 0;
        memcpy(&net_port, &buf[pos], sizeof(net_port));
        target_port = ntohs(net_port);

        strncpy(client->target_host, target_host, sizeof(client->target_host) - 1);
        client->target_host[sizeof(client->target_host) - 1] = '\0';
        client->target_port = target_port;
    }

    /* 按目标域名分流：@bulk 命中走 BULK 会话，其余走 MAIN。accept 时挂在
     * MAIN 上，这里才知道目标域名，需要时把 client 迁到 BULK 的哈希表。 */
    {
        WOLFSSH* want = socks5_pick_session(client->target_host);
        if (want && want != client->ssh_session &&
            socks5_client_restage(client, want) != 0) {
            XLOGE("Failed to restage client fd=%d to bulk session, using main",
                  (int)client->client_sock);
        }
    }

    {
        SshSessionSlot* slot = socks5_slot_for_session(client->ssh_session);
        XLOGI("SOCKS5 CONNECT -> %s:%d, fd=%d via=%s",
              client->target_host, client->target_port,
              (int)client->client_sock, slot ? slot->name : "none");
    }

    if (!client->ssh_session) {
        XLOGE("No SSH session, fd=%d", (int)client->client_sock);
        return socks5_reply_and_close(client, SOCKS5_REP_GENERAL_FAILURE,
                                      "no_ssh_session");
    }

    client->state = SOCKS5_STATE_OPENING;
    return socks5_client_open_channel(client);
}

void socks5_client_free(Socks5Client* client) {
    if (client->io_ch) {
        xChannel *ch = client->io_ch;
        client->io_ch = NULL;
        xchannel_destroy(ch);
        client->client_sock = INVALID_SOCKET;
    }

    if (client->client_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(client->client_sock);
        client->client_sock = INVALID_SOCKET;
    }

    // Only close channel if it's not already EOF and session is valid
    // (slot lookup also filters dangling pointers to destroyed sessions)
    if (client->ssh_channel &&
        socks5_slot_for_session(client->ssh_session)) {
        WOLFSSH *ssh_session = client->ssh_session;
        SOCKET_T ssh_socket = wolfSSH_session_get_socket(ssh_session);
        wolfSSH_channel_close(client->ssh_channel);
        if (wolfSSH_session_has_pending_output(ssh_session)) {
            xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
            socks5_arm_ssh_writable(ssh_socket, hash_table, 0,
                                    "channel_close");
        }
    }

    client->ssh_channel = NULL;
    client->ssh_session = NULL;
    socks5_client_wbuf_reset(client);
    client->state = SOCKS5_STATE_ERROR;
}

static void socks5_client_cleanup(SOCKET_T fd, Socks5Client *client) {
    if (!client) return;
    SOCKET_T key_fd = (fd != INVALID_SOCKET) ? fd : client->client_sock;
    // unreg ev
    if (key_fd != INVALID_SOCKET) {
        xpoll_del_event(key_fd, XPOLL_ALL);
    }

    /* 从 client 所在会话的哈希表摘除；会话已销毁重建时 slot 查不到，
     * 哈希表也随会话销毁了，无需处理。 */
    if (socks5_slot_for_session(client->ssh_session) && key_fd != INVALID_SOCKET) {
        SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
        xhash* hash = xpoll_get_client_data(ssh_socket);

        if (hash) {
            xhash_remove_int(hash, (long)key_fd, false);

            if (xhash_size(hash) <= 0) {
                xpoll_del_event(ssh_socket, XPOLL_READABLE);
                XLOGE("SSH socket fd=%d remove XPOLL_ALL event", (int)ssh_socket);
            }
        }
    }

    socks5_client_free(client);
    free(client);

    XLOGI("Active connections: %d (connection closed)", socks5_active_connections());
}

static int ssh_process_session_events(SOCKET_T fd, void *clientData, const char *where) {
    enum { SSH_EVENT_DRAIN_LIMIT = 64 };

    WOLFSSH* session = socks5_session_for_socket(fd);
    if (!session) return -1;

    for (int i = 0; i < SSH_EVENT_DRAIN_LIMIT; i++) {
        word32 channelId = 0;
        int ret = wolfSSH_process_events(session, &channelId);
        if (ret < 0) {
            int error = wolfSSH_get_error(session);
            if (wolfSSH_check_fatal(error)) {
                XLOGE("wolfSSH_process_events fatal on %s: %d:%s",
                      where, error, wolfSSH_ErrorToName(error));
                ssh_error_cb(fd, XPOLL_ERROR, clientData, NULL);
                return -1;
            }

            if (error != WS_CHANOPEN_FAILED && error != WS_INVALID_CHANID) {
                XLOGE("wolfSSH_process_events %s error: %d:%s",
                      where, error, wolfSSH_ErrorToName(error));
            }
        }

        /* 半个包留在 inputBuffer 里时 length > idx 同样成立，所以
         * has_buffered_input() 单独用不能判定"还有整包要处理"。这个判据是
         * 阻塞时代写的 —— 那时缓冲区非空就意味着有整包；socket 改成非阻塞之后
         * GetInputData() 会在整包到齐前带着 WS_WANT_READ 返回，DoReceive 推不动
         * 半包，于是每个不完整的包都把 SSH_EVENT_DRAIN_LIMIT 圈白转完（每圈一次
         * recv），最后再打一条 WARN。加上 WS_WANT_READ 判断后，撞上半包只多花
         * 一圈就退出，剩下的字节等下次可读事件。 */
        if (!wolfSSH_session_has_buffered_input(session) ||
            wolfSSH_get_error_code(session) == WS_WANT_READ) {
            return 0;
        }
    }

    XLOG_CD(SOCKS5_LOG_CD_MS, XLOGW,
            "wolfSSH_process_events %s drain limit reached", where);
    return 0;
}

static void socks5_client_remote_eof(Socks5Client* client, const char* reason) {
    if (!client) return;
    XLOGW("SSH channel EOF/close: fd=%d host=%s reason=%s",
          (int)client->client_sock, client->target_host,
          reason ? reason : "ssh_channel_eof");

    if (client->io_ch && !xchannel_is_closed(client->io_ch)) {
        socks5_client_close_after_send(client,
                                       reason ? reason : "ssh_channel_eof");
    } else if (client->client_sock != INVALID_SOCKET) {
        socks5_client_cleanup(client->client_sock, client);
    }
}

/* Drain one client's SSH channel into its io_ch, applying download-direction
 * backpressure: if the client send buffer is backed up we stop reading and
 * leave data in the SSH channel buffer, which makes wolfSSH withhold window
 * updates and throttles the remote. This is the read-side mirror of
 * socks5_update_backpressure() (the upload side). Resumed from
 * socks5_resume_io_send() once the send buffer drains below the low water. */
static void socks5_pump_client_read(Socks5Client *client) {
    if (!client || client->state != SOCKS5_STATE_CONNECTED || !client->ssh_channel)
        return;

    if (client->wlen > SOCKS5_WRITE_BUFFER_MAX) {
        XLOGE("Warning: Invalid wlen=%zu for fd=%d",
                   client->wlen, (int)client->client_sock);
        socks5_client_wbuf_reset(client);
        socks5_client_fail(client, "invalid_write_buffer");
        return;
    }

    if (!client->io_ch) {
        XLOGE("Client channel missing for fd=%d", (int)client->client_sock);
        socks5_client_fail(client, "missing_client_channel");
        return;
    }

    /* Do NOT act on wolfSSH_channel_eof() here. It only reports eofRxd -- the
     * peer sent CHANNEL_EOF -- and says nothing about data still sitting in
     * channel->inputBuffer. ssh_process_session_events() drains up to
     * SSH_EVENT_DRAIN_LIMIT packets before we ever get here, so a response and
     * the close that follows it routinely land in the same pass; tearing the
     * client down on the flag would discard the whole response body. Drain the
     * channel first -- the EOF check after the loop then closes with the data
     * already queued on io_ch. */

    char ssh_rbuf[8192];
    for (;;) {
        /* Backpressure: check the client send buffer BEFORE reading so we
         * never pull bytes off the channel that we couldn't queue. Pausing
         * here leaves the data in the SSH channel buffer -> window throttle. */
        size_t send_buf = 0;
        xchannel_get_stats(client->io_ch, &send_buf, NULL, NULL, NULL);
        if (send_buf >= SOCKS5_IO_SEND_HIGH_WATER) {
            if (!client->io_send_paused) {
                XLOGD("io_ch send high water: pausing SSH reads fd=%d send_buf=%zu",
                      (int)client->client_sock, send_buf);
            }
            client->io_send_paused = true;
            return;
        }

        int n = wolfSSH_channel_read(client->ssh_channel, ssh_rbuf, sizeof(ssh_rbuf));
        if (n > 0) {
            SOCKET_T client_fd = client->client_sock;
            int rc = xchannel_send_raw(client->io_ch, ssh_rbuf, (size_t)n);
            if (rc != 0) {
                XLOGE("Channel send failed %d bytes to client fd=%d, rc=%d",
                      n, (int)client_fd, rc);
                if (rc == -2) {
                    socks5_client_fail(client, "client_send_backpressure");
                }
                return;
            }
            continue;
        }

        if (n < 0) {
            if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
                socks5_client_remote_eof(client, "ssh_channel_eof");
            } else {
                XLOGE("Channel read failed for fd=%d, n=%d", (int)client->client_sock, n);
                socks5_client_fail(client, "ssh_channel_read_error");
            }
            return;
        }

        break;
    }

    /* Channel drained. This is now the normal remote-close path, and
     * socks5_client_remote_eof() already logs it with host and reason.
     * has_buffered_input() guards the case where the loop above broke on a
     * 0-read that meant "not readable right now" (rekey) rather than "empty":
     * closing then would drop the bytes still sitting on the channel. The next
     * readable event pumps us again once the rekey completes. */
    if (client->ssh_channel && wolfSSH_channel_eof(client->ssh_channel)!=0 &&
        !wolfSSH_channel_has_buffered_input(client->ssh_channel)) {
        socks5_client_remote_eof(client, "ssh_channel_closed");
        return;
    }
}

static bool ssh_read_each_client(xhashKey k, void* value, void* ud) {
    (void)k;
    (void)ud;
    socks5_pump_client_read((Socks5Client*)value);
    return true;  // Continue to next client
}

/* need_write 的来源。以前是个 0/1 标志，现在按位记谁置的 —— 这样才能区分
 * "在等 socket 可写"和"在等对端的控制包"，前者该挂 EPOLLOUT，后者挂了就是空转。
 * 见下面的 SSH_WNEED_POLLOUT。 */
enum {
    SSH_WNEED_WINDOW_FULL  = 1 << 0,  /* channel 窗口满，等对端 WINDOW_ADJUST */
    SSH_WNEED_CHANNEL_BUSY = 1 << 1,  /* channel_write 返回 0，但不是窗口满 */
    SSH_WNEED_BACKLOG      = 1 << 2,  /* 预算用尽，wbuf 还有剩 */
    SSH_WNEED_OPENING      = 1 << 3,  /* 通道还没开好 */
    SSH_WNEED_EOF          = 1 << 4,  /* 等着把 CHANNEL_EOF 发出去 */
    SSH_WNEED_SOCKET       = 1 << 5,  /* socket 发送缓冲满 */
};

/* outputBuffer 空着还该留 EPOLLOUT 的唯一理由：预算用尽，而通道还写得动、
 * socket 也吃得下 —— 下一次可写事件能真推进。
 *
 * 其余几位刻意不在这里：
 *   SOCKET / CHANNEL_BUSY / EOF 的可达来源是 WS_WANT_WRITE，那时 outputBuffer
 *     必然非空（wolfSSH_SendPacket 是在 while (length > idx) 循环体内部 return
 *     的），摘除处的 has_pending_output 已经把 EPOLLOUT 留住了，再列一遍是冗余。
 *     CHANNEL_BUSY 还能是 WS_REKEYING —— 那时 outputBuffer 可能是空的，而重协商
 *     靠读方向完成，留着 EPOLLOUT 就是空转；wolfSSH 每约 1GB rekey 一次，大流量
 *     下会反复踩。
 *   WINDOW_FULL / OPENING 等的是对端的 WINDOW_ADJUST / CHANNEL_OPEN_CONFIRM，
 *     从读方向到达，socket 早就可写。上行重排由 ssh_read_cb 末尾的写泵负责，
 *     OPENING 的重试由 100ms 的 socks5_server_update 负责。
 *
 * 这几位仍然记账，只是不参与决策 —— 诊断日志要靠它们说清在等谁。 */
#define SSH_WNEED_POLLOUT SSH_WNEED_BACKLOG

/* 位掩码转可读串，只给诊断日志用。 */
static const char* ssh_wneed_names(int mask, char* buf, size_t cap) {
    static const struct { int bit; const char* name; } kNames[] = {
        { SSH_WNEED_WINDOW_FULL,  "window_full"  },
        { SSH_WNEED_CHANNEL_BUSY, "channel_busy" },
        { SSH_WNEED_BACKLOG,      "backlog"      },
        { SSH_WNEED_OPENING,      "opening"      },
        { SSH_WNEED_EOF,          "eof"          },
        { SSH_WNEED_SOCKET,       "socket"       },
    };
    size_t off = 0;

    if (!buf || cap == 0) return "";
    buf[0] = '\0';
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        if (!(mask & kNames[i].bit)) continue;
        int n = snprintf(buf + off, cap - off, "%s%s",
                         off ? "|" : "", kNames[i].name);
        if (n < 0 || (size_t)n >= cap - off) break;
        off += (size_t)n;
    }
    if (off == 0) snprintf(buf, cap, "none");
    return buf;
}

/* xhash_foreach() 的回调只能带一个 void*（xhash.h 的 xhashForeachCb），而每轮
 * 迭代要带两个值出来，所以才有这个结构体 —— 不是设计上想要，是容器逼的。
 * 它同时也是 socks5_drain_ssh_wbuf() / socks5_maybe_send_ssh_eof() 的出参载体，
 * 那两个函数在 foreach 之外还有三个直接调用点。 */
typedef struct {
    int    need_write;     /* SSH_WNEED_* 位掩码，0 表示不需要再等可写 */
    size_t bytes_written;  /* 本轮写出去的字节；>0 即等价于"有推进" */
} SshWritePumpCtx;

/* ssh_read_cb 末尾要跑一趟写泵，实现在下面。 */
static bool ssh_write_each_client(xhashKey k, void* value, void* ctx);

static void ssh_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table) {
        XLOGE("ERROR: ssh_read_cb called with NULL hash table!");
        return;
    }

    if (ssh_process_session_events(fd, clientData, "read") != 0)
        return;

    xhash_foreach(hash_table, ssh_read_each_client, NULL);

    /* 上行被通道窗口卡住的 client 只能在这里重排：窗口重开是靠对端的
     * WINDOW_ADJUST，它从读方向进来，不产生任何可写事件。少了这一步，
     * wbuf 到高水位后 io_recv 被暂停、客户端也不再送数据，上传就彻底锁死。 */
    SshWritePumpCtx pump = { 0, 0 };
    xhash_foreach(hash_table, ssh_write_each_client, &pump);

    /* Channel reads can queue SSH control packets such as WINDOW_ADJUST.
     * Arm writable now so pending SSH output drains on the next poll. */
    socks5_arm_ssh_writable(fd, hash_table,
                            (pump.need_write & SSH_WNEED_POLLOUT),
                            "ssh_read_pending_output");
}


static int socks5_update_backpressure(Socks5Client* client) {
    if (!client || !client->io_ch || xchannel_is_closed(client->io_ch)) {
        return 0;
    }
    if (client->client_read_eof || xchannel_is_read_closed(client->io_ch)) {
        client->io_recv_paused = false;
        return 0;
    }

    if (!client->io_recv_paused && client->wlen >= SOCKS5_WBUF_HIGH_WATER) {
        XLOGD("SSH wbuf high water: pausing io_ch reads fd=%d wlen=%zu",
              (int)client->client_sock, client->wlen);
        client->io_recv_paused = true;
        xchannel_pause_read(client->io_ch);
        return 0;
    }

    if (client->io_recv_paused && client->wlen <= SOCKS5_WBUF_LOW_WATER) {
        XLOGD("SSH wbuf low water: resuming io_ch reads fd=%d wlen=%zu",
              (int)client->client_sock, client->wlen);
        client->io_recv_paused = false;
        if (xchannel_resume_read(client->io_ch) != 0) {
            socks5_client_fail(client, "resume_read_error");
            return -1;
        }
    }

    return 0;
}

static int socks5_maybe_send_ssh_eof(Socks5Client* client,
                                     SshWritePumpCtx* ctx) {
    if (!client || !client->client_read_eof || client->ssh_eof_sent) {
        return 0;
    }
    if (!client->ssh_channel || !client->ssh_session ||
        client->state == SOCKS5_STATE_OPENING) {
        if (ctx) ctx->need_write |= SSH_WNEED_OPENING;
        return 0;
    }
    if (client->wlen > 0 || wolfSSH_session_has_pending_output(client->ssh_session)) {
        if (ctx) ctx->need_write |= SSH_WNEED_EOF;
        return 0;
    }

    int rc = wolfSSH_channel_send_eof(client->ssh_channel);
    if (rc > 0) {
        client->ssh_eof_sent = true;
        XLOGD("Forwarded client EOF to SSH channel fd=%d host=%s",
              (int)client->client_sock, client->target_host);
        if (ctx && wolfSSH_session_has_pending_output(client->ssh_session)) {
            ctx->need_write |= SSH_WNEED_SOCKET;
        }
        return 0;
    }
    if (rc == 0) {
        if (ctx) ctx->need_write |= SSH_WNEED_EOF;
        return 0;
    }

    socks5_client_fail(client, "ssh_channel_eof_send_error");
    return -1;
}

static int socks5_drain_ssh_wbuf(Socks5Client* client,
                                 SshWritePumpCtx* ctx) {
    if (!client || client->state != SOCKS5_STATE_CONNECTED ||
        !client->ssh_channel) {
        return 0;
    }

    /* No eof gate here: eofRxd means the peer will send us nothing more, not
     * that it stopped reading. A half-closed channel still accepts our upload,
     * and bailing out dropped whatever the client had queued in wbuf. When the
     * channel is really gone, ssh_channel_close_callback() has already NULLed
     * client->ssh_channel and the guard above catches it. */

    size_t bytes_this_client = 0;
    int iterations = 0;
    int stalled = 0;   /* 循环是被 channel_write 顶回来的，不是预算用尽 */
    while (client->wlen > 0 &&
           bytes_this_client < SOCKS5_WRITE_PUMP_BYTE_BUDGET &&
           iterations < SOCKS5_WRITE_PUMP_ITER_BUDGET) {
        size_t remaining = client->wlen;
        int chunk = (remaining > (size_t)INT_MAX) ? INT_MAX : (int)remaining;
        int written = wolfSSH_channel_write(client->ssh_channel,
                                            client->wbuf,
                                            chunk);
        if (written < 0) {
            XLOGE("Channel write failed, fd=%d, host=%s, err=%d",
                  (int)client->client_sock, client->target_host, written);
            socks5_client_fail(client, "ssh_channel_write_error");
            return -1;
        }
        if (written == 0) {
            /* wolfSSH_channel_write() 把 WS_WINDOW_FULL 和 WS_WANT_WRITE 都折叠成
             * 返回 0（见 ssh_tunnel.c 的 is_temporary_state 分支）。窗口满等的是
             * 对端 WINDOW_ADJUST，跟 socket 可写无关；这里先把两者分开记账，
             * 确认问题真的发生了再动 EPOLLOUT 的行为。 */
            stalled = 1;
            if (ctx) {
                ctx->need_write |=
                    (wolfSSH_get_error_code(client->ssh_session) == WS_WINDOW_FULL)
                        ? SSH_WNEED_WINDOW_FULL : SSH_WNEED_CHANNEL_BUSY;
            }
            break;
        }

        socks5_client_wbuf_consume(client, (size_t)written);
        bytes_this_client += (size_t)written;
        iterations++;
        client->retry_error_count = 0;
        if (ctx) ctx->bytes_written += (size_t)written;
    }

    if (bytes_this_client > 0) {
        XLOG_CD(SOCKS5_LOG_CD_MS, XLOGD,
                "Drained SSH wbuf: fd=%d wrote=%zu remaining=%zu",
                (int)client->client_sock, bytes_this_client, client->wlen);
    }

    /* 只有"预算用尽但通道还写得动"才算 backlog —— 那是我们主动让出 CPU，下一轮
     * 确实能继续写。被窗口顶回来时 wlen 同样 > 0，但那不是 backlog，上面已经按
     * WINDOW_FULL 记过账了，再叠一个 BACKLOG 会把 EPOLLOUT 又勾回来。 */
    if (client->wlen > 0 && !stalled && ctx) {
        ctx->need_write |= SSH_WNEED_BACKLOG;
    }

    if (socks5_update_backpressure(client) != 0) {
        return -1;
    }
    return socks5_maybe_send_ssh_eof(client, ctx);
}

static bool ssh_write_each_client(xhashKey k, void* value, void * ctx) {
    (void)k;
    SshWritePumpCtx* pump = (SshWritePumpCtx*)ctx;
    // Get client from hash node
    Socks5Client *client = (Socks5Client*)value;
    if (!client) return true;

    if (client->state == SOCKS5_STATE_OPENING) {
        if (pump) pump->need_write |= SSH_WNEED_OPENING;
        return true;  // Continue to next client
    }

    if (client->state != SOCKS5_STATE_CONNECTED || !client->ssh_channel) {
        return true;
    }

    (void)socks5_drain_ssh_wbuf(client, pump);

    return true;  // Continue to next client
}

static void ssh_write_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    xhash *hash_table = (xhash*)clientData;
    WOLFSSH* session = socks5_session_for_socket(fd);
    if (!hash_table || !session)
        return;

    static int _call_count = 0;
    _call_count++;

    if (_call_count % 10000 == 0) {
        XLOGD("ssh_write_cb called (count=%d, mask=%d)", _call_count, mask);
    }

    if (ssh_process_session_events(fd, clientData, "write") != 0)
        return;

    size_t total_bytes_written = 0;
    int last_need_write = 0;
    for (int round = 0; round < 8; round++) {
        SshWritePumpCtx pump = { 0, 0 };
        xhash_foreach(hash_table, ssh_write_each_client, &pump);

        if (wolfSSH_session_has_pending_output(session)) {
            /* 这里以前只调 process_events，指望它把 outputBuffer 冲出去，但
             * wolfSSH_worker() 在 DoReceive 返回 WS_FATAL_ERROR 时会跳过 flush，
             * 而 socket 无数据可读时 GetInputData() 正是返回 WS_FATAL_ERROR
             * （error=WS_WANT_READ）—— 纯 POLLOUT 唤醒必然命中这条路。结果待发
             * 字节没人发，has_pending_output 恒真，下面的 xpoll_del_event 永远
             * 执行不到，水平触发的 POLLOUT 让主循环空转（实测 46500 次/秒，
             * 期间 can_open_channel 也一直为假，新连接被推迟）。 */
            int flushed = wolfSSH_session_flush_output(session);
            if (flushed < 0) {
                ssh_error_cb(fd, XPOLL_ERROR, clientData, NULL);
                return;  /* session 已被销毁重建，不能再碰 */
            }
            if (flushed == 0)
                pump.need_write |= SSH_WNEED_SOCKET;

            /* 冲完再收一次：可能带回 WINDOW_ADJUST，让下一轮还能继续写。 */
            if (ssh_process_session_events(fd, clientData, "write-pump") != 0)
                return;
        }

        last_need_write = pump.need_write;
        total_bytes_written += pump.bytes_written;

        if (!pump.bytes_written || !pump.need_write) {
            break;
        }
    }

    if (total_bytes_written > 0) {
        char reasons[96];
        XLOG_CD(SOCKS5_LOG_CD_MS, XLOGD,
                "SSH write pump fd=%d wrote=%zu need_write=%s",
                (int)fd, total_bytes_written,
                ssh_wneed_names(last_need_write, reasons, sizeof(reasons)));
    }

    if (!wolfSSH_session_has_pending_output(session)) {
        char reasons[96];

        if ((last_need_write & SSH_WNEED_POLLOUT) == 0) {
            xpoll_del_event(fd, XPOLL_WRITABLE);

            if (last_need_write != 0) {
                /* 正常路径：摘掉了，但确实还有没做完的事（等窗口 / 等开通道）。
                 * 重排交给 ssh_read_cb 末尾的写泵 —— 对端的 WINDOW_ADJUST /
                 * CHANNEL_OPEN_CONFIRM 从读方向到达。留一条节流日志：日后又见
                 * 上传卡死，先来查是不是摘早了。 */
                XLOG_CD(SOCKS5_LOG_CD_MS, XLOGD,
                        "EPOLLOUT dropped, waiting on peer fd=%d need_write=%s",
                        (int)fd, ssh_wneed_names(last_need_write,
                                                 reasons, sizeof(reasons)));
            }
        } else if (total_bytes_written == 0) {
            /* 回归哨兵，盯的是空转的定义本身：outputBuffer 已空、这一次回调一个
             * 字节都没写出去，却还把 EPOLLOUT 留着 —— 下一轮 poll 必然立刻再触发
             * 一次同样什么都干不了的回调，就是当初 46500 次/秒的形状。
             *
             * 正常走不到：能留住 EPOLLOUT 的只有 BACKLOG，而它按定义是"刚写成功
             * 过、只是预算用尽"，必然伴随 bytes_written > 0。所以这条不依赖具体
             * 是哪一位，日后往 SSH_WNEED_POLLOUT 里加位加错了也照样报。
             *
             * 出现了就照着 need_write= 的取值查：那一位等的到底是不是 socket 可写。 */
            XLOG_CD(SOCKS5_LOG_CD_MS, XLOGW,
                    "EPOLLOUT held with empty outputBuffer fd=%d need_write=%s",
                    (int)fd, ssh_wneed_names(last_need_write,
                                             reasons, sizeof(reasons)));
        }
    }
}

static bool client_on_closed(xhashKey k, void* value, void *ctx) {
    (void)k;
    (void)ctx;
    Socks5Client *client = (Socks5Client*)value;
    if (!client) return true;
    if (client->io_ch) {
        xchannel_close(client->io_ch, "ssh_session_closed");
    } else {
        socks5_client_cleanup(client->client_sock, client);
    }
    return true;
}

static bool client_channel_confirm(xhashKey k, void* value, void* channel_ptr) {
    Socks5Client *client = (Socks5Client*)value;
    WOLFSSH_CHANNEL* channel = (WOLFSSH_CHANNEL*)channel_ptr;
    if (client->ssh_channel == channel) {
        if (!client->io_ch) {
            XLOGE("Client xchannel missing for fd=%d", (int)client->client_sock);
            socks5_client_fail(client, "missing_client_channel");
            return false;
        }

        client->state = SOCKS5_STATE_CONNECTED;
        int sr = socks5_send_reply(client, SOCKS5_REP_SUCCESS);
        if (sr != 0) {
            if (sr != SOCKS5_SEND_CLOSED) {
                socks5_client_fail(client, "reply_send_error");
            }
            return false;
        }
        if ((client->wlen > 0 || client->client_read_eof) && client->ssh_session) {
            SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
            xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
            SshWritePumpCtx pump = { 0, 0 };
            if (client->wlen == 0 && client->client_read_eof) {
                if (socks5_maybe_send_ssh_eof(client, &pump) != 0) {
                    return false;
                }
            }
            socks5_arm_ssh_writable(ssh_socket, hash_table, 1,
                                    "channel_confirm_pending_client_data");
        }
        XLOGE("SSH channel confirm connect, fd=%d, host=%s, trycount=%d"
                , (int)client->client_sock, client->target_host, client->retry_error_count);
        client->retry_error_count = 0;
        return false;
    }
    return true;
}

static bool client_channel_refuse(xhashKey k, void* value, void* channel_ptr) {
    Socks5Client *client = (Socks5Client*)value;
    WOLFSSH_CHANNEL* channel = (WOLFSSH_CHANNEL*)channel_ptr;
    if(client->ssh_channel != channel) return true;

    XLOGE("SSH channel refuse connect, fd=%d, host=%s, trycount=%d, error=%d"
            , (int)client->client_sock, client->target_host
            , client->retry_error_count, wolfSSH_get_error_code(client->ssh_session));

    client->ssh_channel = NULL;
    if( client->retry_error_count >= MAX_REOPEN_COUNT
        || !wolfSSH_is_temporary_state(client->ssh_session)
        || WS_CHANOPEN_FAILED==wolfSSH_get_error_code(client->ssh_session) ) {
        XLOGE("SSH channel refuse connect, fd=%d, host=%s, errno=%d"
                , (int)client->client_sock, client->target_host, wolfSSH_get_error_code(client->ssh_session));
        socks5_reply_and_close(client, SOCKS5_REP_CONNECTION_REFUSED, "ssh_channel_refused");
    } else {
         client->last_retry_time = time_get_ms() + 500;
    }
    return false;
}

static bool client_channel_closed(xhashKey k, void* value, void* channel_ptr) {
    Socks5Client *client = (Socks5Client*)value;
    WOLFSSH_CHANNEL* channel = (WOLFSSH_CHANNEL*)channel_ptr;
    if (client->ssh_channel == channel) {
        client->ssh_channel = NULL;
        socks5_client_remote_eof(client, "ssh_channel_closed");
        return false;
    }
    return true;
}

static int ssh_channel_close_callback(WOLFSSH_CHANNEL* channel, void* ctx) {
    xhash* hash = (xhash*)ctx;
    if (hash)
        xhash_foreach(hash, client_channel_closed, channel);

    return WS_SUCCESS;
}

static int ssh_channel_open_fini_callback(WOLFSSH_CHANNEL* channel, void* ctx) {
    XLOGI("ssh channel opened:%p", channel);
    xhash* hash = (xhash*)ctx;
    /* ctx（每会话的 client 哈希）还没注册：这是 wolfSSH_connect 握手期间
     * 内部打开的 session 通道（回调挂在共享 CTX 上，任何在建会话都会触发）。
     * 千万不能 ChannelExit——那会杀掉握手用的通道，导致连接失败。 */
    if (!hash) return WS_SUCCESS;

    BOOL miss = xhash_foreach(hash, client_channel_confirm, channel);
    if (miss) {
        XLOGE("ssh_channel_open_fini_callback: no matching client for channel %p", channel);
        wolfSSH_ChannelExit(channel);
    }
    return WS_SUCCESS;
}

static int ssh_channel_open_fail_callback(WOLFSSH_CHANNEL* channel, void* ctx) {
    xhash* hash = (xhash*)ctx;
    if (hash)
        xhash_foreach(hash, client_channel_refuse, channel);
    return WS_SUCCESS;
}

static void ssh_error_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table)
        return;
    if(xpoll_get_client_data(fd)!=clientData) {
        XLOGE("ssh_error_cb: clientData mismatch for fd=%d", (int)fd);
        return;
    }

    SshSessionSlot* slot = socks5_slot_for_socket(fd);
    if (!slot) {
        XLOGE("ssh_error_cb: no session slot for fd=%d", (int)fd);
        return;
    }

    XLOGE("ssh_error_cb called (fd=%d, slot=%s)", (int)fd, slot->name);

    xhash_foreach(hash_table, client_on_closed, NULL);
    socks5_destroy_shared_session(slot->session);
    slot->session = NULL;

    slot->session = socks5_create_shared_session(&g_server_config);
    if (!slot->session) {
        XLOGE("ReCreating failed to create shared SSH session (%s)", slot->name);
        return;
    }
    XLOGW("ReCreating shared SSH session created successfully (%s)", slot->name);
}

static int socks5_forward_client_data_to_ssh(Socks5Client* client,
                                             const char* data, size_t len) {
    if (!client || !data || len == 0) return 0;

    SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
    xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);

    if (client->ssh_eof_sent) {
        XLOGE("ERROR: data received after SSH EOF was sent, host=%s",
              client->target_host);
        return -1;
    }

    if (socks5_client_wbuf_append(client, data, len) != 0) {
        XLOGE("ERROR: Write buffer full. buffered=%zu, needed=%zu, %s",
              client->wlen, len, client->target_host);
        return -1;
    }

    SshWritePumpCtx pump = { 0, 0 };
    if (socks5_drain_ssh_wbuf(client, &pump) != 0) {
        return -1;
    }

    socks5_arm_ssh_writable(ssh_socket, hash_table,
                            (pump.need_write & SSH_WNEED_POLLOUT),
                            "client_data_to_ssh");

    return 0;
}

typedef enum {
    PKT_ADVANCE,    /* consumed some bytes, loop and re-dispatch */
    PKT_NEED_MORE,  /* not enough data this turn; caller returns off */
    PKT_DONE,       /* whole packet handled (or implicitly drained); caller returns len */
    PKT_ABORT,      /* client already failed/closed; caller returns len */
} packet_step_t;

/* Single-state consumer for client_channel_packet_cb. Reads from data + *off
 * and advances *off on progress. The outer loop re-dispatches on PKT_ADVANCE
 * because consume_* may have moved client->state forward. */
static packet_step_t packet_step(Socks5Client* client,
                                 const char* data, size_t len, size_t* off) {
    size_t used = 0;
    int rc;

    switch (client->state) {
    case SOCKS5_STATE_AUTH:
        rc = socks5_consume_auth(client,
                                 (const uint8_t*)data + *off, len - *off, &used);
        if (rc < 0) {
            if (rc != SOCKS5_SEND_CLOSED) socks5_client_fail(client, "auth_error");
            return PKT_ABORT;
        }
        if (rc == 0) return PKT_NEED_MORE;
        *off += used;
        return PKT_ADVANCE;

    case SOCKS5_STATE_AUTH_PASSWORD:
        rc = socks5_consume_userpass_auth(client,
                                          (const uint8_t*)data + *off, len - *off, &used);
        if (rc < 0) {
            if (rc != SOCKS5_SEND_CLOSED) socks5_client_fail(client, "auth_userpass_error");
            return PKT_ABORT;
        }
        if (used > 0) *off += used;
        return (rc == 0 && used == 0) ? PKT_NEED_MORE : PKT_ADVANCE;

    case SOCKS5_STATE_REQUEST:
        rc = socks5_consume_request(client,
                                    (const uint8_t*)data + *off, len - *off, &used);
        if (rc < 0) {
            if (rc != SOCKS5_SEND_CLOSED) socks5_client_fail(client, "request_error");
            return PKT_ABORT;
        }
        if (used > 0) *off += used;
        return (rc == 0 && used == 0) ? PKT_NEED_MORE : PKT_ADVANCE;

    case SOCKS5_STATE_OPENING: {
        size_t remaining = len - *off;
        if (remaining > 0 &&
            socks5_client_wbuf_append(client, data + *off, remaining) != 0) {
            XLOGE("ERROR: Pending buffer full while opening. needed=%zu, host=%s",
                  remaining, client->target_host);
            socks5_client_fail(client, "buffer_full");
            return PKT_ABORT;
        }
        *off = len;
        return PKT_DONE;
    }

    case SOCKS5_STATE_CONNECTED:
        if (!client->ssh_channel || !client->ssh_session) {
            socks5_client_fail(client, "missing_ssh_channel");
            return PKT_ABORT;
        }
        if (socks5_forward_client_data_to_ssh(client, data + *off, len - *off) != 0) {
            socks5_client_fail(client, "ssh_write_error");
        }
        return PKT_DONE;

    default:
        /* Unknown / unexpected state — bail with whatever we already consumed
         * (NEED_MORE in the outer loop returns off, matching the old default
         * fall-through `break`). */
        return PKT_NEED_MORE;
    }
}

static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud) {
    (void)ch;
    Socks5Client *client = (Socks5Client*)ud;
    if (!client || len == 0) return 0;
    if (client->state == SOCKS5_STATE_ERROR) return len;

    size_t off = 0;
    while (off < len) {
        switch (packet_step(client, data, len, &off)) {
        case PKT_ADVANCE:   continue;
        case PKT_NEED_MORE: return off;
        case PKT_DONE:
        case PKT_ABORT:     return len;
        }
    }
    return off;
}

static void client_channel_eof_cb(xChannel* ch, const char* reason, void* ud) {
    (void)ch;
    Socks5Client *client = (Socks5Client*)ud;
    if (!client) return;

    XLOGW("client channel EOF: fd=%d reason=%s",
          (int)client->client_sock, reason ? reason : "unknown");
    client->client_read_eof = true;
    client->io_recv_paused = false;

    if (client->state == SOCKS5_STATE_AUTH ||
        client->state == SOCKS5_STATE_AUTH_PASSWORD ||
        client->state == SOCKS5_STATE_REQUEST ||
        client->state == SOCKS5_STATE_INIT) {
        socks5_client_fail(client, "client_eof_before_request");
        return;
    }

    SOCKET_T ssh_socket = client->ssh_session
                              ? wolfSSH_session_get_socket(client->ssh_session)
                              : INVALID_SOCKET;
    xhash* hash_table = (ssh_socket != INVALID_SOCKET)
                            ? (xhash*)xpoll_get_client_data(ssh_socket)
                            : NULL;
    SshWritePumpCtx pump = { 0, 0 };

    if (client->state == SOCKS5_STATE_CONNECTED) {
        if (socks5_drain_ssh_wbuf(client, &pump) != 0) {
            return;
        }
    } else if (client->state == SOCKS5_STATE_OPENING) {
        pump.need_write |= SSH_WNEED_OPENING;
    }

    socks5_arm_ssh_writable(ssh_socket, hash_table,
                            (pump.need_write & SSH_WNEED_POLLOUT), "client_eof");
}

static void client_channel_close_cb(xChannel* ch, const char* reason, void* ud) {
    Socks5Client *client = (Socks5Client*)ud;
    XLOGW("client channel closed: reason=%s", reason ? reason : "unknown");

    if (client) {
        SOCKET_T old_fd = client->client_sock;
        if (client->io_ch == ch) {
            client->io_ch = NULL;
        }
        client->client_sock = INVALID_SOCKET;
        client->state = SOCKS5_STATE_ERROR;
        socks5_client_cleanup(old_fd, client);
    }

    xchannel_destroy(ch);
}

static bool socks5_channel_retry_open(Socks5Client *client) {
    if (SOCKS5_STATE_OPENING != client->state) return false;
    if (time_get_ms() < client->last_retry_time) return false;
    if (client->ssh_channel) return true;

    /* SSH socket 还没冲干净时不发起 open（发出去会在服务端漏通道，见
     * wolfSSH_session_can_open_channel）。这只是等发送缓冲，不是开通道被拒，
     * 所以不能计进 retry_error_count —— 否则拥塞几百毫秒就把 MAX_REOPEN_COUNT
     * 耗光，把本来好好的连接判成 TTL_EXPIRED。 */
    if (!wolfSSH_session_can_open_channel(client->ssh_session)) {
        SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
        socks5_arm_ssh_writable(ssh_socket, NULL, 1, "channel_open_wait_drain");
        client->last_retry_time = time_get_ms() + 20;
        return true;
    }

    client->ssh_channel = wolfSSH_channel_open(client->ssh_session,
                                               client->target_host, client->target_port,
                                               g_server_config.ssh_host, client->client_port);
    client->last_retry_time = time_get_ms() + 50;
    client->retry_error_count++;

    if (client->ssh_channel == NULL) {
        int err = wolfSSH_get_error(client->ssh_session);
        if (client->retry_error_count > MAX_REOPEN_COUNT
            || wolfSSH_check_fatal(err)) {
            XLOGE("socks5_channel_retry_open retries reached, fd=%d, host=%s",
                  (int)client->client_sock, client->target_host);
            socks5_reply_and_close(client, SOCKS5_REP_TTL_EXPIRED, "channel_open_ttl_expired");
            return false;
        }

        SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
        xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
        socks5_arm_ssh_writable(ssh_socket, hash_table, 1,
                                "channel_retry_open");
    }
    return true;
}

/* Download-direction resume: once the client send buffer has drained below the
 * low water, re-pump the SSH channel (which re-opens the receive window and lets
 * the remote send again). Runs off the 100 ms update tick rather than an xchannel
 * callback so it never re-enters xchannel send while a flush is in progress. */
static void socks5_resume_io_send(Socks5Client* client) {
    if (!client || !client->io_send_paused) return;
    if (client->state != SOCKS5_STATE_CONNECTED || !client->io_ch ||
        xchannel_is_closed(client->io_ch)) {
        client->io_send_paused = false;
        return;
    }

    size_t send_buf = 0;
    xchannel_get_stats(client->io_ch, &send_buf, NULL, NULL, NULL);
    if (send_buf > SOCKS5_IO_SEND_LOW_WATER) return;  /* still draining */

    XLOGD("io_ch send low water: resuming SSH reads fd=%d send_buf=%zu",
          (int)client->client_sock, send_buf);
    client->io_send_paused = false;
    socks5_pump_client_read(client);
}

static bool socks5_client_update_each(xhashKey k, void* value, void* ud) {
    (void)k;
    (void)ud;
    Socks5Client *client = (Socks5Client*)value;
    if (!client) return true;
    if (client->state == SOCKS5_STATE_OPENING) {
        socks5_channel_retry_open(client);
    } else if (client->io_send_paused) {
        socks5_resume_io_send(client);
    }

    return true;
}

static void accept_cb_single(SOCKET_T listen_fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)mask;
    (void)clientData;
    (void)submit_arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    SOCKET_T client_sock = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock == INVALID_SOCKET) {
        if (g_server_running && !socket_check_eagain()) {
            XLOGE("accept failed: %d", GET_ERRNO());
        }
        return;
    }

    int active_connections = socks5_active_connections();
    if (active_connections >= MAX_CONCURRENT_CONNECTIONS) {
        XLOGE("Too many connections (%d), rejecting new connection", active_connections);
        CLOSE_SOCKET(client_sock);
        return;
    }
    socket_set_nonblocking(client_sock);
    // socket_set_keepalive(client_sock, 30, 5, 5);

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    if (!xpac_proxy_client_allowed(client_ip)) {
        XLOGW("Reject SOCKS5 client %s:%d: not in proxy whitelist",
              client_ip, ntohs(client_addr.sin_port));
        CLOSE_SOCKET(client_sock);
        return;
    }

    Socks5Client *client = (Socks5Client*)malloc(sizeof(Socks5Client));
    if (!client) {
        XLOGE("client malloc failed...");
        CLOSE_SOCKET(client_sock);
        return;
    }

    memset(client, 0, sizeof(Socks5Client));
    client->client_sock = client_sock;
    client->state = SOCKS5_STATE_INIT;
    /* 先挂在 MAIN 上；CONNECT 解析出目标域名后再按 @bulk 分流迁移 */
    client->ssh_session = socks5_main_session();
    if (!client->ssh_session) {
        XLOGE("SSH session not ready, reject client socket=%d", (int)client_sock);
        socks5_client_free(client);
        free(client);
        return;
    }

    strncpy(client->client_host, client_ip, sizeof(client->client_host) - 1);
    client->client_host[sizeof(client->client_host) - 1] = '\0';
    client->client_port = ntohs(client_addr.sin_port);
    XLOGW("New client connection from %s:%d, socket=%d",
            client->client_host, client->client_port, (int)client_sock);

    xChannelConfig chcfg = XCHANNEL_CONFIG_INIT;
    chcfg.frame = XCHANNEL_FRAME_RAW;
    chcfg.packet_cb = client_channel_packet_cb;
    chcfg.close_cb = client_channel_close_cb;
    chcfg.eof_cb = client_channel_eof_cb;
    chcfg.userdata = client;

    client->io_ch = xchannel_create(client_sock, &chcfg);
    if (!client->io_ch) {
        XLOGE("Failed to create client xchannel");
        socks5_client_free(client);
        free(client);
        return;
    }
    xchannel_set_max_send(client->io_ch, 16 * 1024 * 1024);
    xchannel_set_max_recv(client->io_ch, 16 * 1024 * 1024);
    if (xchannel_attach(client->io_ch) != 0) {
        XLOGE("Failed to attach client xchannel");
        socks5_client_free(client);
        free(client);
        return;
    }

    client->state = SOCKS5_STATE_AUTH;
    if (socks5_client_stage(client) != 0) {
        XLOGE("Failed to stage new client fd=%d", (int)client_sock);
        socks5_client_free(client);
        free(client);
        return;
    }

    XLOGD("New client registered, active connections: %d", socks5_active_connections());
}

static void handle_ssh_session_error(SshSessionSlot* slot) {
    if (!slot || !slot->session) return;
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(slot->session);
    xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
    if (hash_table) {
        ssh_error_cb(ssh_socket, XPOLL_ERROR | XPOLL_CLOSE, hash_table, NULL);
    }
}

void socks5_server_update() {
    static long64 last_keepalive = 0;
    long64 now_ms = time_get_ms();
    long64 now_sec = now_ms/1000;
    if (now_sec - last_keepalive >= 15) {
        last_keepalive = now_sec;
        for (int i = 0; i < SSH_SLOT_COUNT; i++) {
            SshSessionSlot* slot = &g_ssh_slots[i];
            if (slot->session) {
                // wolfSSH doesn't have direct keepalive, send ignore packet instead
                int rc = wolfSSH_session_keepalive(slot->session);
                if (rc < 0) {
                    XLOGE("keepalive error: %d (%s)", rc, slot->name);
                    handle_ssh_session_error(slot);
                    continue;
                }
                socks5_arm_ssh_writable(wolfSSH_session_get_socket(slot->session),
                                        NULL, 0, "keepalive_pending_output");
                XLOGI("keepalive success %lld (%s)", time_get_ms(), slot->name);
            }

            if (!slot->session) {
                slot->session = socks5_create_shared_session(&g_server_config);
                if (!slot->session) {
                    XLOGE("ReCreating failed to create shared SSH session (%s)",
                          slot->name);
                    continue;
                }
                XLOGW("ReCreating shared SSH session created successfully (%s)",
                      slot->name);
            }
        }
    }

    for (int i = 0; i < SSH_SLOT_COUNT; i++) {
        if (!g_ssh_slots[i].session) continue;
        SOCKET_T ssh_sock = wolfSSH_session_get_socket(g_ssh_slots[i].session);
        xhash* hash = (xhash*)xpoll_get_client_data(ssh_sock);
        if(hash) {
            xhash_foreach(hash, socks5_client_update_each, NULL);
            /* Resuming a paused download can queue WINDOW_ADJUST packets. */
            socks5_arm_ssh_writable(ssh_sock, hash, 0,
                                    "update_pending_output");
        }
    }
}

int socks5_server_start(const Socks5ServerConfig* config) {
    if (!config)
        return -1;

    // Initialize server configuration
    memcpy(&g_server_config, config, sizeof(Socks5ServerConfig));

    {
        const bool has_user = config->proxy_username && config->proxy_username[0] != '\0';
        const bool has_pass = config->proxy_password && config->proxy_password[0] != '\0';
        if (has_user != has_pass) {
            XLOGE("Invalid SOCKS5 auth config: both --socks-user and --socks-pass are required");
            return -1;
        }
    }

    XLOGI("Creating shared SSH session to %s:%d...", config->ssh_host, config->ssh_port);
    WOLFSSH *ssh_session = socks5_create_shared_session(config);
    if (!ssh_session) {
        XLOGE("Failed to create shared SSH session");
        return -1;
    }
    XLOGI("Shared SSH session created successfully");

    /* BULK 会话尽力创建：失败只降级为全部走 MAIN，更新 tick 里会重试 */
    WOLFSSH *bulk_session = socks5_create_shared_session(config);
    if (bulk_session) {
        XLOGI("Bulk SSH session created successfully");
    } else {
        XLOGW("Failed to create bulk SSH session, bulk domains fall back to main");
    }

    // Create listening socket
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock == INVALID_SOCKET) {
        XLOGE("listen socket creation failed");
        socks5_destroy_shared_session(ssh_session);
        socks5_destroy_shared_session(bulk_session);
        return -1;
    }

    // Set SO_REUSEADDR
    int opt = 1;
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // Bind address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = config->bind_address ?
        inet_addr(config->bind_address) : INADDR_ANY;
    server_addr.sin_port = htons(config->bind_port);

    if (bind(g_listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        XLOGE("bind failed");
        socks5_destroy_shared_session(ssh_session);
        socks5_destroy_shared_session(bulk_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Listen
    if (listen(g_listen_sock, SOMAXCONN) < 0) {
        XLOGE("listen failed");
        socks5_destroy_shared_session(ssh_session);
        socks5_destroy_shared_session(bulk_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Register listening socket event
    if (xpoll_add_event(g_listen_sock, XPOLL_READABLE,
                        accept_cb_single, NULL, NULL, NULL) != 0) {
        XLOGE("Failed to register listen socket event");
        socks5_destroy_shared_session(ssh_session);
        socks5_destroy_shared_session(bulk_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Set shared SSH sessions
    g_ssh_slots[SSH_SLOT_MAIN].session = ssh_session;
    g_ssh_slots[SSH_SLOT_BULK].session = bulk_session;

    // Set server running flag
    g_server_running = 1;

    XLOGI("SOCKS5 proxy is running...");
    XLOGI("Listen address: %s:%d", config->bind_address, config->bind_port);
    XLOGI("SSH tunnel: %s:%d (user: %s)", config->ssh_host, config->ssh_port, config->ssh_username);
    XLOGI("SOCKS5 auth: %s", socks5_userpass_configured() ? "username/password" : "none");
    XLOGI("Using %s for I/O multiplexing", xpoll_name());

    return 0;
}

void socks5_server_stop(void) {
    if(g_server_running==0) return;
    XLOGW("[socks5] try stop socks5 service...");

    // Close listening socket and remove from xpoll
    if (g_listen_sock != INVALID_SOCKET) {
        xpoll_del_event(g_listen_sock, XPOLL_ALL);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        XLOGI("SOCKS5 listening socket closed");
    }

    for (int i = 0; i < SSH_SLOT_COUNT; i++) {
        if (!g_ssh_slots[i].session) continue;
        SOCKET_T ssh_sock = wolfSSH_session_get_socket(g_ssh_slots[i].session);
        xhash* hash = (xhash*)xpoll_get_client_data(ssh_sock);
        if(hash) {
            xhash_foreach(hash, client_on_closed, NULL);
        }
        socks5_destroy_shared_session(g_ssh_slots[i].session);
        g_ssh_slots[i].session = NULL;
    }

    g_server_running = 0;
    XLOGW("[socks5] socks5 service stoped");
}
