#include "socks5_server.h"
#include "xsock.h"
#include "xchannel.h"
#include "ssh_tunnel.h"

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
/* Returned by socks5_send_reply / socks5_client_send_raw / socks5_reply_and_close
 * to tell callers "the client is now in a terminal state — stop further work". */
#define SOCKS5_SEND_CLOSED (-3)

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;
static WOLFSSH *g_ssh_session = NULL;
static SOCKET_T g_listen_sock = INVALID_SOCKET;

static void ssh_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void ssh_write_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void ssh_error_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static int ssh_channel_close_callback(WOLFSSH_CHANNEL* channel, void* ctx);
static int ssh_channel_open_fini_callback(WOLFSSH_CHANNEL* channel, void* ctx);
static int ssh_channel_open_fail_callback(WOLFSSH_CHANNEL* channel, void* ctx);

static int socks5_active_connections(void) {
    if (!g_ssh_session) return 0;
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
    xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
    return hash_table ? (int)xhash_size(hash_table) : 0;
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
    client->state = SOCKS5_STATE_ERROR;

    if (!client->io_ch || xchannel_close_after_flush(client->io_ch, why) != 0) {
        socks5_client_fail(client, why);
    }
    return SOCKS5_SEND_CLOSED;
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

static int socks5_send_reply(Socks5Client* client, uint8_t rep) {
    uint8_t response[256];
    int len = 0;

    response[len++] = 0x05;  // SOCKS version
    response[len++] = rep;   // Reply code
    response[len++] = 0x00;  // Reserved

    if (rep == SOCKS5_REP_SUCCESS) {
        response[len++] = 0x01;  // IPv4

        // convert host address to IP address
        struct in_addr ip_addr;
        if (inet_pton(AF_INET, g_server_config.ssh_host, &ip_addr) == 1) {
            memcpy(&response[len], &ip_addr, 4);
        } else {
            // rollback to 0.0.0.0
            memset(&response[len], 0, 4);
        }
        len += 4;

        // response ssh port
        uint16_t ssh_port = htons(g_server_config.ssh_port);
        memcpy(&response[len], &ssh_port, 2);
        len += 2;
    } else {
        response[len++] = 0x01;
        memset(&response[len], 0, 6);
        len += 6;
    }

    return socks5_client_send_raw(client, response, (size_t)len, "socks5_reply");
}

/* Send a SOCKS5 reply with rep code, then schedule a graceful close.
 * Returns SOCKS5_SEND_CLOSED in every case (success-with-graceful-close or
 * send failure that already escalated to socks5_client_fail). Callers should
 * propagate this as a terminal indicator and stop touching the client. */
static int socks5_reply_and_close(Socks5Client* client, uint8_t rep, const char* reason) {
    int sr = socks5_send_reply(client, rep);
    if (sr == SOCKS5_SEND_CLOSED) return SOCKS5_SEND_CLOSED;
    if (sr != 0) {
        socks5_client_fail(client, "reply_send_error");
        return SOCKS5_SEND_CLOSED;
    }
    return socks5_client_close_after_send(client, reason);
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

static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud);
static void client_channel_close_cb(xChannel* ch, const char* reason, void* ud);
static int socks5_client_stage(Socks5Client* client) {
    if (!client || !g_ssh_session) return -1;

    SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
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

static int socks5_client_open_channel(Socks5Client* client) {
    client->ssh_channel = wolfSSH_channel_open(
        client->ssh_session,
        client->target_host, client->target_port,
        client->client_host, client->client_port);
    if (!client->ssh_channel) {
        if (!wolfSSH_check_fatal(wolfSSH_get_error(client->ssh_session))) {
            SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
            xhash* hash_table = xpoll_get_client_data(ssh_socket);
            if (hash_table) {
                xpoll_add_event(ssh_socket, XPOLL_WRITABLE,
                                NULL, ssh_write_cb, NULL, hash_table);
            }
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

    if (buf[0] != 0x05) {
        XLOGE("SOCKS5 version mismatch 0x%02X, fd=%d",
              buf[0], (int)client->client_sock);
        return -1;
    }

    uint8_t selected = 0xFF;
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

    if (selected == 0xFF) {
        XLOGE("No acceptable auth method, fd=%d", (int)client->client_sock);
        {
            uint8_t resp[2] = {0x05, SOCKS5_AUTH_NO_ACCEPTABLE};
            int sr = socks5_client_send_raw(client, resp, sizeof(resp),
                                            "auth_no_acceptable");
            if (sr == SOCKS5_SEND_CLOSED) return SOCKS5_SEND_CLOSED;
            if (sr != 0) {
                socks5_client_fail(client, "auth_no_acceptable_send_error");
                return SOCKS5_SEND_CLOSED;
            }
        }
        return socks5_client_close_after_send(client, "auth_no_acceptable");
    }

    {
        uint8_t resp[2] = {0x05, selected};
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

    if (buf[0] != 0x01) {
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
    uint8_t resp[2] = {0x01, ok ? 0x00 : 0x01};
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

    if (buf[0] != 0x05) {
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

    if (atyp == SOCKS5_ATYP_IPV4) {
        addr_len = 4;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        addr_len = 16;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        if (len < pos + 1) return 0;
        addr_len = 1u + (size_t)buf[pos];
    } else {
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
        if (atyp == SOCKS5_ATYP_IPV4) {
            struct in_addr addr;
            memcpy(&addr, &buf[pos], 4);
            inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
            pos += 4;
        } else if (atyp == SOCKS5_ATYP_IPV6) {
            struct in6_addr addr6;
            memcpy(&addr6, &buf[pos], 16);
            inet_ntop(AF_INET6, &addr6, target_host, sizeof(target_host));
            pos += 16;
        } else {
            size_t domain_len = (size_t)buf[pos++];
            if (domain_len >= sizeof(target_host)) {
                XLOGE("Domain too long, fd=%d", (int)client->client_sock);
                return -1;
            }
            memcpy(target_host, &buf[pos], domain_len);
            target_host[domain_len] = '\0';
            pos += domain_len;
        }

        uint16_t net_port = 0;
        uint16_t target_port = 0;
        memcpy(&net_port, &buf[pos], sizeof(net_port));
        target_port = ntohs(net_port);

        strncpy(client->target_host, target_host, sizeof(client->target_host) - 1);
        client->target_host[sizeof(client->target_host) - 1] = '\0';
        client->target_port = target_port;

        XLOGI("SOCKS5 CONNECT -> %s:%d, fd=%d",
              target_host, target_port, (int)client->client_sock);
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
    if (client->ssh_channel && g_ssh_session &&
        client->ssh_session == g_ssh_session ) {
        wolfSSH_channel_close(client->ssh_channel);
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

    if (g_ssh_session && key_fd != INVALID_SOCKET) {
        SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
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

static bool ssh_read_each_client(xhashKey k, void* value, void* ud) {
    (void)ud;
    // Get client from hash node
    Socks5Client *client = (Socks5Client*)value;
    if (!client || client->state != SOCKS5_STATE_CONNECTED || !client->ssh_channel)
        return true;  // Continue to next client

    if (client->wlen > SOCKS5_WRITE_BUFFER_MAX) {
        XLOGE("Warning: Invalid wlen=%zu for fd=%d",
                   client->wlen, (int)client->client_sock);
        socks5_client_wbuf_reset(client);
        socks5_client_fail(client, "invalid_write_buffer");
        return true;
    }

    if (client->ssh_session && client->ssh_channel) {
        if (wolfSSH_channel_eof(client->ssh_channel) != 0) {
            socks5_client_fail(client, "ssh_channel_eof");
            return true;
        }
    }

    char ssh_rbuf[8192];
    int n = wolfSSH_channel_read(client->ssh_channel, ssh_rbuf, sizeof(ssh_rbuf));
    if (n > 0) {
        if (!client->io_ch) {
            XLOGE("Client channel missing for fd=%d", (int)client->client_sock);
            socks5_client_fail(client, "missing_client_channel");
            return true;
        }
        SOCKET_T client_fd = client->client_sock;
        int rc = xchannel_send_raw(client->io_ch, ssh_rbuf, (size_t)n);
        if (rc != 0) {
            XLOGE("Channel send failed %d bytes to client fd=%d, rc=%d",
                  n, (int)client_fd, rc);
            if (rc == -2) {
                socks5_client_fail(client, "client_send_backpressure");
            }
            return true;
        } else if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
            XLOGE("Channel read finished && EOF for fd=%d", (int)client->client_sock);
            socks5_client_fail(client, "ssh_channel_eof");
            return true;
        }
    } else if (n < 0) {
        if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
            socks5_client_fail(client, "ssh_channel_eof");
        } else {
            XLOGE("Channel read failed for fd=%d, n=%d", (int)client->client_sock, n);
            socks5_client_fail(client, "ssh_channel_read_error");
        }
        return true;
    } else {
        if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
            XLOGE("Channel closed by remote fd=%d", (int)client->client_sock);
            socks5_client_fail(client, "ssh_channel_closed");
            return true;
        }
    }

    return true;
}

static void ssh_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table) {
        XLOGE("ERROR: ssh_read_cb called with NULL hash table!");
        return;
    }

    word32 channelId = 0;
    int ret = wolfSSH_process_events(g_ssh_session, &channelId);
    if (ret < 0) {
        int error = wolfSSH_get_error(g_ssh_session);
        if (wolfSSH_check_fatal(error)) {
            XLOGE("wolfSSH_worker fatal error: %d:%s", error, wolfSSH_ErrorToName(error));
            ssh_error_cb(fd, XPOLL_ERROR, clientData, NULL);
            return;
        } else if(error != WS_CHANOPEN_FAILED && WS_INVALID_CHANID != error) {
            XLOGE("wolfSSH_worker error: %d:%s", error, wolfSSH_ErrorToName(error));
        }
    }

    xhash_foreach(hash_table, ssh_read_each_client, NULL);
}

static bool ssh_write_each_client(xhashKey k, void* value, void * ctx) {
    // Get client from hash node
    Socks5Client *client = (Socks5Client*)value;
    if (!client || client->state != SOCKS5_STATE_CONNECTED ||
        !client->ssh_channel || client->wlen == 0) {
        return true;  // Continue to next client
    }

    if (client->ssh_session && client->ssh_channel) {
        if (wolfSSH_channel_eof(client->ssh_channel) != 0) {
            socks5_client_fail(client, "ssh_channel_eof");
            return true;
        }
    }

    size_t remaining = client->wlen;
    int chunk = (remaining > (size_t)INT_MAX) ? INT_MAX : (int)remaining;
    int written = wolfSSH_channel_write(client->ssh_channel,
                                    client->wbuf,
                                    chunk);
    if (written < 0) {
        XLOGE("Channel write failed, fd=%d, host=%s, err=%d",
               (int)client->client_sock, client->target_host, GET_ERRNO());
        socks5_client_fail(client, "ssh_channel_write_error");
        return true;
    } else if ((size_t)written >= remaining) {
        // All data has been written
        socks5_client_wbuf_reset(client);
        XLOGE("All buffered data (%d bytes) written for fd=%d",
               written, (int)client->client_sock);
    } else if(written != 0) {
        // Partial write
        socks5_client_wbuf_consume(client, (size_t)written);
        XLOGE("Partially buffered data written: %d/%zu bytes for fd=%d",
               written, client->wlen, (int)client->client_sock);
         *(int*)ctx = 1;
    } else {
        *(int*)ctx = 1;
    }

    return true;  // Continue to next client
}

static void ssh_write_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table)
        return;

    static int _call_count = 0;
    _call_count++;

    if (_call_count % 10000 == 0) {
        XLOGD("ssh_write_cb called (count=%d, mask=%d)", _call_count, mask);
    }

    int has_data = 0;
    xhash_foreach(hash_table, ssh_write_each_client, &has_data);
    if( has_data==0 )
        xpoll_del_event(fd, XPOLL_WRITABLE);
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
        if (client->wlen > 0 && client->ssh_session) {
            SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
            xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
            if (hash_table) {
                xpoll_add_event(ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
            }
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
        XLOGE("Marked client as error due to SSH channel close, fd=%d, host=%s", (int)client->client_sock, client->target_host);
        socks5_client_fail(client, "ssh_channel_closed");
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
    BOOL miss = TRUE;
    if (hash)
        miss = xhash_foreach(hash, client_channel_confirm, channel);
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

    XLOGE("ssh_error_cb called (fd=%d)", (int)fd);

    xhash_foreach(hash_table, client_on_closed, NULL);
    socks5_destroy_shared_session(g_ssh_session);
    g_ssh_session = NULL;

    g_ssh_session = socks5_create_shared_session(&g_server_config);
    if (!g_ssh_session) {
        XLOGE("ReCreating failed to create shared SSH session");
        return;
    }
    XLOGW("ReCreating shared SSH session created successfully");
}

static int socks5_forward_client_data_to_ssh(Socks5Client* client,
                                             const char* data, size_t len) {
    if (!client || !data || len == 0) return 0;

    SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
    xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);

    if (client->wlen > 0) {
        if (socks5_client_wbuf_append(client, data, len) != 0) {
            XLOGE("ERROR: Write buffer full. buffered=%zu, needed=%zu, %s",
                  client->wlen, len, client->target_host);
            return -1;
        }
    } else {
        if (len > (size_t)INT_MAX) {
            XLOGE("ERROR: Packet too large for SSH write: %zu, %s",
                  len, client->target_host);
            return -1;
        }

        int written = wolfSSH_channel_write(client->ssh_channel, data, (int)len);
        if (written < 0) {
            client->retry_error_count++;
            XLOGE("Failed to write to SSH channel: error count=%d, host=%s, errno=%d",
                  client->retry_error_count, client->target_host, written);
            return -1;
        }
        if (written < (int)len) {
            size_t remaining = len - (size_t)written;
            if (socks5_client_wbuf_append(client, data + written, remaining) != 0) {
                XLOGE("ERROR: Write buffer full for %zu bytes, %s",
                      remaining, client->target_host);
                return -1;
            }
        } else {
            client->retry_error_count = 0;
        }
    }

    if (client->wlen > 0 && hash_table) {
        xpoll_add_event(ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
    }
    return 0;
}

static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud) {
    (void)ch;
    Socks5Client *client = (Socks5Client*)ud;
    if (!client || len == 0) return 0;
    if (client->state == SOCKS5_STATE_ERROR) return len;

    size_t off = 0;
    while (off < len) {
        if (client->state == SOCKS5_STATE_AUTH) {
            size_t used = 0;
            int rc = socks5_consume_auth(client, (const uint8_t*)data + off, len - off, &used);
            if (rc < 0) {
                if (rc != SOCKS5_SEND_CLOSED) {
                    socks5_client_fail(client, "auth_error");
                }
                return len;
            }
            if (rc == 0) break;
            off += used;
            continue;
        }

        if (client->state == SOCKS5_STATE_AUTH_PASSWORD) {
            size_t used = 0;
            int rc = socks5_consume_userpass_auth(client, (const uint8_t*)data + off, len - off, &used);
            if (rc < 0) {
                if (rc != SOCKS5_SEND_CLOSED) {
                    socks5_client_fail(client, "auth_userpass_error");
                }
                return len;
            }
            if (used > 0) off += used;
            if (rc == 0 && used == 0) break;
            continue;
        }

        if (client->state == SOCKS5_STATE_REQUEST) {
            size_t used = 0;
            int rc = socks5_consume_request(client, (const uint8_t*)data + off, len - off, &used);
            if (rc < 0) {
                if (rc != SOCKS5_SEND_CLOSED) {
                    socks5_client_fail(client, "request_error");
                }
                return len;
            }
            if (used > 0) off += used;
            if (rc == 0 && used == 0) break;
            continue;
        }

        if (client->state == SOCKS5_STATE_OPENING) {
            size_t remaining = len - off;
            if (remaining > 0 &&
                socks5_client_wbuf_append(client, data + off, remaining) != 0) {
                XLOGE("ERROR: Pending buffer full while opening. needed=%zu, host=%s",
                      remaining, client->target_host);
                socks5_client_fail(client, "buffer_full");
                return len;
            }
            off = len;
            break;
        }

        if (client->state == SOCKS5_STATE_CONNECTED) {
            if (!client->ssh_channel || !client->ssh_session) {
                socks5_client_fail(client, "missing_ssh_channel");
                return len;
            }
            if (socks5_forward_client_data_to_ssh(client, data + off, len - off) != 0) {
                socks5_client_fail(client, "ssh_write_error");
            }
            return len;
        }

        break;
    }

    return off;
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

    client->ssh_channel = wolfSSH_channel_open(client->ssh_session,
                                               client->target_host, client->target_port,
                                               client->client_host, client->client_port);
    client->last_retry_time = time_get_ms() + 50;
    client->retry_error_count++;

    if (client->ssh_channel == NULL) {
        if (client->retry_error_count > MAX_REOPEN_COUNT
            || wolfSSH_check_fatal(wolfSSH_get_error(client->ssh_session))) {
            XLOGE("socks5_channel_retry_open retries reached, fd=%d, host=%s",
                  (int)client->client_sock, client->target_host);
            socks5_reply_and_close(client, SOCKS5_REP_TTL_EXPIRED, "channel_open_ttl_expired");
            return false;
        }
    }
    return true;
}

static bool socks5_client_update_each(xhashKey k, void* value, void* ud) {
    (void)k;
    (void)ud;
    Socks5Client *client = (Socks5Client*)value;
    if (!client) return true;
    if (client->state == SOCKS5_STATE_OPENING) {
        socks5_channel_retry_open(client);
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
    socket_set_keepalive(client_sock, 30, 5, 5);

    Socks5Client *client = (Socks5Client*)malloc(sizeof(Socks5Client));
    if (!client) {
        XLOGE("client malloc failed...");
        CLOSE_SOCKET(client_sock);
        return;
    }

    memset(client, 0, sizeof(Socks5Client));
    client->client_sock = client_sock;
    client->state = SOCKS5_STATE_INIT;
    client->ssh_session = g_ssh_session;
    if (!client->ssh_session) {
        XLOGE("SSH session not ready, reject client socket=%d", (int)client_sock);
        socks5_client_free(client);
        free(client);
        return;
    }

    inet_ntop(AF_INET, &client_addr.sin_addr, client->client_host, sizeof(client->client_host));
    client->client_port = ntohs(client_addr.sin_port);
    XLOGW("New client connection from %s:%d, socket=%d",
            client->client_host, client->client_port, (int)client_sock);

    xChannelConfig chcfg = XCHANNEL_CONFIG_INIT;
    chcfg.frame = XCHANNEL_FRAME_RAW;
    chcfg.packet_cb = client_channel_packet_cb;
    chcfg.close_cb = client_channel_close_cb;
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

static void handle_ssh_session_error() {
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
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
        if (g_ssh_session) {
            // wolfSSH doesn't have direct keepalive, send ignore packet instead
            int rc = wolfSSH_session_keepalive(g_ssh_session);
            if (rc < 0) {
                XLOGE("keepalive error: %d", rc);
                handle_ssh_session_error();
                return;
            }
        }
        XLOGI("keepalive success %lld", time_get_ms());

        if(!g_ssh_session) {
            g_ssh_session = socks5_create_shared_session(&g_server_config);
            if (!g_ssh_session) {
                XLOGE("ReCreating failed to create shared SSH session");
                return;
            }
            XLOGW("ReCreating shared SSH session created successfully");
        }
    }

    if (g_ssh_session) {
        SOCKET_T ssh_sock = wolfSSH_session_get_socket(g_ssh_session);
        xhash* hash = (xhash*)xpoll_get_client_data(ssh_sock);
        if(hash) {
            xhash_foreach(hash, socks5_client_update_each, NULL);
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

    // Create listening socket
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock == INVALID_SOCKET) {
        XLOGE("listen socket creation failed");
        socks5_destroy_shared_session(ssh_session);
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
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Listen
    if (listen(g_listen_sock, SOMAXCONN) < 0) {
        XLOGE("listen failed");
        socks5_destroy_shared_session(ssh_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Register listening socket event
    if (xpoll_add_event(g_listen_sock, XPOLL_READABLE,
                        accept_cb_single, NULL, NULL, NULL) != 0) {
        XLOGE("Failed to register listen socket event");
        socks5_destroy_shared_session(ssh_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Set shared SSH session
    g_ssh_session = ssh_session;

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

    if( g_ssh_session ) {
        SOCKET_T ssh_sock = wolfSSH_session_get_socket(g_ssh_session);
        xhash* hash = (xhash*)xpoll_get_client_data(ssh_sock);
        if(hash) {
            xhash_foreach(hash, client_on_closed, NULL);
        }
        socks5_destroy_shared_session(g_ssh_session);
    }

    g_server_running = 0;
    g_ssh_session = NULL;
    XLOGW("[socks5] socks5 service stoped");
}
