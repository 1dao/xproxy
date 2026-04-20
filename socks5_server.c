#include "socks5_server.h"
#include "socket_util.h"
#include "ssh_tunnel.h"

#include "xpoll.h"
#include "xhash.h"
#ifdef LOG_TAG
    #undef LOG_TAG
#endif
#define LOG_TAG "xsocks5"
#include "xlog.h"

#define MAX_CONCURRENT_CONNECTIONS 8192
#define MAX_REOPEN_COUNT 10 // wait for 3min

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;
static int g_active_connections = 0;
static WOLFSSH *g_ssh_session = NULL;
static SOCKET_T g_listen_sock = INVALID_SOCKET;

typedef struct {
    SOCKET_T client_sock;
    Socks5ClientState state;
    uint8_t auth_method;
    char target_host[256];
    uint16_t target_port;
    uint8_t cmd;
    WOLFSSH *ssh_session;
    WOLFSSH_CHANNEL *ssh_channel;
    char client_host[256];
    uint16_t client_port;

    // IO buffers and state
    char rbuf[131072]; // ssh read
    int rlen;
    char wbuf[65536];// ssh write
    int wlen;

    // reopen cd
    long64 last_retry_time;  // retry time
    int retry_error_count;
} Socks5Client;

static void socks5_send_reply(Socks5Client* client, uint8_t rep) {
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

    send(client->client_sock,  (const char*)response, len, 0);
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

static void ssh_read_cb(SOCKET_T fd, int mask, void *clientData);
static void ssh_write_cb(SOCKET_T fd, int mask, void *clientData);
static void ssh_error_cb(SOCKET_T fd, int mask, void *clientData);
static void client_write_cb(SOCKET_T fd, int mask, void *clientData);
static void socks5_client_stage(Socks5Client* client) {
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
    void* ud = xpoll_get_client_data(ssh_socket);
    if (ud) {
        xhash *hash_table = (xhash*)ud;
        xhash_set_int(hash_table, (long)client->client_sock, client);
        XLOGI("Client fd=%d added to SSH socket hash table", (int)client->client_sock);
        if (xhash_size(hash_table) == 1) {
            xpoll_add_event(ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                            ssh_read_cb, NULL, ssh_error_cb, hash_table);
            XLOGD("SSH socket fd=%d added to XPOLL_ALL event", (int)ssh_socket);
        }
    }
}

static int socks5_handle_handshake(Socks5Client* client) {
    int room = (int)sizeof(client->rbuf) - client->rlen;
    if (room <= 0) {
        XLOGE("Handshake buffer full, fd=%d", (int)client->client_sock);
        return -1;
    }

    int n = recv(client->client_sock,
                 (char*)client->rbuf + client->rlen, room, 0);
    if (n < 0) {
        if (socket_check_eagain()) return 0;
        XLOGE("Handshake recv error, fd=%d, err=%d",
              (int)client->client_sock, GET_ERRNO());
        return -1;
    }
    if (n == 0) {
        XLOGE("Handshake peer closed, fd=%d", (int)client->client_sock);
        return -1;
    }
    client->rlen += n;

    if (client->rlen < 2) return 0;

    uint8_t* buf      = (uint8_t*)client->rbuf;
    uint8_t  nmethods = buf[1];
    int      need     = 2 + (int)nmethods;

    if (client->rlen < need) return 0;

    if (buf[0] != 0x05) {
        XLOGE("SOCKS5 version mismatch 0x%02X, fd=%d",
              buf[0], (int)client->client_sock);
        return -1;
    }

    uint8_t selected = 0xFF;
    for (int i = 0; i < (int)nmethods; i++) {
        if (buf[2 + i] == SOCKS5_AUTH_NONE) {
            selected = SOCKS5_AUTH_NONE;
            break;
        }
    }

    if (selected == 0xFF) {
        XLOGE("No acceptable auth method, fd=%d", (int)client->client_sock);
        uint8_t resp[2] = {0x05, SOCKS5_AUTH_NO_ACCEPTABLE};
        send(client->client_sock, (const char*)resp, 2, 0);
        return -1;
    }

    uint8_t resp[2] = {0x05, selected};
    if (send(client->client_sock, (const char*)resp, 2, 0) != 2) {
        XLOGE("Failed to send auth response, fd=%d, err=%d",
              (int)client->client_sock, GET_ERRNO());
        return -1;
    }
    client->auth_method = selected;

    // consume greeting，keep any remaining data for next read
    int consumed = need;
    if (client->rlen > consumed)
        memmove(client->rbuf, client->rbuf + consumed, client->rlen - consumed);
    client->rlen -= consumed;

    return 1;
}

static int socks5_client_auth(Socks5Client* client) {
    int room = (int)sizeof(client->rbuf) - client->rlen;
    if (room <= 0) {
        XLOGE("Request buffer full, fd=%d", (int)client->client_sock);
        return -1;
    }

    int n = recv(client->client_sock,
                 (char*)client->rbuf + client->rlen, room, 0);
    if (n < 0) {
        if (!socket_check_eagain()) {
            XLOGE("Request recv error, fd=%d, err=%d",
                  (int)client->client_sock, GET_ERRNO());
            return -1;
        }
    } else if (n == 0) {
        XLOGE("Request peer closed, fd=%d", (int)client->client_sock);
        return -1;
    } else client->rlen += n;

    uint8_t* buf = (uint8_t*)client->rbuf;
    if (client->rlen < 4) return 0;
    if (buf[0] != 0x05) {
        XLOGE("SOCKS5 request version mismatch, fd=%d", (int)client->client_sock);
        return -1;
    }
    if (buf[1] != SOCKS5_CMD_CONNECT) {
        XLOGE("Unsupported cmd=0x%02X, fd=%d", buf[1], (int)client->client_sock);
        socks5_send_reply(client, SOCKS5_REP_COMMAND_NOT_SUPPORTED);
        return -1;
    }

    uint8_t atyp = buf[3];
    int pos = 4;
    int addr_len = 0;

    if (atyp == SOCKS5_ATYP_IPV4) {
        addr_len = 4;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        addr_len = 16;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        if (client->rlen < pos + 1) return 0;
        addr_len = 1 + (int)buf[pos];
    } else {
        XLOGE("Unsupported ATYP=0x%02X, fd=%d", atyp, (int)client->client_sock);
        socks5_send_reply(client, SOCKS5_REP_ADDRESS_NOT_SUPPORTED);
        return -1;
    }

    int need = pos + addr_len + 2;
    if (client->rlen < need) return 0;

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
        int domain_len = buf[pos++];
        if (domain_len >= (int)sizeof(target_host)) {
            XLOGE("Domain too long, fd=%d", (int)client->client_sock);
            return -1;
        }
        memcpy(target_host, &buf[pos], domain_len);
        target_host[domain_len] = '\0';
        pos += domain_len;
    }

    uint16_t target_port = ntohs(*(uint16_t*)&buf[pos]);
    pos += 2;

    strncpy(client->target_host, target_host, sizeof(client->target_host) - 1);
    client->target_host[sizeof(client->target_host) - 1] = '\0';
    client->target_port = target_port;

    XLOGI("SOCKS5 CONNECT -> %s:%d, fd=%d",
          target_host, target_port, (int)client->client_sock);

    if (!client->ssh_session) {
        XLOGE("No SSH session, fd=%d", (int)client->client_sock);
        socks5_send_reply(client, SOCKS5_REP_GENERAL_FAILURE);
        return -1;
    }

    // handshake done, clear rbuf for SSH data
    client->rlen = 0;

    client->state = SOCKS5_STATE_OPENING;
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
        } else {
            socks5_send_reply(client, SOCKS5_REP_GENERAL_FAILURE);
            return -1;
        }
    }
    return 1;
}

void socks5_client_free(Socks5Client* client) {
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
    client->state = SOCKS5_STATE_ERROR;
}

static void socks5_client_cleanup(SOCKET_T fd, Socks5Client *client) {
    if (!client) return;
    // unreg ev
    xpoll_del_event(client->client_sock, XPOLL_ALL);

    if (g_ssh_session) {
        SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
        xhash* hash = xpoll_get_client_data(ssh_socket);

        if (hash) {
            xhash_remove_int(hash, (long)client->client_sock, false);

            if (xhash_size(hash) <= 0) {
                xpoll_del_event(ssh_socket, XPOLL_READABLE);
                XLOGE("SSH socket fd=%d remove XPOLL_ALL event", (int)ssh_socket);
            }
        }
    }

    socks5_client_free(client);
    free(client);

    g_active_connections--;
    XLOGI("Active connections: %d (connection closed)", g_active_connections);
}

static bool ssh_read_each_client(xhashKey k, void* value, void* ud) {
    (void)ud;
    // Get client from hash node
    Socks5Client *client = (Socks5Client*)value;
    if (!client || client->state != SOCKS5_STATE_CONNECTED || !client->ssh_channel)
        return true;  // Continue to next client

    if (client->rlen < 0 || client->rlen >= sizeof(client->rbuf)) {
        XLOGE("Warning: Invalid rlen=%d, resetting to 0 for fd=%d",
                   client->rlen, (int)client->client_sock);
        client->rlen = 0;
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        return true;
    }

    if (client->wlen < 0 || client->wlen >= sizeof(client->wbuf)) {
        XLOGE("Warning: Invalid wlen=%d, resetting to 0 for fd=%d",
                   client->wlen, (int)client->client_sock);
        client->wlen = 0;
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        return true;
    }

    if (client->ssh_session && client->ssh_channel) {
        if (wolfSSH_channel_eof(client->ssh_channel) != 0) {
            client->state = SOCKS5_STATE_ERROR;
            SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
            return true;
        }
    }

    // Try to read this channel
    int n = wolfSSH_channel_read(client->ssh_channel,
                                client->rbuf+client->rlen,
                                sizeof(client->rbuf)-client->rlen);
    if (n > 0) {
        // Successfully read, send to client
        int total = n + client->rlen;
        int sent = send(client->client_sock, client->rbuf, total, 0);
        if (sent != total) {
            if (sent <= 0 ){
                if(socket_check_eagain()) {
                    XLOGI("Channel send failed %d bytes to client fd=%d (sent=%d), eagain got",
                           n, (int)client->client_sock, sent);
                    xpoll_add_event(client->client_sock, XPOLL_WRITABLE,
                                    NULL, client_write_cb, NULL, client);
                } else {
                    client->state = SOCKS5_STATE_ERROR;
                    XLOGE("Channel send failed %d bytes to client fd=%d (sent=%d), close got",
                           n, (int)client->client_sock, sent);
                }
            } else {
                if (sent > 0 && sent < total) {
                    memmove(client->rbuf, client->rbuf + sent, total - sent);
                    client->rlen = total - sent;
                    XLOGI("Channel data send %d bytes to client fd=%d (sent=%d)",
                           n, (int)client->client_sock, sent);
                    xpoll_add_event(client->client_sock, XPOLL_WRITABLE,
                                    NULL, client_write_cb, NULL, client);
                } else {
                    XLOGE("Invalid sent value %d, resetting buffer", sent);
                    client->rlen = 0;
                }
            }
        } else {
            // Check if channel is EOF
            client->rlen = 0;
            if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
                XLOGE("Channel read finished && EOF for fd=%d", (int)client->client_sock);
                client->state = SOCKS5_STATE_ERROR;
            }
        }
    } else if (n < 0) {
        if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
            client->state = SOCKS5_STATE_ERROR;
        } else {
            XLOGE("Channel read failed for fd=%d, n=%d", (int)client->client_sock, n);
            client->state = SOCKS5_STATE_ERROR;
        }
        return true;
    } else {
        if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
            XLOGE("Channel closed by remote fd=%d", (int)client->client_sock);
            client->state = SOCKS5_STATE_ERROR;
        }
    }

    if( client->state == SOCKS5_STATE_ERROR )
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);

    return true;
}

static void ssh_read_cb(SOCKET_T fd, int mask, void *clientData) {
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
            ssh_error_cb(fd, XPOLL_ERROR, clientData);
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
            client->state = SOCKS5_STATE_ERROR;
            SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
            return true;
        }
    }

    int remaining = client->wlen;
    int written = wolfSSH_channel_write(client->ssh_channel,
                                    client->wbuf,
                                    remaining);
    if (written < 0) {
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        XLOGE("Channel write failed, fd=%d, host=%s, err=%d",
               (int)client->client_sock, client->target_host, GET_ERRNO());
    } else if (written >= remaining) {
        // All data has been written
        client->wlen = 0;
        XLOGE("All buffered data (%d bytes) written for fd=%d",
               written, (int)client->client_sock);
    } else if(written != 0) {
        // Partial write
        memmove(client->wbuf, client->wbuf + written, remaining - written);
        client->wlen = remaining - written;
        XLOGE("Partially buffered data written: %d/%d bytes for fd=%d",
               written, remaining - written, (int)client->client_sock);
         *(int*)ctx = 1;
    } else {
        *(int*)ctx = 1;
    }

    return true;  // Continue to next client
}

static void ssh_write_cb(SOCKET_T fd, int mask, void *clientData) {
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
    Socks5Client *client = (Socks5Client*)value;
    if (!client) return true;
    if(!ctx) {
        socks5_client_cleanup(client->client_sock, client);
    } else if(client->state==SOCKS5_STATE_ERROR) {
        socks5_client_cleanup(client->client_sock, client);
    }
    return true;
}

static bool client_channel_confirm(xhashKey k, void* value, void* channel_ptr) {
    Socks5Client *client = (Socks5Client*)value;
    WOLFSSH_CHANNEL* channel = (WOLFSSH_CHANNEL*)channel_ptr;
    if (client->ssh_channel == channel) {
        client->state = SOCKS5_STATE_CONNECTED;
        socks5_send_reply(client, SOCKS5_REP_SUCCESS);
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
        client->state = SOCKS5_STATE_ERROR;
        socks5_send_reply(client, SOCKS5_REP_CONNECTION_REFUSED);
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        XLOGE("SSH channel refuse connect, fd=%d, host=%s, errno=%d"
                , (int)client->client_sock, client->target_host, wolfSSH_get_error_code(client->ssh_session));
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
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        XLOGE("Marked client as error due to SSH channel close, fd=%d, host=%s", (int)client->client_sock, client->target_host);
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
        XLOGE("ssh_channel_open_fini_callback: no matching client for channel %p", channel);
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

static void ssh_error_cb(SOCKET_T fd, int mask, void *clientData) {
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table)
        return;
    if(xpoll_get_client_data(fd)!=clientData) {
        XLOGE("ssh_error_cb: clientData mismatch for fd=%d, ", (int)fd);
        XLOGE("ssh_error_cb: clientData mismatch for fd=%d", (int)fd);
        XLOGE("ssh_error_cb: clientData mismatch for fd=%d", (int)fd);
        return;
    }

    XLOGE("ssh_error_cb called (fd=%d)", (int)fd);
    XLOGE("ssh_error_cb called (fd=%d)", (int)fd);
    XLOGE("ssh_error_cb called (fd=%d)", (int)fd);

    xhash_foreach(hash_table, client_on_closed, NULL);
    xpoll_del_event(fd, XPOLL_ALL);
    wolfSSH_session_close(g_ssh_session);
    xhash_destroy(hash_table, false);
    g_ssh_session = NULL;

    // Create shared SSH session
    const Socks5ServerConfig* config = &g_server_config;
    WOLFSSH *ssh_session = wolfSSH_session_open(
        config->ssh_host,
        config->ssh_port,
        config->ssh_username,
        config->ssh_password);

    if (!ssh_session) {
        XLOGE("ReCreating Failed to create shared SSH session");
        return;
    }
    XLOGW("ReCreating Shared SSH session created successfully");

    // Setup hash table for SSH socket
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(ssh_session);
    hash_table = xhash_create(512, XHASH_KEY_INT);
    if (!hash_table) {
        XLOGE("ReCreating Failed to create hash table");
        wolfSSH_session_close(ssh_session);
        return;
    }

    // Register SSH socket events
    if (xpoll_add_event(ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                        ssh_read_cb, ssh_write_cb, ssh_error_cb, hash_table) != 0) {
        XLOGE("ReCreating Failed to register SSH socket event");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        return;
    }
    wolfSSH_channel_callback(ssh_session, ssh_channel_close_callback, ssh_channel_open_fini_callback, ssh_channel_open_fail_callback, hash_table);

    // reset
    g_ssh_session = ssh_session;
}

static void client_read_cb(SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;
    if( client->wlen > (sizeof(client->wbuf) * 3 / 4) )
        return;// wait send
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
    xhash* hash_table = xpoll_get_client_data(ssh_socket);
    char client_rbuf[8192];
    int n = recv(client->client_sock, client_rbuf, sizeof(client_rbuf), 0);
    if (n <= 0) {
        if(n < 0 && socket_check_eagain()) return;
        XLOGE("Client disconnected, fd=%d, err=%d", (int)client->client_sock, GET_ERRNO());
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        return;
    }
    if (!client->ssh_channel){
        XLOGE("ERROR: No SSH channel available");
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        return;
    }

    if (client->wlen > 0) {
        int buffer_space = sizeof(client->wbuf) - client->wlen;
        if (n > buffer_space) {
            XLOGE("ERROR: Buffer overflow. Available: %d, needed: %d, %s",
                   buffer_space, n, client->target_host);
            client->state = SOCKS5_STATE_ERROR;
            SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
            return;
        }
        memcpy(client->wbuf + client->wlen, client_rbuf, n);
        client->wlen += n;

        XLOGE("Appended %d bytes to write buffer, total buffered: %d bytes, %s",
               n, client->wlen, client->target_host);
    } else {
        int written = wolfSSH_channel_write(client->ssh_channel, client_rbuf, n);
        if (written < 0) {
            client->retry_error_count++;
            XLOGE("Failed to write to SSH channel: error count=%d, host=%s, errno=%d", client->retry_error_count, client->target_host, written);
            client->state = SOCKS5_STATE_ERROR;
        } else if (written == 0) {
            XLOGE("SSH channel not ready for write (EAGAIN), buffering %d bytes:%s...", n, client->target_host);
            if (n > sizeof(client->wbuf)) {
                XLOGE("ERROR: Buffer too small for %d bytes, dropping data:%s", n, client->target_host);
                client->state = SOCKS5_STATE_ERROR;
            } else {
                memcpy(client->wbuf, client_rbuf, n);
                client->wlen = n;
                XLOGD("Buffered %d bytes, will retry writing:%s", n, client->target_host);
                xpoll_add_event(ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
            }
        } else {
            client->retry_error_count = 0;
            XLOGD("SSH channel wrote %d bytes to %s", written, client->target_host);

            if (written < n) {
                int remaining = n - written;
                XLOGD("Partially written: %d/%d bytes, buffering remaining %d bytes:%s...",
                       written, n, remaining, client->target_host);

                if (remaining > sizeof(client->wbuf)) {
                    XLOGE("ERROR: Buffer too small for %d bytes, dropping data,%s", remaining, client->target_host);
                    client->state = SOCKS5_STATE_ERROR;
                } else {
                    memcpy(client->wbuf, client_rbuf + written, remaining);
                    client->wlen = remaining;
                    XLOGE("Buffered remaining %d bytes:%s", remaining, client->target_host);
                    xpoll_add_event(ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
                }
            }
        }
    }

    if( client->state == SOCKS5_STATE_ERROR )
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
}

static void client_write_cb(SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;
    if (!client || client->state != SOCKS5_STATE_CONNECTED) {
        xpoll_del_event(fd, XPOLL_WRITABLE);
        return;
    }

    if (client->rlen > 0) {
        int sent = send(fd, client->rbuf, client->rlen, 0);
        if (sent < 0) {
            if (!socket_check_eagain()) {
                XLOGE("client_write_cb: send error on fd=%d, err=%d", (int)fd, GET_ERRNO());
                client->state = SOCKS5_STATE_ERROR;
                SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
                xpoll_del_event(fd, XPOLL_WRITABLE);
            }
        } else if (sent < client->rlen) {
            memmove(client->rbuf, client->rbuf + sent, client->rlen - sent);
            client->rlen -= sent;
        } else {
            client->rlen = 0;
            xpoll_del_event(fd, XPOLL_WRITABLE);
        }
    } else {
        xpoll_del_event(fd, XPOLL_WRITABLE);
    }
}

static void client_error_cb(SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;
    XLOGE("client try close:%s, mask=%d", client->target_host, mask);

    if (client->state != SOCKS5_STATE_ERROR) {
        client->state = SOCKS5_STATE_ERROR;
        XLOGE("client closed %d-%d", (int)fd, (int)client->client_sock);
        socks5_client_cleanup(fd, client);
    } else {
        XLOGE("client closed1 %d-%d", (int)fd, (int)client->client_sock);
        socks5_client_cleanup(fd, client);
    }
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
            socks5_send_reply(client, SOCKS5_REP_TTL_EXPIRED);
            client->state = SOCKS5_STATE_ERROR;
            SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
            XLOGE("socks5_channel_retry_open retries reached, fd=%d, host=%s",
                  (int)client->client_sock, client->target_host);
            return false;
        }
    }
    return true;
}

void client_state_cb(SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;
    if (!client || client->state == SOCKS5_STATE_ERROR)
        return;

    switch (client->state) {
        case SOCKS5_STATE_AUTH:{
            int r = socks5_handle_handshake(client);
            if (r < 0) {
                client->state = SOCKS5_STATE_ERROR;
                break;
            }
            if (r == 0) break; // 数据不够，等下次

            // r == 1: handshake done，switch to REQUEST state
            client->state = SOCKS5_STATE_REQUEST;
            if (client->rlen == 0) break;
            if (socks5_client_auth(client) < 0)
                client->state = SOCKS5_STATE_ERROR;
            break;
        }
        case SOCKS5_STATE_REQUEST:
            if (socks5_client_auth(client) < 0)
                client->state = SOCKS5_STATE_ERROR;
            break;
        case SOCKS5_STATE_OPENING:
            socks5_channel_retry_open(client);
            break;
        case SOCKS5_STATE_CONNECTED:
            client_read_cb(fd, mask, clientData);
            break;
        default:
            break;
    }

    if (client->state == SOCKS5_STATE_ERROR)
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
}

static void accept_cb_single(SOCKET_T listen_fd, int mask, void *clientData) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    SOCKET_T client_sock = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock == INVALID_SOCKET) {
        if (g_server_running) {
            XLOGE("accept failed: %d", GET_ERRNO());
        }
        return;
    }

    if (g_active_connections >= MAX_CONCURRENT_CONNECTIONS) {
        XLOGE("Too many connections (%d), rejecting new connection", g_active_connections);
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

    if (true) {
        inet_ntop(AF_INET, &client_addr.sin_addr, client->client_host, sizeof(client->client_host));
        client->client_port = ntohs(client_addr.sin_port);
        XLOGW("New client connection from %s:%d, socket=%d",
                client->client_host, client->client_port, (int)client_sock);
    }

    if (xpoll_add_event(client_sock,
                        XPOLL_READABLE | XPOLL_ERROR | XPOLL_CLOSE,
                        client_state_cb, NULL, client_error_cb, client) != 0) {
        XLOGE("Failed to register client state event");
        socks5_client_free(client);
        free(client);
        CLOSE_SOCKET(client_sock);
        return;
    }
    client->state = SOCKS5_STATE_AUTH;
    socks5_client_stage(client);

    g_active_connections++;
    XLOGD("New client registered, active connections: %d", g_active_connections);
}

static bool socks5_channel_each_reopen(xhashKey k, void* value, void* ud) {
    (void)ud;
    Socks5Client *client = (Socks5Client*)value;
    socks5_channel_retry_open(client);
    return true;
}

static void handle_ssh_session_error() {
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
    xhash* hash_table = (xhash*)xpoll_get_client_data(ssh_socket);
    if (hash_table) {
        ssh_error_cb(ssh_socket, XPOLL_ERROR | XPOLL_CLOSE, hash_table);
    }
}

void socks5_server_update() {
    static long64 last_keepalive = 0;
    long64 now = time_get_ms()/1000;
    if (now - last_keepalive >= 15) {
        last_keepalive = now;
        if (g_ssh_session) {
            // wolfSSH doesn't have direct keepalive, send ignore packet instead
            int rc = wolfSSH_session_keepalive(g_ssh_session);
            if (rc < 0) {
                XLOGE("keepalive error: %d", rc);
                XLOGE("keepalive error: %d", rc);
                XLOGE("keepalive error: %d", rc);
                handle_ssh_session_error();
                return;
            }
        }
        XLOGI("keepalive success %lld", time_get_ms());

        if(!g_ssh_session) {
            // Create shared SSH session
            const Socks5ServerConfig* config = &g_server_config;
            WOLFSSH *ssh_session = wolfSSH_session_open(
                config->ssh_host,
                config->ssh_port,
                config->ssh_username,
                config->ssh_password);

            if (!ssh_session) {
                XLOGE("ReCreating Failed to create shared SSH session");
                return;
            }
            XLOGW("ReCreating Shared SSH session created successfully");

            // Setup hash table for SSH socket
            SOCKET_T ssh_socket = wolfSSH_session_get_socket(ssh_session);
            xhash* hash_table = xhash_create(512, XHASH_KEY_INT);
            if (!hash_table) {
                XLOGE("ReCreating Failed to create hash table");
                wolfSSH_session_close(ssh_session);
                return;
            }

            // Register SSH socket events
            if (xpoll_add_event(ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                                ssh_read_cb, ssh_write_cb, ssh_error_cb, hash_table) != 0) {
                XLOGE("ReCreating Failed to register SSH socket event");
                xhash_destroy(hash_table, false);
                wolfSSH_session_close(ssh_session);
                return;
            }
            wolfSSH_channel_callback(ssh_session, ssh_channel_close_callback, ssh_channel_open_fini_callback, ssh_channel_open_fail_callback, hash_table);

            // reset
            g_ssh_session = ssh_session;
        }
    }

    if (g_ssh_session) {
        SOCKET_T ssh_sock = wolfSSH_session_get_socket(g_ssh_session);
        xhash* hash = (xhash*)xpoll_get_client_data(ssh_sock);
        if(hash)
            xhash_foreach(hash, socks5_channel_each_reopen, NULL);
    }
}

int socks5_server_start(const Socks5ServerConfig* config) {
    if (!config)
        return -1;

    // Initialize server configuration
    memcpy(&g_server_config, config, sizeof(Socks5ServerConfig));

    // Create shared SSH session
    XLOGI("Creating shared SSH session to %s:%d...", config->ssh_host, config->ssh_port);
    WOLFSSH *ssh_session = wolfSSH_session_open(
        config->ssh_host,
        config->ssh_port,
        config->ssh_username,
        config->ssh_password);

    if (!ssh_session) {
        XLOGE("Failed to create shared SSH session");
        return -1;
    }
    XLOGI("Shared SSH session created successfully");

    // Setup hash table for SSH socket
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(ssh_session);
    xhash *hash_table = xhash_create(512, XHASH_KEY_INT);
    if (!hash_table) {
        XLOGE("Failed to create hash table");
        wolfSSH_session_close(ssh_session);
        return -1;
    }

    // Register SSH socket events
    if (xpoll_add_event(ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                        ssh_read_cb, ssh_write_cb, ssh_error_cb, hash_table) != 0) {
        XLOGE("Failed to register SSH socket event");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        return -1;
    }

    // Create listening socket
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock == INVALID_SOCKET) {
        XLOGE("listen socket creation failed");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
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
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Listen
    if (listen(g_listen_sock, SOMAXCONN) < 0) {
        XLOGE("listen failed");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Register listening socket event
    if (xpoll_add_event(g_listen_sock, XPOLL_READABLE,
                        (xFileProc)accept_cb_single, NULL, NULL, NULL) != 0) {
        XLOGE("Failed to register listen socket event");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }
    wolfSSH_channel_callback(ssh_session, ssh_channel_close_callback, ssh_channel_open_fini_callback, ssh_channel_open_fail_callback, hash_table);

    // Set shared SSH session
    g_ssh_session = ssh_session;

    // Set server running flag
    g_server_running = 1;

    XLOGI("SOCKS5 proxy is running...");
    XLOGI("Listen address: %s:%d", config->bind_address, config->bind_port);
    XLOGI("SSH tunnel: %s:%d (user: %s)", config->ssh_host, config->ssh_port, config->ssh_username);
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
            xhash_destroy(hash, false);
        }
    }

    g_server_running = 0;
    g_ssh_session = NULL;
    XLOGW("[socks5] socks5 service stoped");
}
