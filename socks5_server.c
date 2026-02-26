#include "socks5_server.h"
#include "socket_util.h"
#include "ssh_tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xpoll.h"
#include "xhash.h"

#define MAX_CONCURRENT_CONNECTIONS 8192
#define MAX_ERROR_COUNT 10
#define MAX_REOPEN_COUNT 30
#define XLOG_PRINT(fd, ...) {fprintf(fd, __VA_ARGS__); fflush(fd);}

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;
static int g_active_connections = 0;
static xPollState *g_xpoll = NULL;
static WOLFSSH *g_ssh_session = NULL;

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
    char read_buffer[131070]; // ssh read
    char write_buffer[65535];// ssh write
    int write_buffer_size;
    int read_buffer_size;

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

static int socks5_handle_handshake(Socks5Client* client) {
    uint8_t buf[4096];
    int n = recv(client->client_sock, (char*)buf, sizeof(buf), 0);
    if (n < 3) return -1;
    if (buf[0] != 0x05) return -1;

    uint8_t nmethods = buf[1];
    XLOG_PRINT(stderr, "SOCKS5 handshake: version=0x%02X, nmethods=%d\n", buf[0], nmethods);
    if (n < 2 + nmethods) return -1;

    uint8_t selected_method = 0xFF;
    for (int i = 0; i < nmethods; i++) {
        XLOG_PRINT(stderr, "  Method %d: 0x%02X\n", i, buf[2 + i]);
        if (buf[2 + i] == SOCKS5_AUTH_NONE) {
            selected_method = SOCKS5_AUTH_NONE;
            break;
        }
    }

    if (selected_method == 0xFF) {
        XLOG_PRINT(stderr, "No acceptable authentication method found\n");
        uint8_t response[2] = {0x05, SOCKS5_AUTH_NO_ACCEPTABLE};
        send(client->client_sock,  (const char*)response, 2, 0);
        return -1;
    }

    XLOG_PRINT(stderr, "Selected authentication method: 0x%02X\n", selected_method);
    uint8_t response[2] = {0x05, selected_method};
    if (send(client->client_sock,  (const char*)response, 2, 0) != 2) return -1;

    client->auth_method = selected_method;
    return 0;
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

static void ssh_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData);
static void ssh_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData);
static void socks5_client_stage(Socks5Client* client) {
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
    void* ud = xpoll_get_client_data(g_xpoll, ssh_socket);
    if (ud) {
        xhash *hash_table = (xhash*)ud;
        xhash_set_int(hash_table, (long)client->client_sock, client);
        XLOG_PRINT(stderr, "Client fd=%d added to SSH socket hash table\n", (int)client->client_sock);
        if (xhash_size(hash_table) == 1) {
            xpoll_add_event(g_xpoll, ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                            ssh_read_cb, NULL, ssh_error_cb, hash_table);
            XLOG_PRINT(stderr, "SSH socket fd=%d added to XPOLL_ALL event\n", (int)ssh_socket);
        }
    }
}

static int socks5_client_auth(Socks5Client* client) {
    uint8_t buf[4096];
    int n = recv(client->client_sock, (char*)buf, sizeof(buf), 0);
    if (n < 10) return -1;
    if (buf[0] != 0x05) return -1;

    client->cmd = buf[1];
    if (client->cmd != SOCKS5_CMD_CONNECT) {
        socks5_send_reply(client, SOCKS5_REP_COMMAND_NOT_SUPPORTED);
        return -1;
    }

    uint8_t atyp = buf[3];
    XLOG_PRINT(stderr, "SOCKS5 request: cmd=0x%02X, atyp=0x%02X\n", buf[1], atyp);

    char target_host[256];
    uint16_t target_port;
    int pos = 4;

    if (atyp == SOCKS5_ATYP_IPV4) {
        XLOG_PRINT(stderr, "ATYP: IPv4\n");
        if (n < pos + 6) return -1;
        struct in_addr addr;
        memcpy(&addr, &buf[pos], 4);
        inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
        pos += 4;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        uint8_t domain_len = buf[pos++];
        XLOG_PRINT(stderr, "ATYP: Domain name, length=%d, fd=%d\n", domain_len, (int)client->client_sock);
        if (n < pos + domain_len + 2) return -1;
        if (domain_len >= sizeof(target_host)) return -1;
        memcpy(target_host, &buf[pos], domain_len);
        target_host[domain_len] = '\0';
        pos += domain_len;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        XLOG_PRINT(stderr, "ATYP: IPv6\n");
        if (n < pos + 18) return -1;
        struct in6_addr addr6;
        memcpy(&addr6, &buf[pos], 16);
        inet_ntop(AF_INET6, &addr6, target_host, sizeof(target_host));
        pos += 16;
    } else {
        XLOG_PRINT(stderr, "ATYP not supported: 0x%02X\n", atyp);
        socks5_send_reply(client, SOCKS5_REP_ADDRESS_NOT_SUPPORTED);
        return -1;
    }

    target_port = ntohs(*(uint16_t*)&buf[pos]);
    strncpy(client->target_host, target_host, sizeof(client->target_host) - 1);
    client->target_port = target_port;
    XLOG_PRINT(stderr, "SOCKS5 request: connect to %s:%d, fd=%d\n", target_host, target_port, (int)client->client_sock);

    if (!client->ssh_session) {
        XLOG_PRINT(stderr, "SSH session not available\n");
        socks5_send_reply(client, SOCKS5_REP_GENERAL_FAILURE);
        return -1;
    }

    client->state = SOCKS5_STATE_OPENING;
    client->ssh_channel = wolfSSH_channel_open(client->ssh_session,
                                                   client->target_host, client->target_port,
                                                   client->client_host, client->client_port);
    if (!client->ssh_channel) {
        client->last_retry_time = time_get_ms() + 200;
        XLOG_PRINT(stderr, "Failed to open SSH channel\n");
        return 0;// for retry
    }

    client->state = SOCKS5_STATE_CONNECTED;
    //socks5_send_reply(client, SOCKS5_REP_SUCCESS);
    socks5_client_stage(client);
    return 0;
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

static void socks5_client_cleanup(xPollState *loop, SOCKET_T fd, Socks5Client *client) {
    if (!client) return;
    // unreg ev
    xpoll_del_event(loop, client->client_sock, XPOLL_ALL);

    if (g_ssh_session) {
        SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
        xhash* hash = xpoll_get_client_data(loop, ssh_socket);

        if (hash) {
            xhash_remove_int(hash, (long)client->client_sock, false);

            if (xhash_size(hash) <= 0) {
                xpoll_del_event(g_xpoll, ssh_socket, XPOLL_READABLE);
                XLOG_PRINT(stderr, "SSH socket fd=%d remove XPOLL_ALL event\n", (int)ssh_socket);
            }
        }
    }

    socks5_client_free(client);
    free(client);

    g_active_connections--;
    XLOG_PRINT(stderr, "Active connections: %d (connection closed)\n", g_active_connections);
}

static bool ssh_read_each_client(xhashNode *node, void* ud) {
    (void)ud;
    // Get client from hash node
    Socks5Client *client = (Socks5Client*)node->value;
    if (!client || client->state != SOCKS5_STATE_CONNECTED || !client->ssh_channel) {
        return true;  // Continue to next client
    }

    // If client state is ERROR, clean up immediately and remove from hash table
    if (client->state == SOCKS5_STATE_ERROR) {
        XLOG_PRINT(stderr, "Cleaning up error client fd=%d\n", (int)client->client_sock);
        // socks5_client_cleanup(g_xpoll, client->client_sock, client);
        return true;
    }

    if (client->read_buffer_size < 0 || client->read_buffer_size >= sizeof(client->read_buffer)) {
        XLOG_PRINT(stderr, "Warning: Invalid read_buffer_size=%d, resetting to 0 for fd=%d\n",
                   client->read_buffer_size, (int)client->client_sock);
        client->read_buffer_size = 0;
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        return true;
    }

    if (client->write_buffer_size < 0 || client->write_buffer_size >= sizeof(client->write_buffer)) {
        XLOG_PRINT(stderr, "Warning: Invalid write_buffer_size=%d, resetting to 0 for fd=%d\n",
                   client->write_buffer_size, (int)client->client_sock);
        client->write_buffer_size = 0;
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
                                client->read_buffer+client->read_buffer_size,
                                sizeof(client->read_buffer)-client->read_buffer_size);
    if (n > 0) {
        // Successfully read, send to client
        int total = n + client->read_buffer_size;
        int sent = send(client->client_sock, client->read_buffer, total, 0);
        if (sent != total) {
            if (sent <= 0 ){
                if(socket_check_eagain()) {
                    XLOG_PRINT(stderr, "Channel send failed %d bytes to client fd=%d (sent=%d), eagain got\n",
                           n, (int)client->client_sock, sent);
                } else {
                    client->state = SOCKS5_STATE_ERROR;
                    XLOG_PRINT(stderr, "Channel send failed %d bytes to client fd=%d (sent=%d), close got\n",
                           n, (int)client->client_sock, sent);
                }
            } else {
                if (sent > 0 && sent < total) {
                    memmove(client->read_buffer, client->read_buffer + sent, total - sent);
                    client->read_buffer_size = total - sent;
                    XLOG_PRINT(stderr, "Channel data send %d bytes to client fd=%d (sent=%d)\n",
                           n, (int)client->client_sock, sent);
                } else {
                    XLOG_PRINT(stderr, "Invalid sent value %d, resetting buffer\n", sent);
                    client->read_buffer_size = 0;
                }
            }
        } else {
            // Check if channel is EOF
            client->read_buffer_size = 0;
            if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
                XLOG_PRINT(stderr, "Channel read finished && EOF for fd=%d\n", (int)client->client_sock);
                client->state = SOCKS5_STATE_ERROR;
            }
        }
    } else if (n < 0) {
        if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
            client->state = SOCKS5_STATE_ERROR;
        } else {
            XLOG_PRINT(stderr, "Channel read failed for fd=%d, n=%d\n", (int)client->client_sock, n);
            client->state = SOCKS5_STATE_ERROR;
        }
        return true;
    } else {
        if (wolfSSH_channel_eof(client->ssh_channel)!=0) {
            XLOG_PRINT(stderr, "Channel closed by remote fd=%d\n", (int)client->client_sock);
            client->state = SOCKS5_STATE_ERROR;
        }
    }

    if( client->state == SOCKS5_STATE_ERROR )
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);

    return true;
}

static void ssh_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    static int call_count = 0;
    call_count++;

    xhash *hash_table = (xhash*)clientData;
    if (!hash_table) {
        XLOG_PRINT(stderr, "ERROR: ssh_read_cb called with NULL hash table!\n");
        return;
    }

    if (!g_ssh_session) {
        return;
    }

    word32 channelId = 0;
    int ret = wolfSSH_worker(g_ssh_session, &channelId);
    if (ret < 0 && ret != WS_CHAN_RXD && ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
        int error = wolfSSH_get_error(g_ssh_session);
        if (error == WS_SOCKET_ERROR_E || error == WS_FATAL_ERROR) {
            XLOG_PRINT(stderr, "wolfSSH_worker fatal error: %d\n", error);
            ssh_error_cb(loop, fd, XPOLL_ERROR, clientData);
            return;
        } else if(error != WS_CHANOPEN_FAILED && WS_INVALID_CHANID != error) {
            XLOG_PRINT(stderr, "wolfSSH_worker error: %d-%s\n", error, wolfSSH_ErrorToName(error));
        }
    }

    xhash_foreach(hash_table, ssh_read_each_client, NULL);
}

static bool ssh_write_each_client(xhashNode *node, void * ctx) {
    // Get client from hash node
    Socks5Client *client = (Socks5Client*)node->value;

    if (!client || client->state != SOCKS5_STATE_CONNECTED ||
        !client->ssh_channel || client->write_buffer_size == 0) {
        return true;  // Continue to next client
    }

    if (client->ssh_session && client->ssh_channel) {
        if (wolfSSH_channel_eof(client->ssh_channel) != 0) {
            client->state = SOCKS5_STATE_ERROR;
            SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
            return true;
        }
    }

    int remaining = client->write_buffer_size;
    int written = wolfSSH_channel_write(client->ssh_channel,
                                    client->write_buffer,
                                    remaining);
    if (written < 0) {
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        XLOG_PRINT(stderr, "Channel write failed, fd=%d, host=%s\n",
               (int)client->client_sock, client->target_host);
    } else if (written >= remaining) {
        // All data has been written
        client->write_buffer_size = 0;
        XLOG_PRINT(stderr, "All buffered data (%d bytes) written for fd=%d\n",
               written, (int)client->client_sock);
    } else if(written != 0) {
        // Partial write
        memmove(client->write_buffer, client->write_buffer + written, remaining - written);
        client->write_buffer_size = remaining - written;
        XLOG_PRINT(stderr, "Partially buffered data written: %d/%d bytes for fd=%d\n",
               written, remaining - written, (int)client->client_sock);
         *(int*)ctx = 1;
    } else {
        *(int*)ctx = 1;
    }

    return true;  // Continue to next client
}

static void ssh_write_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table)
        return;

    static int _call_count = 0;
    _call_count++;

    if (_call_count % 10000 == 0) {
        XLOG_PRINT(stderr, "ssh_write_cb called (count=%d, mask=%d)\n", _call_count, mask);
    }

    int has_data = 0;
    xhash_foreach(hash_table, ssh_write_each_client, &has_data);
    if( has_data==0 )
        xpoll_del_event(loop, fd, XPOLL_WRITABLE);
}

static bool client_on_closed(xhashNode *node, void *ctx) {
    Socks5Client *client = (Socks5Client*)node->value;
    if (!client) return true;
    if(!ctx) {
        socks5_client_cleanup(g_xpoll, client->client_sock, client);
    } else if(client->state==SOCKS5_STATE_ERROR) {
        socks5_client_cleanup(g_xpoll, client->client_sock, client);
    }
    return true;
}

static bool client_channel_confirm(xhashNode* node, void* channel_ptr) {
    Socks5Client *client = (Socks5Client*)node->value;
    WOLFSSH_CHANNEL* channel = (WOLFSSH_CHANNEL*)channel_ptr;
    if (client->ssh_channel == channel) {
        socks5_send_reply(client, SOCKS5_REP_SUCCESS);
        return false;
    }
    return true;
}

static bool client_channel_refuse(xhashNode* node, void* channel_ptr) {
    Socks5Client *client = (Socks5Client*)node->value;
    WOLFSSH_CHANNEL* channel = (WOLFSSH_CHANNEL*)channel_ptr;
    if (client->ssh_channel == channel) {
        client->ssh_channel = NULL;
        client->state = SOCKS5_STATE_ERROR;
        socks5_send_reply(client, SOCKS5_REP_CONNECTION_REFUSED);
        XLOG_PRINT(stderr, "SSH channel refuse connect, fd=%d, host=%s\n", (int)client->client_sock, client->target_host);
        return false;
    }
    return true;
}

static bool client_channel_closed(xhashNode* node, void* channel_ptr) {
    Socks5Client *client = (Socks5Client*)node->value;
    WOLFSSH_CHANNEL* channel = (WOLFSSH_CHANNEL*)channel_ptr;
    if (client->ssh_channel == channel) {
        client->ssh_channel = NULL;
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        XLOG_PRINT(stderr, "Marked client as error due to SSH channel close, fd=%d, host=%s\n", (int)client->client_sock, client->target_host);
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
    XLOG_PRINT(stderr, "ssh channel opened:%p\n", channel);
    xhash* hash = (xhash*)ctx;
    if (hash)
        xhash_foreach(hash, client_channel_confirm, channel);
    return WS_SUCCESS;
}

static int ssh_channel_open_fail_callback(WOLFSSH_CHANNEL* channel, void* ctx) {
    xhash* hash = (xhash*)ctx;
    if (hash)
        xhash_foreach(hash, client_channel_refuse, channel);
    return WS_SUCCESS;
}

static void ssh_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table)
        return;
    XLOG_PRINT(stderr, "ssh_error_cb called (fd=%d)\n", (int)fd);
    XLOG_PRINT(stderr, "ssh_error_cb called (fd=%d)\n", (int)fd);
    XLOG_PRINT(stderr, "ssh_error_cb called (fd=%d)\n", (int)fd);

    xhash_foreach(hash_table, client_on_closed, NULL);
    xpoll_del_event(loop, fd, XPOLL_ALL);
    wolfSSH_session_close(g_ssh_session);
    g_ssh_session = NULL;

    // Create shared SSH session
    const Socks5ServerConfig* config = &g_server_config;
    WOLFSSH *ssh_session = wolfSSH_session_open(
        config->ssh_host,
        config->ssh_port,
        config->ssh_username,
        config->ssh_password);

    if (!ssh_session) {
        XLOG_PRINT(stderr, "ReCreating Failed to create shared SSH session\n");
        return;
    }
    XLOG_PRINT(stderr, "ReCreating Shared SSH session created successfully\n");

    // Setup hash table for SSH socket
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(ssh_session);
    hash_table = xhash_create(1024);
    if (!hash_table) {
        XLOG_PRINT(stderr, "ReCreating Failed to create hash table\n");
        wolfSSH_session_close(ssh_session);
        return;
    }

    // Register SSH socket events
    if (xpoll_add_event(loop, ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                        ssh_read_cb, ssh_write_cb, ssh_error_cb, hash_table) != 0) {
        XLOG_PRINT(stderr, "ReCreating Failed to register SSH socket event\n");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        return;
    }
    wolfSSH_channel_callback(ssh_session, ssh_channel_close_callback, ssh_channel_open_fini_callback, ssh_channel_open_fail_callback, hash_table);

    // reset
    g_ssh_session = ssh_session;
}

static void client_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;

    SOCKET_T ssh_socket = wolfSSH_session_get_socket(client->ssh_session);
    xhash* hash_table = xpoll_get_client_data(loop, ssh_socket);
    char client_rbuf[8192];
    int n = recv(client->client_sock, client_rbuf, sizeof(client_rbuf), 0);
    if (n <= 0) {
        if(socket_check_eagain()) return;
        XLOG_PRINT(stderr, "Client disconnected\n");
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        return;
    }
    if (!client->ssh_channel){
        XLOG_PRINT(stderr, "ERROR: No SSH channel available\n");
        client->state = SOCKS5_STATE_ERROR;
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
        return;
    }

    if (client->write_buffer_size > 0) {
        int buffer_space = sizeof(client->write_buffer) - client->write_buffer_size;
        if (n > buffer_space) {
            XLOG_PRINT(stderr, "ERROR: Buffer overflow. Available: %d, needed: %d, %s\n",
                   buffer_space, n, client->target_host);
            client->state = SOCKS5_STATE_ERROR;
            SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
            return;
        }
        memcpy(client->write_buffer + client->write_buffer_size, client_rbuf, n);
        client->write_buffer_size += n;

        XLOG_PRINT(stderr, "Appended %d bytes to write buffer, total buffered: %d bytes, %s\n",
               n, client->write_buffer_size, client->target_host);
    } else {
        int written = wolfSSH_channel_write(client->ssh_channel, client_rbuf, n);
        if (written < 0) {
            client->retry_error_count++;
            XLOG_PRINT(stderr, "Failed to write to SSH channel: error count=%d, host=%s, errno=%d\n", client->retry_error_count, client->target_host, written);
            client->state = SOCKS5_STATE_ERROR;
        } else if (written == 0) {
            XLOG_PRINT(stderr, "SSH channel not ready for write (EAGAIN), buffering %d bytes:%s...\n", n, client->target_host);
            if (n > sizeof(client->write_buffer)) {
                XLOG_PRINT(stderr, "ERROR: Buffer too small for %d bytes, dropping data:%s\n", n, client->target_host);
                client->state = SOCKS5_STATE_ERROR;
            } else {
                memcpy(client->write_buffer, client_rbuf, n);
                client->write_buffer_size = n;
                XLOG_PRINT(stderr, "Buffered %d bytes, will retry writing:%s\n", n, client->target_host);
                xpoll_add_event(loop, ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
            }
        } else {
            client->retry_error_count = 0;
            XLOG_PRINT(stderr, "SSH channel wrote %d bytes to %s\n", written, client->target_host);

            if (written < n) {
                int remaining = n - written;
                XLOG_PRINT(stderr, "Partially written: %d/%d bytes, buffering remaining %d bytes:%s...\n",
                       written, n, remaining, client->target_host);

                if (remaining > sizeof(client->write_buffer)) {
                    XLOG_PRINT(stderr, "ERROR: Buffer too small for %d bytes, dropping data,%s\n", remaining, client->target_host);
                    client->state = SOCKS5_STATE_ERROR;
                } else {
                    memcpy(client->write_buffer, client_rbuf + written, remaining);
                    client->write_buffer_size = remaining;
                    XLOG_PRINT(stderr, "Buffered remaining %d bytes:%s\n", remaining, client->target_host);
                    xpoll_add_event(loop, ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
                }
            }
        }
    }

    if( client->state == SOCKS5_STATE_ERROR )
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
}

static void client_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;
    XLOG_PRINT(stderr, "client try close:%s, mask=%d\n", client->target_host, mask);

    if (client->state != SOCKS5_STATE_ERROR) {
        client->state = SOCKS5_STATE_ERROR;
        XLOG_PRINT(stderr, "client closed %d-%d\n", (int)fd, (int)client->client_sock);
        socks5_client_cleanup(loop, fd, client);
    } else {
        XLOG_PRINT(stderr, "client closed1 %d-%d\n", (int)fd, (int)client->client_sock);
        socks5_client_cleanup(loop, fd, client);
    }
}

static bool socks5_channel_retry_open(Socks5Client *client) {
    if (SOCKS5_STATE_OPENING != client->state) return false;
    if (time_get_ms() < client->last_retry_time) return false;

    client->ssh_channel = wolfSSH_channel_open(client->ssh_session,
                                               client->target_host, client->target_port,
                                               client->client_host, client->client_port);
    client->last_retry_time = time_get_ms() + 200;

    if (!client->ssh_channel) {
        client->retry_error_count++;
        if (client->retry_error_count > MAX_REOPEN_COUNT) {
            socks5_send_reply(client, SOCKS5_REP_TTL_EXPIRED);
            client->state = SOCKS5_STATE_ERROR;
            SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
            XLOG_PRINT(stderr, "socks5_channel_retry_open retries reached, fd=%d, host=%s\n", (int)client->client_sock, client->target_host);
            XLOG_PRINT(stderr, "socks5_channel_retry_open retries reached, fd=%d, host=%s\n", (int)client->client_sock, client->target_host);
            XLOG_PRINT(stderr, "socks5_channel_retry_open retries reached, fd=%d, host=%s\n", (int)client->client_sock, client->target_host);
            return false;
        }
    } else {
        client->retry_error_count = 0;
        client->state = SOCKS5_STATE_CONNECTED;
        //socks5_send_reply(client, SOCKS5_REP_SUCCESS);
        socks5_client_stage(client);
    }
    return true;
}

void client_state_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;
    if (!client || client->state == SOCKS5_STATE_ERROR)
        return;

    switch (client->state) {
        case SOCKS5_STATE_AUTH:
            if (socks5_handle_handshake(client) == 0) {
                client->state = SOCKS5_STATE_REQUEST;  // 移动到认证状态
            } else {
                client->state = SOCKS5_STATE_ERROR;
            }
            break;
        case SOCKS5_STATE_REQUEST:
            if (socks5_client_auth(client) != 0) {
                client->state = SOCKS5_STATE_ERROR;
            }
            break;
        case SOCKS5_STATE_OPENING:
            socks5_channel_retry_open(client);
            break;
        case SOCKS5_STATE_CONNECTED:
            client_read_cb(loop, fd, mask, clientData);
            break;
        default:
            break;
    }

    if (client->state == SOCKS5_STATE_ERROR)
        SHUTDOWN_SOCKET(client->client_sock, SHUTDOWN_WR);
}

static void accept_cb_single(xPollState *loop, SOCKET_T listen_fd, int mask, void *clientData) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    SOCKET_T client_sock = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock == INVALID_SOCKET) {
        if (g_server_running) {
            XLOG_PRINT(stderr, "accept failed: %d\n", WSAGetLastError());
        }
        return;
    }

    if (g_active_connections >= MAX_CONCURRENT_CONNECTIONS) {
        XLOG_PRINT(stderr, "Too many connections (%d), rejecting new connection\n", g_active_connections);
        CLOSE_SOCKET(client_sock);
        return;
    }
    socket_set_nonblocking(client_sock);
    socket_set_keepalive(client_sock, 30, 5, 5);

    Socks5Client *client = (Socks5Client*)malloc(sizeof(Socks5Client));
    if (!client) {
        XLOG_PRINT(stderr, "client malloc failed...\n");
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
        XLOG_PRINT(stderr, "New client connection from %s:%d, socket=%d\n",
                client->client_host, client->client_port, (int)client_sock);
    }

    if (xpoll_add_event(g_xpoll, client_sock,
                        XPOLL_READABLE | XPOLL_ERROR | XPOLL_CLOSE,
                        client_state_cb, NULL, client_error_cb, client) != 0) {
        XLOG_PRINT(stderr, "Failed to register client state event\n");
        socks5_client_free(client);
        free(client);
        CLOSE_SOCKET(client_sock);
        return;
    }
    client->state = SOCKS5_STATE_AUTH;

    g_active_connections++;
    XLOG_PRINT(stderr, "New client registered, active connections: %d\n", g_active_connections);
}

static bool socks5_channel_each_reopen(xhashNode *node, void* ud) {
    (void)ud;
    Socks5Client *client = (Socks5Client*)node->value;
    socks5_channel_retry_open(client);
    return true;
}

static void handle_ssh_session_error() {
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(g_ssh_session);
    xhash* hash_table = (xhash*)xpoll_get_client_data(g_xpoll, ssh_socket);
    if (hash_table)
        ssh_error_cb(g_xpoll, ssh_socket, XPOLL_ERROR | XPOLL_CLOSE, hash_table);
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
                XLOG_PRINT(stderr, "keepalive error: %d\n", rc);
                XLOG_PRINT(stderr, "keepalive error: %d\n", rc);
                XLOG_PRINT(stderr, "keepalive error: %d\n", rc);
                handle_ssh_session_error();
                return;
            }
        }
        XLOG_PRINT(stderr, "keepalive success %lld\n", time_get_ms());
    }

    if (g_ssh_session) {
        SOCKET_T ssh_sock = wolfSSH_session_get_socket(g_ssh_session);
        xhash* hash = (xhash*)xpoll_get_client_data(g_xpoll, ssh_sock);
        if(hash)
            xhash_foreach(hash, socks5_channel_each_reopen, NULL);
    }
}

int socks5_server_start(const Socks5ServerConfig* config, xPollState *xpoll) {
    if (!config || !xpoll)
        return -1;

    // Initialize server configuration
    memcpy(&g_server_config, config, sizeof(Socks5ServerConfig));

    // Create shared SSH session
    XLOG_PRINT(stdout, "Creating shared SSH session to %s:%d...\n", config->ssh_host, config->ssh_port);
    WOLFSSH *ssh_session = wolfSSH_session_open(
        config->ssh_host,
        config->ssh_port,
        config->ssh_username,
        config->ssh_password);

    if (!ssh_session) {
        XLOG_PRINT(stderr, "Failed to create shared SSH session\n");
        return -1;
    }
    XLOG_PRINT(stdout, "Shared SSH session created successfully\n");

    // Setup hash table for SSH socket
    SOCKET_T ssh_socket = wolfSSH_session_get_socket(ssh_session);
    xhash *hash_table = xhash_create(20);
    if (!hash_table) {
        XLOG_PRINT(stderr, "Failed to create hash table\n");
        wolfSSH_session_close(ssh_session);
        return -1;
    }

    // Register SSH socket events
    if (xpoll_add_event(xpoll, ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                        ssh_read_cb, ssh_write_cb, ssh_error_cb, hash_table) != 0) {
        XLOG_PRINT(stderr, "Failed to register SSH socket event\n");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        return -1;
    }

    // Create listening socket
    SOCKET_T listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        XLOG_PRINT(stderr, "listen socket creation failed\n");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        return -1;
    }

    // // Set SO_REUSEADDR
    // int opt = 1;
    // setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // Bind address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = config->bind_address ?
        inet_addr(config->bind_address) : INADDR_ANY;
    server_addr.sin_port = htons(config->bind_port);

    if (bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        XLOG_PRINT(stderr, "bind failed");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        CLOSE_SOCKET(listen_sock);
        return -1;
    }

    // Listen
    if (listen(listen_sock, SOMAXCONN) < 0) {
        XLOG_PRINT(stderr, "listen failed");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        CLOSE_SOCKET(listen_sock);
        return -1;
    }

    // Register listening socket event
    if (xpoll_add_event(xpoll, listen_sock, XPOLL_READABLE,
                        (xFileProc)accept_cb_single, NULL, NULL, NULL) != 0) {
        XLOG_PRINT(stderr, "Failed to register listen socket event\n");
        xhash_destroy(hash_table, false);
        wolfSSH_session_close(ssh_session);
        CLOSE_SOCKET(listen_sock);
        return -1;
    }
    wolfSSH_channel_callback(ssh_session, ssh_channel_close_callback, ssh_channel_open_fini_callback, ssh_channel_open_fail_callback, hash_table);

    // Set xpoll instance
    g_xpoll = xpoll;

    // Set shared SSH session
    g_ssh_session = ssh_session;

    // Set server running flag
    g_server_running = 1;

    XLOG_PRINT(stdout, "SOCKS5 proxy is running...\n");
    XLOG_PRINT(stdout, "Listen address: %s:%d\n", config->bind_address, config->bind_port);
    XLOG_PRINT(stdout, "SSH tunnel: %s:%d (user: %s)\n", config->ssh_host, config->ssh_port, config->ssh_username);
    XLOG_PRINT(stdout, "Using %s for I/O multiplexing\n", xpoll_name());

    return 0;
}

void socks5_server_stop(void) {
    if(g_server_running==0) return;

    SOCKET_T ssh_sock = wolfSSH_session_get_socket(g_ssh_session);
    xhash* hash = (xhash*)xpoll_get_client_data(g_xpoll, ssh_sock);
    if(hash) {
        xhash_foreach(hash, client_on_closed, NULL);
        xhash_destroy(hash, false);
    }

    g_server_running = 0;
}
