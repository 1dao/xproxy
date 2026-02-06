#include "socks5_server.h"
#include "libssh2/include/libssh2.h"
#include "socket_util.h"
#include "ssh_tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xpoll.h"
#include "xhash.h"

#define MAX_CONCURRENT_CONNECTIONS 8192
#define MAX_ERROR_COUNT 10

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;
static int g_active_connections = 0;
static xPollState *g_xpoll = NULL;
static LIBSSH2_SESSION *g_ssh_session = NULL;

typedef struct {
    SOCKET_T client_sock;
    Socks5ClientState state;
    uint8_t auth_method;
    char target_host[256];
    uint16_t target_port;
    uint8_t cmd;
    LIBSSH2_SESSION *ssh_session;  // Thread-level SSH session
    LIBSSH2_CHANNEL *ssh_channel;  // Current SSH channel
    char client_host[256];
    uint16_t client_port;

    // IO buffers and state
    char read_buffer[8192];
    char write_buffer[8192];
    int write_buffer_size;
    int write_error_count;
} Socks5Client;

void socks5_send_reply(Socks5Client* client, uint8_t rep) {
    uint8_t response[10] = {0};
    response[0] = 0x05;  // SOCKS version 5
    response[1] = rep;   // Reply field
    response[2] = 0x00;  // Reserved
    response[3] = 0x01;  // ATYP: IPv4
    // DST.ADDR: 0.0.0.0
    response[4] = 0x00;
    response[5] = 0x00;
    response[6] = 0x00;
    response[7] = 0x00;
    // DST.PORT: 0
    response[8] = 0x00;
    response[9] = 0x00;

    int sent = send(client->client_sock, response, 10, 0);
    if (sent != 10) {
        fprintf(stderr, "Failed to send SOCKS5 reply: sent %d bytes\n", sent);
    } else {
        fprintf(stderr, "SOCKS5 reply sent successfully (rep: 0x%02X)\n", rep);
    }
}

int socks5_handle_handshake(Socks5Client* client) {
    uint8_t buf[4096];
    int n = recv(client->client_sock, buf, sizeof(buf), 0);
    if (n < 3) return -1;
    if (buf[0] != 0x05) return -1;

    uint8_t nmethods = buf[1];
    fprintf(stderr, "SOCKS5 handshake: version=0x%02X, nmethods=%d\n", buf[0], nmethods);

    if (n < 2 + nmethods) return -1;

    uint8_t selected_method = 0xFF;
    for (int i = 0; i < nmethods; i++) {
        fprintf(stderr, "  Method %d: 0x%02X\n", i, buf[2 + i]);
        if (buf[2 + i] == SOCKS5_AUTH_NONE) {
            selected_method = SOCKS5_AUTH_NONE;
            break;
        }
    }

    if (selected_method == 0xFF) {
        fprintf(stderr, "No acceptable authentication method found\n");
        uint8_t response[2] = {0x05, SOCKS5_AUTH_NO_ACCEPTABLE};
        send(client->client_sock, response, 2, 0);
        return -1;
    }

    fprintf(stderr, "Selected authentication method: 0x%02X\n", selected_method);
    uint8_t response[2] = {0x05, selected_method};
    if (send(client->client_sock, response, 2, 0) != 2) return -1;

    client->auth_method = selected_method;
    client->state = SOCKS5_STATE_AUTH;
    return 0;
}

int socks5_accout_auth(Socks5Client* client) {
    if (client->auth_method == SOCKS5_AUTH_NONE) {
        client->state = SOCKS5_STATE_REQUEST;
        return 0;
    }
    return -1;
}

int socks5_client_auth(Socks5Client* client) {
    uint8_t buf[4096];
    int n = recv(client->client_sock, buf, sizeof(buf), 0);
    if (n < 10) return -1;
    if (buf[0] != 0x05) return -1;

    client->cmd = buf[1];
    if (client->cmd != SOCKS5_CMD_CONNECT) {
        socks5_send_reply(client, SOCKS5_REP_COMMAND_NOT_SUPPORTED);
        return -1;
    }

    uint8_t atyp = buf[3];
    fprintf(stderr, "SOCKS5 request: cmd=0x%02X, atyp=0x%02X\n", buf[1], atyp);

    char target_host[256];
    uint16_t target_port;
    int pos = 4;

    if (atyp == SOCKS5_ATYP_IPV4) {
        fprintf(stderr, "ATYP: IPv4\n");
        if (n < pos + 6) return -1;
        struct in_addr addr;
        memcpy(&addr, &buf[pos], 4);
        inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
        pos += 4;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        uint8_t domain_len = buf[pos++];
        fprintf(stderr, "ATYP: Domain name, length=%d\n", domain_len);
        if (n < pos + domain_len + 2) return -1;
        if (domain_len >= sizeof(target_host)) return -1;
        memcpy(target_host, &buf[pos], domain_len);
        target_host[domain_len] = '\0';
        pos += domain_len;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        fprintf(stderr, "ATYP: IPv6\n");
        if (n < pos + 18) return -1;
        struct in6_addr addr6;
        memcpy(&addr6, &buf[pos], 16);
        inet_ntop(AF_INET6, &addr6, target_host, sizeof(target_host));
        pos += 16;
    } else {
        fprintf(stderr, "ATYP not supported: 0x%02X\n", atyp);
        socks5_send_reply(client, SOCKS5_REP_ADDRESS_NOT_SUPPORTED);
        return -1;
    }

    target_port = ntohs(*(uint16_t*)&buf[pos]);
    strncpy(client->target_host, target_host, sizeof(client->target_host) - 1);
    client->target_port = target_port;
    fprintf(stderr, "SOCKS5 request: connect to %s:%d\n", target_host, target_port);

    if (!client->ssh_session) {
        fprintf(stderr, "SSH session not available\n");
        socks5_send_reply(client, SOCKS5_REP_GENERAL_FAILURE);
        return -1;
    }

    client->state = SOCKS5_STATE_OPENING;
    client->ssh_channel = ssh_tunnel_channel_open(client->ssh_session,
                                                   client->target_host, client->target_port,
                                                   client->client_host, client->client_port);
    if (!client->ssh_channel) {
        fprintf(stderr, "Failed to open SSH channel\n");
        //socks5_send_reply(client, SOCKS5_REP_NETWORK_UNREACHABLE);
        socks5_send_reply(client, SOCKS5_REP_SUCCESS);
        return 0;
    }

    socks5_send_reply(client, SOCKS5_REP_SUCCESS);
    client->state = SOCKS5_STATE_CONNECTED;
    return 0;
}

void socks5_client_free(Socks5Client* client) {
    if (client->client_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(client->client_sock);
        client->client_sock = INVALID_SOCKET;
    }
    if (client->ssh_channel) {
        ssh_tunnel_channel_close(client->ssh_channel);
        client->ssh_channel = NULL;
    }
    client->state = SOCKS5_STATE_ERROR;
}

static void socks5_client_cleanup(xPollState *loop, SOCKET_T fd, Socks5Client *client) {
    LIBSSH2_SESSION* session = client->ssh_session;
    SOCKET_T ssh_socket = ssh_tunnel_session_get_socket(session);
    xhash* hash = xpoll_get_client_data(loop, ssh_socket);
    xpoll_del_event(loop, client->client_sock, XPOLL_ALL);
    xhash_remove_int(hash, (long)client->client_sock, false);

    socks5_client_free(client);
    free(client);

    if (xhash_size(hash)<=0 && session){
        xpoll_del_event(g_xpoll, ssh_socket, XPOLL_READABLE);
        fprintf(stderr, "SSH socket fd=%d remove XPOLL_ALL event\n", ssh_socket);
    }
    g_active_connections--;
    fprintf(stderr, "Active connections: %d (connection closed)\n", g_active_connections);
}

static bool ssh_read_each_client(xhashNode *node, void*) {
    // Get client from hash node
    Socks5Client *client = (Socks5Client*)node->value;
    if (!client || client->state != SOCKS5_STATE_CONNECTED || !client->ssh_channel) {
        return true;  // Continue to next client
    }

    // If client state is ERROR, clean up immediately and remove from hash table
    if (client->state == SOCKS5_STATE_ERROR) {
        fprintf(stderr, "Cleaning up error client fd=%d\n", client->client_sock);
        socks5_client_cleanup(g_xpoll, client->client_sock, client);
        return false;
    }

    // Try to read this channel
    int n = libssh2_channel_read(client->ssh_channel,
                                client->read_buffer,
                                sizeof(client->read_buffer));

    if (n > 0) {
        // Successfully read, send to client
        int sent = send(client->client_sock, client->read_buffer, n, 0);
        if (sent != n) {
            fprintf(stderr, "Failed to send %d bytes to client fd=%d (sent=%d)\n",
                   n, client->client_sock, sent);
            client->state = SOCKS5_STATE_ERROR;
        } else {
        }
    } else if (n == LIBSSH2_ERROR_EAGAIN) {
        // This channel has no data temporarily, continue checking next
        return true;
    } else if (n < 0) {
        fprintf(stderr, "Channel error for fd=%d, n=%d\n", client->client_sock, n);
        client->state = SOCKS5_STATE_ERROR;
    }
    // n == 0 means channel is closed

    return true;  // Continue to next client
}

static void ssh_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    static int call_count = 0;
    call_count++;

    if (call_count % 1000 == 0) {
        fprintf(stderr, "ssh_read_cb called (count=%d, mask=%d)\n", call_count, mask);
    }

    xhash *hash_table = (xhash*)clientData;
    if (!hash_table) {
        fprintf(stderr, "ERROR: ssh_read_cb called with NULL hash table!\n");
        return;
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

    int remaining = client->write_buffer_size;
    int written = libssh2_channel_write(client->ssh_channel,
                                    client->write_buffer,
                                    remaining);

    if (written < 0) {
        if (written == LIBSSH2_ERROR_EAGAIN) {
            // Cannot write temporarily, continue to next
            *(int*)ctx = 1;
            return true;
        } else {
            fprintf(stderr, "Failed to write for fd=%d, written=%d\n",
                   client->client_sock, written);
            client->state = SOCKS5_STATE_ERROR;
        }
    } else if (written >= remaining) {
        // All data has been written
        client->write_buffer_size = 0;
        fprintf(stderr, "All buffered data (%d bytes) written for fd=%d\n",
               written, client->client_sock);
    } else {
        // Partial write
        memmove(client->write_buffer, client->write_buffer + written, remaining - written);
        client->write_buffer_size = remaining - written;
        fprintf(stderr, "Partially buffered data written: %d/%d bytes for fd=%d\n",
               written, remaining - written, client->client_sock);
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

    if (_call_count % 1000 == 0) {
        fprintf(stderr, "ssh_write_cb called (count=%d, mask=%d)\n", _call_count, mask);
    }

    int has_data = 0;
    xhash_foreach(hash_table, ssh_write_each_client, &has_data);
    if( has_data==0 )
        xpoll_del_event(loop, fd, XPOLL_WRITABLE);
}

static void ssh_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    xhash *hash_table = (xhash*)clientData;
    if (!hash_table)
        return;
    fprintf(stderr, "ssh_error_cb called (fd=%d)\n", fd);
    fprintf(stderr, "ssh_error_cb called (fd=%d)\n", fd);
    fprintf(stderr, "ssh_error_cb called (fd=%d)\n", fd);

    xpoll_del_event(loop, fd, XPOLL_ALL);
    ssh_tunnel_session_close(g_ssh_session);

}

static void client_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;

    SOCKET_T ssh_socket = ssh_tunnel_session_get_socket(client->ssh_session);
    xhash* hash_table = xpoll_get_client_data(loop, ssh_socket);
    int n = recv(client->client_sock, client->read_buffer, sizeof(client->read_buffer), 0);
    if (n <= 0) {
        printf("Client disconnected\n");
        client->state = SOCKS5_STATE_ERROR;
        return;
    }
    if (!client->ssh_channel){
        fprintf(stderr, "ERROR: No SSH channel available\n");
        client->state = SOCKS5_STATE_ERROR;
        return;
    }

    if (client->write_buffer_size > 0) {
        int buffer_space = sizeof(client->write_buffer) - client->write_buffer_size;
        if (n > buffer_space) {
            fprintf(stderr, "ERROR: Buffer overflow. Available: %d, needed: %d\n",
                   buffer_space, n);
            fprintf(stderr, "Dropping new data, waiting for buffer to clear\n");
            return;
        }

        memcpy(client->write_buffer + client->write_buffer_size, client->read_buffer, n);
        client->write_buffer_size += n;

        fprintf(stderr, "Appended %d bytes to write buffer, total buffered: %d bytes\n",
               n, client->write_buffer_size);
    } else {
        int written = ssh_tunnel_write(client->ssh_channel, client->read_buffer, n);
        if (written < 0) {
            client->write_error_count++;
            fprintf(stderr, "Failed to write to SSH channel: error count=%d\n", client->write_error_count);

            if (client->write_error_count >= MAX_ERROR_COUNT) {
                fprintf(stderr, "Max write error count exceeded, closing connection\n");
                client->state = SOCKS5_STATE_ERROR;
                return;
            }

            if (n <= sizeof(client->write_buffer)) {
                memcpy(client->write_buffer, client->read_buffer, n);
                client->write_buffer_size = n;
                fprintf(stderr, "Buffered %d bytes for retry\n", n);
                xpoll_add_event(loop, ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
            } else {
                fprintf(stderr, "ERROR: Data too large to buffer (%d bytes)\n", n);
                client->state = SOCKS5_STATE_ERROR;
            }
        } else if (written == 0) {
            fprintf(stderr, "SSH channel not ready for write (EAGAIN), buffering %d bytes...\n", n);

            if (n > sizeof(client->write_buffer)) {
                fprintf(stderr, "ERROR: Buffer too small for %d bytes, dropping data\n", n);
                client->state = SOCKS5_STATE_ERROR;
                return;
            }

            memcpy(client->write_buffer, client->read_buffer, n);
            client->write_buffer_size = n;
            fprintf(stderr, "Buffered %d bytes, will retry writing\n", n);
            xpoll_add_event(loop, ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
        } else {
            client->write_error_count = 0;
            fprintf(stderr, "SSH channel wrote %d bytes\n", written);

            if (written < n) {
                int remaining = n - written;
                fprintf(stderr, "Partially written: %d/%d bytes, buffering remaining %d bytes...\n",
                       written, n, remaining);

                if (remaining > sizeof(client->write_buffer)) {
                    fprintf(stderr, "ERROR: Buffer too small for %d bytes, dropping data\n", remaining);
                    client->state = SOCKS5_STATE_ERROR;
                    return;
                }

                memcpy(client->write_buffer, client->read_buffer + written, remaining);
                client->write_buffer_size = remaining;
                fprintf(stderr, "Buffered remaining %d bytes\n", remaining);
                xpoll_add_event(loop, ssh_socket, XPOLL_WRITABLE, NULL, ssh_write_cb, NULL, hash_table);
            }
        }
    }
}

static void client_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    Socks5Client *client = (Socks5Client*)clientData;
    fprintf(stderr, "client try close:%s\n", client->target_host);
    if (client->state!=SOCKS5_STATE_ERROR) {
        client->state = SOCKS5_STATE_ERROR;
        fprintf(stderr, "client closed %d-%d\n", fd, client->client_sock);
        fprintf(stderr, "client closed %d-%d\n", fd, client->client_sock);
        fprintf(stderr, "client closed %d-%d\n", fd, client->client_sock);
        socks5_client_cleanup(loop, fd, client);
    }
}

static int socks5_handle_client_single(SOCKET_T client_sock, struct sockaddr_in* client_addr) {
    Socks5Client *client = (Socks5Client*)malloc(sizeof(Socks5Client));
    if (!client) {
        CLOSE_SOCKET(client_sock);
        return -1;
    }
    memset(client, 0, sizeof(Socks5Client));

    client->client_sock = client_sock;
    client->state = SOCKS5_STATE_INIT;
    client->ssh_session = g_ssh_session;  // Use shared SSH session

    if (client_addr) {
        inet_ntop(AF_INET, &client_addr->sin_addr, client->client_host, sizeof(client->client_host));
        client->client_port = ntohs(client_addr->sin_port);
        fprintf(stderr, "New client connection from %s:%d, socket=%d\n",
                client->client_host, client->client_port, client_sock);
    } else {
        strcpy(client->client_host, "127.0.0.1");
        client->client_port = 0;
        fprintf(stderr, "New client connection, socket=%d\n", client_sock);
    }

    if (socks5_handle_handshake(client) != 0) {
        fprintf(stderr, "SOCKS5 handshake failed\n");
        socks5_client_free(client);
        free(client);
        return -1;
    }

    if (socks5_accout_auth(client) != 0) {
        socks5_client_free(client);
        free(client);
        return -1;
    }

    if (socks5_client_auth(client) != 0) {
        socks5_client_free(client);
        free(client);
        return -1;
    }

    bool pending = client->state == SOCKS5_STATE_OPENING;
    SOCKET_T ssh_socket = ssh_tunnel_session_get_socket(client->ssh_session);
    if (ssh_socket == INVALID_SOCKET) {
        fprintf(stderr, "SSH socket is invalid\n");
        if (!pending)
            ssh_tunnel_channel_close(client->ssh_channel);
        socks5_client_free(client);
        free(client);
        return -1;
    }

    int mask = XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE;
    if (pending)
        mask = XPOLL_ERROR|XPOLL_CLOSE;
    if (xpoll_add_event(g_xpoll, client->client_sock, mask,
                         client_read_cb, NULL, client_error_cb, client) != 0) {
        fprintf(stderr, "Failed to register client socket event\n");
        if (!pending)
            ssh_tunnel_channel_close(client->ssh_channel);
        socks5_client_free(client);
        free(client);
        return -1;
    }

    void* ud = xpoll_get_client_data(g_xpoll, ssh_socket);
    if (ud) {
        xhash *hash_table = (xhash*)ud;
        xhash_set_int(hash_table, (long)client->client_sock, client);
        fprintf(stderr, "Client fd=%d added to SSH socket hash table\n", client->client_sock);
        if (xhash_size(hash_table) == 1) {
            xpoll_add_event(g_xpoll, ssh_socket, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                            ssh_read_cb, NULL, ssh_error_cb, hash_table);
            fprintf(stderr, "SSH socket fd=%d added to XPOLL_ALL event\n", ssh_socket);
        }
    }
    socket_set_nonblocking(client->client_sock);

    g_active_connections++;
    fprintf(stderr, "Active connections: %d-%d-%d\n", g_active_connections, client->client_sock, pending?1:0);

    return 0;
}

void accept_cb_single(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    SOCKET_T client_sock = accept(fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock == INVALID_SOCKET) {
        if (g_server_running) {
            fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
        }
        return;
    }

    printf("New client connection from %s:%d\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    if (g_active_connections >= MAX_CONCURRENT_CONNECTIONS) {
        fprintf(stderr, "Too many connections (%d), rejecting new connection\n", g_active_connections);
        CLOSE_SOCKET(client_sock);
        return;
    }

    socks5_handle_client_single(client_sock, &client_addr);
}

void socks5_server_set_xpoll(xPollState *loop) {
    g_xpoll = loop;
}

void socks5_server_set_shared_session(LIBSSH2_SESSION *session) {
    g_ssh_session = session;

    if (session && g_xpoll) {
        SOCKET_T ssh_socket = ssh_tunnel_session_get_socket(session);
        void* ud = xpoll_get_client_data(g_xpoll, ssh_socket);
        if(!ud)
            ud = xhash_create(1024);
        if (ssh_socket != INVALID_SOCKET) {
            if (xpoll_add_event(g_xpoll, ssh_socket, XPOLL_ERROR|XPOLL_CLOSE,
                                ssh_read_cb, ssh_write_cb, ssh_error_cb, ud) != 0) {
                fprintf(stderr, "Failed to register SSH socket event\n");
            } else {
                fprintf(stderr, "SSH socket events registered\n");
            }
        }
    }
}
bool client_on_closed(xhashNode *node, void *ctx) {
    Socks5Client *client = (Socks5Client*)node->value;
    if (!client) return true;
    if(!ctx) {
        socks5_client_cleanup(g_xpoll, client->client_sock, client);
    } else if(client->state==SOCKS5_STATE_ERROR) {
        socks5_client_cleanup(g_xpoll, client->client_sock, client);
    }
    return true;
}

bool socks5_channel_reopen(xhashNode *node, void* ctx) {
    Socks5Client *client = (Socks5Client*)node->value;
    if (SOCKS5_STATE_OPENING!=client->state) return true;

    fprintf(stderr, "channel trying to reopen:%s", client->target_host);
    client->ssh_channel = ssh_tunnel_channel_open(client->ssh_session,
                                                   client->target_host, client->target_port,
                                                   client->client_host, client->client_port);
    if (!client->ssh_channel)
        return true;

    //socks5_send_reply(client, SOCKS5_REP_SUCCESS);
    client->state = SOCKS5_STATE_CONNECTED;
    fprintf(stderr, "channel reopened:%s", client->target_host);

    if (xpoll_add_event(g_xpoll, client->client_sock, XPOLL_READABLE|XPOLL_ERROR|XPOLL_CLOSE,
                         client_read_cb, NULL, client_error_cb, client) != 0) {
        fprintf(stderr, "Failed to register client socket(%d) event\n", client->client_sock);

        client->state = SOCKS5_STATE_ERROR;
        socks5_client_cleanup(NULL, client->client_sock, client);
    }
    return true;
}

#include <time.h>
void socks5_server_update() {
    static time_t last_keepalive = 0;
    static time_t last_reopen = 0;
    time_t now = time(NULL);

    // 每30秒检查一次
    if (now - last_keepalive >= 30) {
        last_keepalive = now;
        if (g_ssh_session) {
            int seconds_to_next = 0;
            int rc = libssh2_keepalive_send(g_ssh_session, &seconds_to_next);
            if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN)
                fprintf(stderr, "keepalive_send error: %d\n", rc);
        }
    }
    if (now - last_reopen >= 1) {
        last_reopen = now;
        SOCKET_T ssh_sock = ssh_tunnel_session_get_socket(g_ssh_session);
        xhash* hash = (xhash*)xpoll_get_client_data(g_xpoll, ssh_sock);
        if(hash)
            xhash_foreach(hash, socks5_channel_reopen, NULL);
    }
}

xFileProc socks5_server_get_accept_cb(void) {
    return (xFileProc)accept_cb_single;
}

int socks5_server_init(const Socks5ServerConfig* config) {
    if (!config) return -1;
    memcpy(&g_server_config, config, sizeof(Socks5ServerConfig));
    return 0;
}

void socks5_server_stop(void) {
    SOCKET_T ssh_sock = ssh_tunnel_session_get_socket(g_ssh_session);
    xhash* hash = (xhash*)xpoll_get_client_data(g_xpoll, ssh_sock);
    if(hash) {
        xhash_foreach(hash, client_on_closed, NULL);
        xhash_destroy(hash, NULL);
    }

    g_server_running = 0;
}
