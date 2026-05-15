#include "https_proxy.h"
#include "xsock.h"
#include "xchannel.h"
#include "xpoll.h"
#include "xpac_server.h"
#ifdef LOG_TAG
    #undef LOG_TAG
#endif
#define LOG_TAG "xhttp"
#include "xlog.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

// Check if host is a local address (127.0.0.1, localhost, 0.0.0.0, or actual local IP)
static int is_local_address(const char* host) {
    if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0 || strcmp(host, "0.0.0.0") == 0)
        return 1;

    // Get local hostname and resolve to IP
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* he = gethostbyname(hostname);
        if (he) {
            for (int i = 0; he->h_addr_list[i] != NULL; i++) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, he->h_addr_list[i], ip, sizeof(ip));
                if (strcmp(host, ip) == 0)
                    return 1;
            }
        }
    }
    return 0;
}

// ===================== Connection State =====================
typedef enum {
    CONN_STATE_NEW,
    CONN_STATE_TCP_CONNECTING,
    CONN_STATE_AUTHING,
    CONN_STATE_CONNECTING,
    CONN_STATE_SOCKS5_OK,
    CONN_STATE_CLOSED
} ConnState;

// ===================== Connection Structure =====================
typedef struct {
    SOCKET_T client_sock;
    SOCKET_T socks5_sock;
    xChannel* client_ch;
    xChannel* socks5_ch;
    ConnState state;
    bool closing;

    // request buf
    char req_buf[32767];
    int req_head;
    int req_size;

    // response buf
    char rep_buf[65536];
    int rep_head;
    int rep_size;

    int is_https;
    char host[255];
    uint16_t port;
} ProxyConn;

// ===================== HTTP Parsing Functions =====================
// Parse CONNECT request, extract target host and port
int https_parse_connect(const char* req_buf, int req_len, char* target_host, int host_len, uint16_t* target_port);

// Parse normal HTTP request (GET/POST etc.), extract target host and port
int http_parse_request(char* req_buf, int* req_len, int buf_size, char* target_host, int host_len, uint16_t* target_port);

// ===================== Global Variables =====================
static HttpProxyConfig g_config;
static ProxyConn* g_conn_list = NULL;
static int g_conn_count = 0;
static SOCKET_T g_listen_sock = INVALID_SOCKET;  // listening socket
// ===================== HTTP Parsing Functions =====================
// Parse CONNECT request, extract target_host and target_port
int https_parse_connect(const char* req_buf, int req_len, char* target_host, int host_len, uint16_t* target_port) {
    if (strncmp(req_buf, "CONNECT", 7) != 0)
        return -1;

    char method[16], path[512], version[16];
    if (sscanf(req_buf, "%15s %511s %15s", method, path, version) != 3)
        return -1;

    // Verify if it's CONNECT method
    if (strcmp(method, "CONNECT") != 0)
        return -1;

    // Split host and port from path (default 443)
    char* colon_pos = strchr(path, ':');
    if (colon_pos) {
        *colon_pos = '\0';
        snprintf(target_host, host_len, "%s", path);
        *target_port = atoi(colon_pos + 1);
    } else {
        snprintf(target_host, host_len, "%s", path);
        *target_port = 443;// HTTPS default port
    }

    return 0;
}

// Convert proxy-formatted HTTP request to direct server format
// Example: GET http://host:port/path HTTP/1.1 -> GET /path HTTP/1.1
static int convert_http_request_inplace(char* req_buf, int* req_len, int buf_size) {
    if (!req_buf || !req_len || *req_len <= 0 || buf_size <= 0)
        return -1;
    // Ensure we have room for null terminator
    if (*req_len >= buf_size)
        return -1; // Buffer already full, no room for null terminator
    // Find first space (after method)
    const char* space1 = memchr(req_buf, ' ', *req_len);
    if (!space1) return -1;

    // Find second space (after URL)
    int space1_offset = space1 - req_buf;
    const char* space2 = memchr(space1 + 1, ' ', *req_len - space1_offset - 1);
    if (!space2) return -1;

    int space2_offset = space2 - req_buf;

    // Check if URL contains "://" (bounded search within URL only)
    const char* url_start = space1 + 1;
    const char* proto = NULL;
    if (space2 - url_start < 7) return 0; // "http://" shortest length is 7 bytes
    const char* end_search = space2 - 3;
    for (const char* p = url_start; p <= end_search; p++) {
        if (p[0] == ':' && p[1] == '/' && p[2] == '/') {
            proto = p;
            break;
        }
    }

    if (!proto)       // No "://", already in direct format
        return 0;

    // Find first '/' after "://" (path start, bounded search)
    const char* slash = NULL;
    for (const char* p = proto + 3; p < space2; p++) {
        if (*p == '/') {
            slash = p;
            break;
        }
    }

    if (!slash) {
        // No path, use "/"
        int method_len = space1_offset;
        int remaining_len = *req_len - space2_offset;
        int new_len = method_len + 2 + remaining_len; // "METHOD / HTTP/1.1..."

        if (new_len > *req_len) {
            XLOGE("[http] no slash convert_http_request_inplace overwrite1...");
            XLOGE("[http] no slash convert_http_request_inplace overwrite1...");
            XLOGE("[http] no slash convert_http_request_inplace overwrite1...");
            return -1; // Buffer too small (shouldn't happen as we're shortening)
        }

        // Safety check: ensure we don't exceed buffer
        if (new_len >= buf_size) {
            XLOGE("[http] no slash convert_http_request_inplace overwrite2...");
            XLOGE("[http] no slash convert_http_request_inplace overwrite2...");
            XLOGE("[http] no slash convert_http_request_inplace overwrite2...");
            return -1;
        }

        // Shift remaining part to make room for "/"
        memmove(req_buf + method_len + 2, req_buf + space2_offset, remaining_len);
        req_buf[method_len] = ' ';
        req_buf[method_len + 1] = '/';
        *req_len = new_len;
        req_buf[*req_len] = '\0';  // Ensure null termination
    } else {
        // Has path, move path part to replace URL
        int method_len = space1_offset;
        int path_len = space2_offset - (slash - req_buf);
        int remaining_len = *req_len - space2_offset;

        // Move path to right after method
        *req_len = method_len + 1 + path_len + remaining_len;
        // Safety check: ensure we don't exceed buffer
        if (*req_len >= buf_size) {
            XLOGE("[http] slash convert_http_request_inplace overwrite...");
            XLOGE("[http] slash convert_http_request_inplace overwrite...");
            XLOGE("[http] slash convert_http_request_inplace overwrite...");
            return -1;
        }
        memmove(req_buf + method_len + 1, slash, path_len + remaining_len);
        req_buf[*req_len] = '\0';  // Ensure null termination
    }

    return 0;
}

// Parse normal HTTP request (extract target address from Host header)
// Note: This function modifies req_buf to convert absolute URL to relative path
int http_parse_request(char* req_buf, int* req_len, int buf_size, char* target_host, int host_len, uint16_t* target_port) {
    // 1. Extract Host header first (core of HTTP request, format: Host: www.baidu.com:80)
    const char* host_header = strstr(req_buf, "Host: ");
    if (host_header == NULL)
        return -1;
    host_header += 6; // Skip "Host: " string

    // 2. Extract Host content (until \r or \n ends)
    char host_buf[256] = {0};
    int i = 0;
    while (i < sizeof(host_buf)-1 && host_header[i] != '\r' && host_header[i] != '\n') {
        host_buf[i] = host_header[i];
        i++;
    }
    host_buf[i] = '\0';

    // Remove leading/trailing whitespace
    char* start = host_buf;
    while (*start == ' ' || *start == '\t') start++;
    char* end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t')) end--;
    *(end + 1) = '\0';

    // 3. Split host and port (HTTP default port 80)
    char* colon_pos = strchr(start, ':');
    if (colon_pos) {
        *colon_pos = '\0';
        snprintf(target_host, host_len, "%s", start);
        *target_port = atoi(colon_pos + 1);
    } else {
        snprintf(target_host, host_len, "%s", start);
        *target_port = 80; // HTTP default port
    }

    // 4. Convert absolute URL to relative path using the improved method
    convert_http_request_inplace(req_buf, req_len, buf_size);

    return 0;
}

// ===================== Connection Management Functions =====================
// Initialize connection list
static int init_conn_list(void) {
    g_conn_list = (ProxyConn*)calloc(g_config.max_conns, sizeof(ProxyConn));
    if ( !g_conn_list )
        return -1;

    for (int i = 0; i < g_config.max_conns; i++) {
        g_conn_list[i].client_sock = INVALID_SOCKET;
        g_conn_list[i].socks5_sock = INVALID_SOCKET;
        g_conn_list[i].client_ch = NULL;
        g_conn_list[i].socks5_ch = NULL;
        g_conn_list[i].state = CONN_STATE_CLOSED;
        g_conn_list[i].closing = false;
        g_conn_list[i].is_https = 0;
        g_conn_list[i].req_size = 0; g_conn_list[i].req_head = 0;
        g_conn_list[i].rep_size = 0; g_conn_list[i].rep_head = 0;
        memset(g_conn_list[i].req_buf, 0, sizeof(g_conn_list[i].req_buf));
    }
    g_conn_count = 0;
    return 0;
}

// Find free connection slot
static int find_free_conn_slot(void) {
    for (int i = 0; i < g_config.max_conns; i++) {
        if (g_conn_list[i].state == CONN_STATE_CLOSED) {
            return i;
        }
    }
    return -1;
}

// Add new client connection to list
static int add_new_client_conn(SOCKET_T client_sock) {
    int slot = find_free_conn_slot();
    if (slot == -1) return -1;

    g_conn_list[slot].client_sock = client_sock;
    g_conn_list[slot].socks5_sock = INVALID_SOCKET;
    g_conn_list[slot].client_ch = NULL;
    g_conn_list[slot].socks5_ch = NULL;
    g_conn_list[slot].state = CONN_STATE_NEW;
    g_conn_list[slot].closing = false;
    g_conn_list[slot].req_size = 0; g_conn_list[slot].req_head = 0;
    g_conn_list[slot].rep_size = 0; g_conn_list[slot].rep_head = 0;
    memset(g_conn_list[slot].req_buf, 0, sizeof(g_conn_list[slot].req_buf));

    g_conn_count++;
    XLOGI("[http] New connection added to slot %d, current connections: %d", slot, g_conn_count);

    return slot;
}

// Close and clean connection
static void close_conn_slot(int slot) {
    if (slot < 0 || slot >= g_config.max_conns) return;
    if (g_conn_list[slot].state == CONN_STATE_CLOSED) return;
    SOCKET_T client_sock = g_conn_list[slot].client_sock;
    SOCKET_T socks5_sock = g_conn_list[slot].socks5_sock;
    ConnState state = g_conn_list[slot].state;

    if (g_conn_list[slot].client_ch) {
        xChannel* ch = g_conn_list[slot].client_ch;
        g_conn_list[slot].client_ch = NULL;
        g_conn_list[slot].client_sock = INVALID_SOCKET;
        xchannel_destroy(ch);
        client_sock = INVALID_SOCKET;
    }
    if (g_conn_list[slot].socks5_ch) {
        xChannel* ch = g_conn_list[slot].socks5_ch;
        g_conn_list[slot].socks5_ch = NULL;
        g_conn_list[slot].socks5_sock = INVALID_SOCKET;
        xchannel_destroy(ch);
        socks5_sock = INVALID_SOCKET;
    }

    XLOGD("[http] Closing slot %d, client_sock=%d, socks5_sock=%d, current_state=%d",
          slot, (int)client_sock, (int)socks5_sock, (int)state);

    if (client_sock != INVALID_SOCKET) {
        xpoll_del_event(client_sock, XPOLL_ALL);
        CLOSE_SOCKET(client_sock);
        XLOGD("[http] Locally closed client socket %d in slot %d", (int)client_sock, slot);
    }
    if (socks5_sock != INVALID_SOCKET) {
        xpoll_del_event(socks5_sock, XPOLL_ALL);
        CLOSE_SOCKET(socks5_sock);
        XLOGD("[http] Locally closed SOCKS5 socket %d in slot %d", (int)socks5_sock, slot);
    }

    // Reset connection structure
    g_conn_list[slot].client_sock = INVALID_SOCKET;
    g_conn_list[slot].socks5_sock = INVALID_SOCKET;
    g_conn_list[slot].client_ch = NULL;
    g_conn_list[slot].socks5_ch = NULL;
    g_conn_list[slot].state = CONN_STATE_CLOSED;
    g_conn_list[slot].closing = false;
    g_conn_list[slot].req_size = 0; g_conn_list[slot].req_head = 0;
    g_conn_list[slot].rep_size = 0; g_conn_list[slot].rep_head = 0;
    memset(g_conn_list[slot].req_buf, 0, sizeof(g_conn_list[slot].req_buf));

    if (g_conn_count > 0) g_conn_count--;

    XLOGI("[http] Slot %d connection fully closed, current connections: %d", slot, g_conn_count);
}

// Clean connection list
static void cleanup_conn_list(void) {
    if (g_conn_list) {
        for (int i = 0; i < g_config.max_conns; i++) {
            if (g_conn_list[i].state != CONN_STATE_CLOSED) {
                close_conn_slot(i);
            }
        }
        free(g_conn_list);
        g_conn_list = NULL;
    }
    g_conn_count = 0;
}

// ===================== Forward Declare Callback Functions =====================
static void accept_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void client_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void socks5_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void socks5_write_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void client_error_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static void socks5_error_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg);
static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud);
static size_t socks5_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud);
static void tunnel_channel_close_cb(xChannel* ch, const char* reason, void* ud);
static int enable_tunnel_channels(ProxyConn* conn);

// ===================== Core Processing Functions =====================
static int proxy_conn_slot(ProxyConn* conn) {
    if (!conn || !g_conn_list) return -1;
    int slot = (int)(conn - g_conn_list);
    if (slot < 0 || slot >= g_config.max_conns) return -1;
    return slot;
}

static void shutdown_conn_slot(int slot, const char* reason) {
    if (slot < 0 || slot >= g_config.max_conns) return;

    ProxyConn* conn = &g_conn_list[slot];
    if (conn->state == CONN_STATE_CLOSED || conn->closing) return;

    conn->closing = true;
    XLOGW("[http] shutdown slot %d, reason=%s", slot,
          reason ? reason : "unknown");

    /* Tunnel state has xchannels with their own send buffer that we want to
     * drain. Closing the xchannel triggers tunnel_channel_close_cb, which in
     * turn calls close_conn_slot to finish teardown.
     *
     * Pre-tunnel state is raw-socket I/O with nothing user-side to drain;
     * SHUTDOWN_WR alone would leave the slot stuck because the new xpoll
     * semantics suppress HUP-as-CLOSE while POLLIN(EOF) is asserted, so
     * close it directly. */
    if (conn->state == CONN_STATE_SOCKS5_OK) {
        xChannel* c = conn->client_ch;
        xChannel* s = conn->socks5_ch;
        if (c) xchannel_close(c, reason);
        if (s && conn->state != CONN_STATE_CLOSED) {
            xchannel_close(s, reason);
        }
        return;
    }

    close_conn_slot(slot);
}

static void shutdown_conn_from_ptr(ProxyConn* conn, const char* reason) {
    int slot = proxy_conn_slot(conn);
    if (slot >= 0) shutdown_conn_slot(slot, reason);
}

static void close_conn_from_ptr(ProxyConn* conn) {
    int slot = proxy_conn_slot(conn);
    if (slot >= 0) close_conn_slot(slot);
}

static int socks5_arm_read(int slot) {
    if (slot < 0 || slot >= g_config.max_conns) return -1;
    ProxyConn* conn = &g_conn_list[slot];
    SOCKET_T fd = conn->socks5_sock;
    if (fd == INVALID_SOCKET) return -1;

    if (xpoll_add_event(fd, XPOLL_READABLE | XPOLL_ERROR,
                        socks5_read_cb, NULL, socks5_error_cb,
                        (void*)(intptr_t)slot) != 0) {
        return -1;
    }
    xpoll_del_event(fd, XPOLL_WRITABLE);
    return 0;
}

static int socks5_arm_write(int slot) {
    if (slot < 0 || slot >= g_config.max_conns) return -1;
    ProxyConn* conn = &g_conn_list[slot];
    SOCKET_T fd = conn->socks5_sock;
    if (fd == INVALID_SOCKET) return -1;

    if (xpoll_add_event(fd, XPOLL_WRITABLE | XPOLL_ERROR,
                        NULL, socks5_write_cb, socks5_error_cb,
                        (void*)(intptr_t)slot) != 0) {
        return -1;
    }
    xpoll_del_event(fd, XPOLL_READABLE);
    return 0;
}

static size_t socks5_pending_write_len(const ProxyConn* conn) {
    if (!conn || conn->rep_head < 0 || conn->rep_size <= conn->rep_head) {
        return 0;
    }
    return (size_t)(conn->rep_size - conn->rep_head);
}

static int socks5_append_pending_write(ProxyConn* conn, const void* data, size_t len) {
    if (!conn || (!data && len > 0) || len > sizeof(conn->rep_buf)) {
        return -1;
    }

    size_t pending = socks5_pending_write_len(conn);
    if (len > sizeof(conn->rep_buf) - pending) {
        return -1;
    }

    /* Use memmove on both copies: data may alias the region being shifted
     * (current callers don't, but it's a one-instruction safety belt). */
    if (pending > 0 && conn->rep_head > 0) {
        memmove(conn->rep_buf, conn->rep_buf + conn->rep_head, pending);
    }
    if (len > 0) {
        memmove(conn->rep_buf + pending, data, len);
    }

    conn->rep_head = 0;
    conn->rep_size = (int)(pending + len);
    return 0;
}

static int socks5_send_or_queue(ProxyConn* conn, const void* data, size_t len) {
    if (!conn || (!data && len > 0) || len > sizeof(conn->rep_buf)) {
        return -1;
    }
    if (socks5_pending_write_len(conn) > 0) {
        return socks5_append_pending_write(conn, data, len) == 0 ? 0 : -1;
    }

    const char* p = (const char*)data;
    size_t off = 0;
    conn->rep_head = 0;
    conn->rep_size = 0;

    while (off < len) {
        int n = send(conn->socks5_sock, p + off, (int)(len - off), 0);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && socket_check_eagain()) {
            break;
        }
        return -1;
    }

    if (off == len) {
        return 1;
    }

    memmove(conn->rep_buf, p + off, len - off);
    conn->rep_head = 0;
    conn->rep_size = (int)(len - off);
    return 0;
}

static int socks5_send_handshake(ProxyConn* conn) {
    static const uint8_t handshake_req[] = {0x05, 0x01, 0x00};
    return socks5_send_or_queue(conn, handshake_req, sizeof(handshake_req));
}

static int socks5_build_connect_request(ProxyConn* conn, size_t* len_out) {
    if (!conn || !len_out) return -1;

    size_t domain_len = strlen(conn->host);
    size_t req_total_len = 5 + domain_len + 2;
    if (domain_len == 0 || domain_len > 255 ||
        req_total_len > sizeof(conn->rep_buf)) {
        return -1;
    }

    uint8_t* connect_req = (uint8_t*)conn->rep_buf;
    connect_req[0] = 0x05;
    connect_req[1] = 0x01;
    connect_req[2] = 0x00;
    connect_req[3] = 0x03;
    connect_req[4] = (uint8_t)domain_len;
    memcpy(connect_req + 5, conn->host, domain_len);

    uint16_t target_port_nbo = htons(conn->port);
    memcpy(connect_req + 5 + domain_len, &target_port_nbo, 2);

    *len_out = req_total_len;
    return 0;
}

static int socks5_flush_pending_write(ProxyConn* conn) {
    if (!conn || conn->socks5_sock == INVALID_SOCKET) return -1;

    while (conn->rep_head < conn->rep_size) {
        int remaining = conn->rep_size - conn->rep_head;
        int n = send(conn->socks5_sock,
                     conn->rep_buf + conn->rep_head,
                     remaining, 0);
        if (n > 0) {
            conn->rep_head += n;
            continue;
        }
        if (n < 0 && socket_check_eagain()) {
            return 0;
        }
        return -1;
    }

    conn->rep_head = 0;
    conn->rep_size = 0;
    return 1;
}

static int socks5_reply_expected_len(const uint8_t* buf, int len) {
    if (!buf || len < 4) return 0;

    switch (buf[3]) {
    case 0x01:
        return 10;
    case 0x03:
        if (len < 5) return 0;
        return 5 + buf[4] + 2;
    case 0x04:
        return 22;
    default:
        return -1;
    }
}

static int enable_tunnel_channels(ProxyConn* conn) {
    if (!conn || conn->client_sock == INVALID_SOCKET || conn->socks5_sock == INVALID_SOCKET) {
        return -1;
    }
    if (conn->client_ch && conn->socks5_ch) {
        return 0;
    }

    xChannelConfig c_cfg = XCHANNEL_CONFIG_INIT;
    c_cfg.frame = XCHANNEL_FRAME_RAW;
    c_cfg.packet_cb = client_channel_packet_cb;
    c_cfg.close_cb = tunnel_channel_close_cb;
    c_cfg.userdata = conn;

    xChannelConfig s_cfg = XCHANNEL_CONFIG_INIT;
    s_cfg.frame = XCHANNEL_FRAME_RAW;
    s_cfg.packet_cb = socks5_channel_packet_cb;
    s_cfg.close_cb = tunnel_channel_close_cb;
    s_cfg.userdata = conn;

    conn->client_ch = xchannel_create(conn->client_sock, &c_cfg);
    conn->socks5_ch = xchannel_create(conn->socks5_sock, &s_cfg);
    if (!conn->client_ch || !conn->socks5_ch) {
        goto fail;
    }

    xchannel_set_max_send(conn->client_ch, 16 * 1024 * 1024);
    xchannel_set_max_recv(conn->client_ch, 16 * 1024 * 1024);
    xchannel_set_max_send(conn->socks5_ch, 16 * 1024 * 1024);
    xchannel_set_max_recv(conn->socks5_ch, 16 * 1024 * 1024);

    if (xchannel_attach(conn->client_ch) != 0) goto fail;
    if (xchannel_attach(conn->socks5_ch) != 0) goto fail;
    return 0;

fail:
    if (conn->client_ch) {
        xchannel_destroy(conn->client_ch);
        conn->client_ch = NULL;
        conn->client_sock = INVALID_SOCKET;
    }
    if (conn->socks5_ch) {
        xchannel_destroy(conn->socks5_ch);
        conn->socks5_ch = NULL;
        conn->socks5_sock = INVALID_SOCKET;
    }
    return -1;
}

static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud) {
    (void)ch;
    ProxyConn* conn = (ProxyConn*)ud;
    if (!conn || conn->state != CONN_STATE_SOCKS5_OK || !conn->socks5_ch) return len;
    if (len == 0) return 0;
    if (xchannel_send_raw(conn->socks5_ch, data, len) != 0) {
        XLOGE("[http] tunnel client->socks5 send failed");
        shutdown_conn_from_ptr(conn, "tunnel_client_send_failed");
    }
    return len;
}

static size_t socks5_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud) {
    (void)ch;
    ProxyConn* conn = (ProxyConn*)ud;
    if (!conn || conn->state != CONN_STATE_SOCKS5_OK || !conn->client_ch) return len;
    if (len == 0) return 0;
    if (xchannel_send_raw(conn->client_ch, data, len) != 0) {
        XLOGE("[http] tunnel socks5->client send failed");
        shutdown_conn_from_ptr(conn, "tunnel_socks5_send_failed");
    }
    return len;
}

static void tunnel_channel_close_cb(xChannel* ch, const char* reason, void* ud) {
    ProxyConn* conn = (ProxyConn*)ud;
    XLOGW("[http] tunnel channel closed: reason=%s", reason ? reason : "unknown");
    if (!conn) {
        xchannel_destroy(ch);
        return;
    }

    if (conn->client_ch == ch) {
        conn->client_ch = NULL;
        conn->client_sock = INVALID_SOCKET;
    }
    if (conn->socks5_ch == ch) {
        conn->socks5_ch = NULL;
        conn->socks5_sock = INVALID_SOCKET;
    }

    close_conn_from_ptr(conn);
    xchannel_destroy(ch);
}

// Handle client request (parse + establish Socks5 connection)
static int handle_client_request(int slot) {
    ProxyConn* conn = &g_conn_list[slot];
    if (conn->req_size == 0) return -1;

    // Parse request (distinguish between HTTP/HTTPS)
    int is_https = 0;
    if (https_parse_connect(conn->req_buf, conn->req_size, conn->host, sizeof(conn->host), &conn->port) == 0) {
        is_https = 1;
        XLOGI("[http] Parsed HTTPS CONNECT request: %s:%d", conn->host, conn->port);
    } else if (http_parse_request(conn->req_buf, &conn->req_size, sizeof(conn->req_buf), conn->host, sizeof(conn->host), &conn->port) == 0) {
        is_https = 0;
        XLOGI("[http]  Parsed HTTP request: %s:%d", conn->host, conn->port);
    } else {
        XLOGE("[http] Invalid request, closing connection");
        return -1;
    }

    // First check if it's a PAC request or management request
    if (is_local_address(conn->host) && conn->port == g_config.listen_port) {
        return xpac_handle_request(conn->client_sock, conn->req_buf, conn->req_size)==1?-2:-1;
    }

    SOCKET_T socks5_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (socks5_sock == INVALID_SOCKET) {
        XLOGE("[http] create socks5 socket failed");
        return -1;
    }

    // set nonblocking before connect
    socket_set_nonblocking(socks5_sock);

    struct sockaddr_in socks5_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr(g_config.socks5_server_ip),
        .sin_port = htons(g_config.socks5_server_port)
    };

    int ret = connect(socks5_sock, (struct sockaddr*)&socks5_addr, sizeof(socks5_addr));
    if (ret != 0) {
        if (!socket_check_eagain()) {
            // connect failed
            XLOGE("[http] connect() failed immediately, host=%s", conn->host);
            CLOSE_SOCKET(socks5_sock);
            return -1;
        }

        // EINPROGRESS: connecting
        conn->socks5_sock = socks5_sock;
        conn->state = CONN_STATE_TCP_CONNECTING;
        conn->is_https = is_https;

        // register WRITABLE event and wait connect finish
        if (xpoll_add_event(socks5_sock,
                            XPOLL_WRITABLE | XPOLL_ERROR,
                            NULL,
                            socks5_write_cb,
                            socks5_error_cb,
                            (void*)(intptr_t)slot) != 0) {
            XLOGE("[http] Failed to register SOCKS5 connect event");
            CLOSE_SOCKET(socks5_sock);
            conn->socks5_sock = INVALID_SOCKET;
            return -1;
        }
    } else {
        // ret == 0: connected, send handshake immediately if possible.
        XLOGD("[http] connect() succeeded immediately, host=%s", conn->host);

        conn->socks5_sock = socks5_sock;
        conn->state = CONN_STATE_AUTHING;
        conn->is_https = is_https;

        int send_rc = socks5_send_handshake(conn);
        if (send_rc < 0) {
            XLOGE("[http] Failed to send SOCKS5 handshake");
            CLOSE_SOCKET(socks5_sock);
            conn->socks5_sock = INVALID_SOCKET;
            return -1;
        }
        if (send_rc == 0) {
            if (socks5_arm_write(slot) != 0) {
                XLOGE("[http] Failed to register SOCKS5 handshake write");
                CLOSE_SOCKET(socks5_sock);
                conn->socks5_sock = INVALID_SOCKET;
                return -1;
            }
        } else if (socks5_arm_read(slot) != 0) {
            XLOGE("[http] Failed to register SOCKS5 handshake read");
            CLOSE_SOCKET(socks5_sock);
            conn->socks5_sock = INVALID_SOCKET;
            return -1;
        }
    }
    return 0;
}

static void accept_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)mask;
    (void)clientData;
    (void)submit_arg;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    SOCKET_T client_sock = accept(fd, (struct sockaddr*)&client_addr, &client_addr_len);

    if (client_sock != INVALID_SOCKET) {
        XLOGI("[http] New client connected: %s:%d (socket %d)",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), (int)client_sock);

        // Add new connection to list
        int slot = add_new_client_conn(client_sock);
        if (slot == -1) {
            XLOGE("[http] Connection list full, rejecting new connection");
            CLOSE_SOCKET(client_sock);
            return;
        }

        socket_set_nonblocking(client_sock);
        if (xpoll_add_event(client_sock, XPOLL_READABLE,
                            client_read_cb, NULL, client_error_cb, (void*)(intptr_t)slot) != 0) {
            XLOGE("[http] Connection list full, rejecting new connection");
            close_conn_slot(slot);
        }
    } else if (!socket_check_eagain()) {
        XLOGE("[http] accept failed, ERRNO=%d", GET_ERRNO());
    }
}

// Client read callback
static void client_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    int slot = (int)(intptr_t)clientData;
    if (slot < 0 || slot >= g_config.max_conns) return;

    ProxyConn* conn = &g_conn_list[slot];
    if (conn->state == CONN_STATE_CLOSED || conn->closing) return;

    if (conn->state == CONN_STATE_NEW) {
        // New connection: read client request (unparsed)
        int recv_len = recv(conn->client_sock, conn->req_buf + conn->req_size,
                           sizeof(conn->req_buf) - conn->req_size - 1, 0);

        if (recv_len <= 0) {
            if(recv_len==0) {
                XLOGE("[http] Client socket %d closed by client (EOF)", (int)conn->client_sock);
                shutdown_conn_slot(slot, "client_eof");
            }else if(!socket_check_eagain()) {
                XLOGE("[http] Client socket %d error on read, locally closed, ERRNO=%d", (int)conn->client_sock, GET_ERRNO());
                shutdown_conn_slot(slot, "client_read_error");
            }
            return;
        }

        // Update request buffer length
        conn->req_size += recv_len;
        conn->req_buf[conn->req_size] = '\0';

        // Try to parse request (complete request received)
        if (strstr(conn->req_buf, "\r\n\r\n") != NULL) {
            int ret = handle_client_request(slot);
            if(ret==-2){
                XLOGI("[http] PAC request handled, closing connection");
                shutdown_conn_slot(slot, "pac_handled");
            } else if (ret != 0) {
                XLOGE("[http] PAC request handling exception, closing connection");
                shutdown_conn_slot(slot, "request_error");
            }
        } else if (conn->req_size >= sizeof(conn->req_buf) - 1) {
            // Request too large
            XLOGE("[http] Request too large, closing connection");
            shutdown_conn_slot(slot, "request_too_large");
        }
    } else if (conn->state == CONN_STATE_SOCKS5_OK) {
        // handled by xchannel tunnel callbacks
        (void)fd;
        (void)mask;
    }
}

// SOCKS5 server read callback
static void socks5_read_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)mask;
    (void)submit_arg;
    int slot = (int)(intptr_t)clientData;
    if (slot < 0 || slot >= g_config.max_conns) return;

    ProxyConn* conn = &g_conn_list[slot];
    if (conn->state == CONN_STATE_CLOSED || conn->closing) return;
    switch (conn->state) {
    case CONN_STATE_AUTHING:{
        // Receive handshake response
        int need = 2 - conn->rep_size;
        int ret = recv(fd, conn->rep_buf + conn->rep_size, need, 0);
        if (ret <= 0) {
            if (ret < 0 && socket_check_eagain()) return;
            if (ret == 0) {
                XLOGE("[http] SOCKS5 socket %d closed by SOCKS5 server during handshake (EOF)", (int)fd);
            } else {
                XLOGE("[http] SOCKS5 socket %d handshake recv failed, locally closed, ERRNO=%d", (int)fd, GET_ERRNO());
            }
            shutdown_conn_slot(slot, "socks5_handshake_read_error");
            return;
        }

        conn->rep_size += ret;
        if (conn->rep_size < 2) return;

        uint8_t* handshake_resp = (uint8_t*)conn->rep_buf;
        if (handshake_resp[0] != 0x05 || handshake_resp[1] != 0x00) {
            XLOGE("socks5 domain auth failed (only no-auth supported)");
            shutdown_conn_slot(slot, "socks5_auth_failed");
            return;
        }

        conn->rep_size = 0;
        conn->rep_head = 0;
        size_t req_len = 0;
        if (socks5_build_connect_request(conn, &req_len) != 0) {
            XLOGE("socks5 domain connect request build failed, host=%s", conn->host);
            shutdown_conn_slot(slot, "socks5_connect_build_failed");
            return;
        }
        conn->state = CONN_STATE_CONNECTING;
        int send_rc = socks5_send_or_queue(conn, conn->rep_buf, req_len);
        if (send_rc < 0) {
            XLOGE("socks5 domain connect send failed, host=%s", conn->host);
            shutdown_conn_slot(slot, "socks5_connect_send_failed");
            return;
        }
        if (send_rc == 0) {
            if (socks5_arm_write(slot) != 0) {
                XLOGE("socks5 domain connect write registration failed, host=%s", conn->host);
                shutdown_conn_slot(slot, "socks5_connect_write_register_failed");
                return;
            }
        } else if (socks5_arm_read(slot) != 0) {
            XLOGE("socks5 domain connect read registration failed, host=%s", conn->host);
            shutdown_conn_slot(slot, "socks5_connect_read_register_failed");
            return;
        }
        break;
    }
    case CONN_STATE_CONNECTING: {
        int expected = socks5_reply_expected_len((const uint8_t*)conn->rep_buf,
                                                  conn->rep_size);
        if (expected < 0 || expected > (int)sizeof(conn->rep_buf)) {
            XLOGE("[http] invalid SOCKS5 connect response");
            shutdown_conn_slot(slot, "socks5_connect_bad_response");
            return;
        }

        int need = 0;
        if (expected > 0) {
            need = expected - conn->rep_size;
        } else if (conn->rep_size < 4) {
            need = 4 - conn->rep_size;
        } else {
            need = 1;
        }

        int ret = recv(conn->socks5_sock,
                       conn->rep_buf + conn->rep_size,
                       need, 0);
        if (ret <= 0) {
            if (ret < 0 && socket_check_eagain()) return;
            if (ret == 0) {
                XLOGE("[http] SOCKS5 socket %d closed by SOCKS5 server during connect response (EOF)", (int)conn->socks5_sock);
            } else {
                XLOGE("[http] SOCKS5 socket %d connect response recv failed, locally closed, ERRNO=%d", (int)conn->socks5_sock, GET_ERRNO());
            }
            shutdown_conn_slot(slot, "socks5_connect_read_error");
            return;
        }

        conn->rep_size += ret;
        expected = socks5_reply_expected_len((const uint8_t*)conn->rep_buf,
                                             conn->rep_size);
        if (expected < 0 || expected > (int)sizeof(conn->rep_buf)) {
            XLOGE("[http] invalid SOCKS5 connect response");
            shutdown_conn_slot(slot, "socks5_connect_bad_response");
            return;
        }
        if (expected == 0 || conn->rep_size < expected) return;

        uint8_t* connect_resp = (uint8_t*)conn->rep_buf;
        if (connect_resp[0] != 0x05) {
            XLOGE("socks5 domain connect invalid version: %d", connect_resp[0]);
            shutdown_conn_slot(slot, "socks5_connect_bad_version");
            return;
        }

        // Verify response result: 0x00 means connection successful
        if (connect_resp[1] != 0x00) {
            XLOGE("socks5 domain connect target failed, code: %d", connect_resp[1]);
            shutdown_conn_slot(slot, "socks5_connect_failed");
            return;
        }
        conn->rep_size = 0;
        conn->rep_head = 0;
        conn->state = CONN_STATE_SOCKS5_OK;
        if (enable_tunnel_channels(conn) != 0) {
            XLOGE("[http] Failed to enable tunnel channels");
            shutdown_conn_slot(slot, "tunnel_channel_enable_failed");
            return;
        }

        // HTTPS returns 200 response, HTTP forwards buffered request
        if (conn->is_https) {
            static const char ok_resp[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
            conn->req_size = 0;
            conn->req_head = 0;
            conn->rep_size = 0;
            conn->rep_head = 0;
            if (xchannel_send_raw(conn->client_ch, ok_resp, sizeof(ok_resp) - 1) != 0) {
                XLOGE("[http] failed to send CONNECT 200 response");
                shutdown_conn_slot(slot, "connect_200_send_failed");
                return;
            }
            XLOGD("[http] HTTPS tunnel established");
        } else {
            if (conn->req_size > 0) {
                if (xchannel_send_raw(conn->socks5_ch,
                                      conn->req_buf + conn->req_head,
                                      (size_t)conn->req_size) != 0) {
                    XLOGE("[http] failed to forward initial HTTP request");
                    shutdown_conn_slot(slot, "initial_request_send_failed");
                    return;
                }
                conn->req_size = 0;
                conn->req_head = 0;
            }
            XLOGD("[http] HTTP plaintext request forwarded");
        }
        break;
    }
    case CONN_STATE_SOCKS5_OK:
        // handled by xchannel tunnel callbacks
        break;
    default:
        break;
    }
}

static void socks5_write_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)mask;
    (void)submit_arg;
    int slot = (int)(intptr_t)clientData;
    if (slot < 0 || slot >= g_config.max_conns) return;

    ProxyConn* conn = &g_conn_list[slot];
    if (conn->state == CONN_STATE_CLOSED || conn->closing) return;
    if (conn->state == CONN_STATE_TCP_CONNECTING) {
        // using getsockopt(SO_ERROR) to confirm async connect success
        int err = 0;
        socklen_t errlen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &errlen) != 0 || err != 0) {
            XLOGE("[http] async connect failed, SO_ERROR=%d, host=%s", err, conn->host);
            shutdown_conn_slot(slot, "socks5_async_connect_failed");
            return;
        }

        XLOGD("[http] async connect succeeded, host=%s:%d", conn->host, conn->port);
        conn->state = CONN_STATE_AUTHING;
        int send_rc = socks5_send_handshake(conn);
        if (send_rc < 0) {
            XLOGE("[http] socks5 handshake send failed");
            shutdown_conn_slot(slot, "socks5_handshake_send_failed");
            return;
        }
        if (send_rc == 0) {
            return;
        }
        if (socks5_arm_read(slot) != 0) {
            XLOGE("[http] socks5 read registration failed after handshake");
            shutdown_conn_slot(slot, "socks5_read_register_failed");
            return;
        }
        return;
    }

    if (conn->rep_head < conn->rep_size) {
        int rc = socks5_flush_pending_write(conn);
        if (rc < 0) {
            XLOGE("[http] socks5 pending write failed, state=%d", conn->state);
            shutdown_conn_slot(slot, "socks5_pending_write_failed");
            return;
        }
        if (rc == 0) {
            return;
        }
        if (socks5_arm_read(slot) != 0) {
            XLOGE("[http] socks5 read registration failed after write");
            shutdown_conn_slot(slot, "socks5_read_register_failed");
            return;
        }
    } else if (conn->state == CONN_STATE_SOCKS5_OK) {
        // handled by xchannel tunnel callbacks
        xpoll_del_event(fd, XPOLL_WRITABLE);
    } else {
        xpoll_del_event(fd, XPOLL_WRITABLE);
    }
}

static void client_error_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    int slot = (int)(intptr_t)clientData;
    XLOGE("[http] Client socket %d error detected, locally closing connection, mask=%d", (int)fd, mask);
    close_conn_slot(slot);
}

static void socks5_error_cb(SOCKET_T fd, int mask, void *clientData, xPollRequest *submit_arg) {
    (void)submit_arg;
    int slot = (int)(intptr_t)clientData;
    XLOGE("[http] SOCKS5 socket %d error detected, locally closing connection, mask=%d", (int)fd, mask);
    close_conn_slot(slot);
}

// ===================== Exported Interface Functions =====================
// Start HTTP/HTTPS proxy service
int https_proxy_start(const HttpProxyConfig* config) {
    if (!config) {
        XLOGE("[http] Config or xpoll is null");
        return -1;
    }
    XLOGD("SOCKET5 SERVER ADDRESS:%s", config->socks5_server_ip);

    // Save configuration
    memcpy(&g_config, config, sizeof(HttpProxyConfig));

    // If SOCKS5 server address is 0.0.0.0 (listening on all interfaces),
    // replace with 127.0.0.1 for local connection since 0.0.0.0 can't be used as target address
    if (strcmp(g_config.socks5_server_ip, "0.0.0.0") == 0) {
        XLOGI("[http] SOCKS5 server address is 0.0.0.0, replacing with 127.0.0.1 for local connection");
        strncpy(g_config.socks5_server_ip, "127.0.0.1", sizeof(g_config.socks5_server_ip) - 1);
        g_config.socks5_server_ip[sizeof(g_config.socks5_server_ip) - 1] = '\0';
    }

    // Initialize connection list
    if (init_conn_list() != 0) {
        XLOGE("[http] Failed to initialize connection list");
        return -1;
    }

    // Create listening socket
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock == INVALID_SOCKET) {
        XLOGE("[http] Failed to create listening socket");
        return -1;
    }

    // Set socket reusable
    int opt = 1;
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // Bind port
    struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(g_config.listen_port)
    };

    if (bind(g_listen_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) != 0) {
        XLOGE("[http]  Failed to bind port");
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Start listening
    if (listen(g_listen_sock, SOMAXCONN) != 0) {
        XLOGE("[http]  Failed to listen");
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    // Set listening socket to non-blocking mode
    socket_set_nonblocking(g_listen_sock);

    // Register listening socket to xpoll
    if (xpoll_add_event(g_listen_sock, XPOLL_READABLE,
                        accept_cb, NULL, NULL, NULL) != 0) {
        XLOGE("[http] Failed to register listening socket event");
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    XLOGI("[http] HTTP/HTTPS sevice started, port: %d", g_config.listen_port);
    return 0;
}

void https_proxy_update(void) {
}

// Stop proxy service
void https_proxy_stop(void) {
    XLOGW("[http] try stop HTTP/HTTPS service...");
    // Close listening socket
    if (g_listen_sock != INVALID_SOCKET) {
        xpoll_del_event(g_listen_sock, XPOLL_ALL);
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
    }

    // Clean all connections
    cleanup_conn_list();

    XLOGW("[http] HTTP/HTTPS service stoped");
}

