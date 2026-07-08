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

static HttpProxyConfig g_config;

/* Tunnel backpressure: when one side's send buffer reaches the high water we
 * pause reads on the other side; we resume (from https_proxy_update) once it
 * drains below the low water. High water sits below the 16 MB max_send so a
 * forward never gets rejected with -2 in the common case. */
#define HTTP_TUNNEL_SEND_HIGH_WATER (8u * 1024u * 1024u)
#define HTTP_TUNNEL_SEND_LOW_WATER  (2u * 1024u * 1024u)

// Check if host is a local address (127.0.0.1, localhost, 0.0.0.0, or actual local IP)
static int is_local_address(const char* host) {
    if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0 || strcmp(host, "0.0.0.0") == 0)
        return 1;

    if (g_config.proxy_host[0] && strcmp(host, g_config.proxy_host) == 0)
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

    /* Client request, accumulated until "\r\n\r\n"; HTTP (non-CONNECT)
     * requests are rewritten in place here and forwarded once the tunnel
     * is up. All other buffering lives inside the xchannels. */
    char req_buf[32767];
    int req_size;

    int is_https;
    char client_ip[INET_ADDRSTRLEN];
    char host[255];
    uint16_t port;
} ProxyConn;

// ===================== HTTP Parsing Functions =====================
// Parse CONNECT request, extract target host and port
int https_parse_connect(const char* req_buf, int req_len, char* target_host, int host_len, uint16_t* target_port);

// Parse normal HTTP request (GET/POST etc.), extract target host and port
int http_parse_request(char* req_buf, int* req_len, int buf_size, char* target_host, int host_len, uint16_t* target_port);

static int ascii_lower(int c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

static int header_name_equals(const char* line, size_t line_len, const char* name) {
    const char* colon = memchr(line, ':', line_len);
    if (!colon) return 0;

    const char* name_end = colon;
    while (name_end > line && (name_end[-1] == ' ' || name_end[-1] == '\t')) {
        name_end--;
    }

    size_t candidate_len = (size_t)(name_end - line);
    size_t name_len = strlen(name);
    if (candidate_len != name_len) return 0;

    for (size_t i = 0; i < name_len; i++) {
        if (ascii_lower((unsigned char)line[i]) != ascii_lower((unsigned char)name[i])) {
            return 0;
        }
    }
    return 1;
}

static int header_name_has_prefix(const char* line, size_t line_len, const char* prefix) {
    const char* colon = memchr(line, ':', line_len);
    if (!colon) return 0;

    const char* name_end = colon;
    while (name_end > line && (name_end[-1] == ' ' || name_end[-1] == '\t')) {
        name_end--;
    }

    size_t candidate_len = (size_t)(name_end - line);
    size_t prefix_len = strlen(prefix);
    if (candidate_len < prefix_len) return 0;

    for (size_t i = 0; i < prefix_len; i++) {
        if (ascii_lower((unsigned char)line[i]) != ascii_lower((unsigned char)prefix[i])) {
            return 0;
        }
    }
    return 1;
}

static int should_strip_forwarding_header(const char* line, size_t line_len) {
    static const char* strip_names[] = {
        "Forwarded",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "X-Forwarded-Server",
        "X-Original-Forwarded-For",
        "X-Real-IP",
        "X-Originating-IP",
        "X-Client-IP",
        "Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Cluster-Client-IP",
        "Via",
        "Proxy-Connection"
    };

    if (header_name_has_prefix(line, line_len, "X-Forwarded-")) {
        return 1;
    }

    for (size_t i = 0; i < sizeof(strip_names) / sizeof(strip_names[0]); i++) {
        if (header_name_equals(line, line_len, strip_names[i])) {
            return 1;
        }
    }
    return 0;
}

static int strip_forwarding_headers_inplace(char* req_buf, int* req_len, int buf_size) {
    if (!req_buf || !req_len || *req_len <= 0 || buf_size <= 0) return -1;
    if (*req_len >= buf_size) return -1;

    char* header_end = strstr(req_buf, "\r\n\r\n");
    if (!header_end) return 0;

    char* request_line_end = strstr(req_buf, "\r\n");
    if (!request_line_end || request_line_end > header_end) return -1;

    char* read = request_line_end + 2;
    char* headers_done = header_end + 2;
    char* write = read;
    int stripped = 0;

    while (read < headers_done) {
        char* line_end = strstr(read, "\r\n");
        if (!line_end || line_end > headers_done) return -1;

        size_t line_len = (size_t)(line_end - read);
        int strip = should_strip_forwarding_header(read, line_len);
        char* block_end = line_end + 2;

        if (strip) {
            stripped++;
            while (block_end < headers_done &&
                   (block_end[0] == ' ' || block_end[0] == '\t')) {
                char* continuation_end = strstr(block_end, "\r\n");
                if (!continuation_end || continuation_end > headers_done) return -1;
                block_end = continuation_end + 2;
            }
        } else {
            size_t block_len = (size_t)(block_end - read);
            if (write != read) memmove(write, read, block_len);
            write += block_len;
        }

        read = block_end;
    }

    if (stripped == 0) return 0;

    *write++ = '\r';
    *write++ = '\n';

    char* body = header_end + 4;
    int body_len = *req_len - (int)(body - req_buf);
    if (body_len > 0) {
        memmove(write, body, (size_t)body_len);
        write += body_len;
    }

    *req_len = (int)(write - req_buf);
    req_buf[*req_len] = '\0';
    XLOGD("[http] stripped %d forwarding/privacy headers", stripped);
    return 0;
}

// ===================== Global Variables =====================
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

    // 4. Convert absolute URL to relative path and remove forwarding hints.
    if (convert_http_request_inplace(req_buf, req_len, buf_size) != 0)
        return -1;
    if (strip_forwarding_headers_inplace(req_buf, req_len, buf_size) != 0)
        return -1;

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
        g_conn_list[i].req_size = 0;
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
static int add_new_client_conn(SOCKET_T client_sock, const char* client_ip) {
    int slot = find_free_conn_slot();
    if (slot == -1) return -1;

    g_conn_list[slot].client_sock = client_sock;
    g_conn_list[slot].socks5_sock = INVALID_SOCKET;
    g_conn_list[slot].client_ch = NULL;
    g_conn_list[slot].socks5_ch = NULL;
    g_conn_list[slot].state = CONN_STATE_NEW;
    g_conn_list[slot].closing = false;
    g_conn_list[slot].req_size = 0;
    strncpy(g_conn_list[slot].client_ip, client_ip ? client_ip : "", sizeof(g_conn_list[slot].client_ip) - 1);
    g_conn_list[slot].client_ip[sizeof(g_conn_list[slot].client_ip) - 1] = '\0';
    memset(g_conn_list[slot].req_buf, 0, sizeof(g_conn_list[slot].req_buf));

    g_conn_count++;
    XLOGI("[http] New connection added to slot %d, current connections: %d", slot, g_conn_count);

    return slot;
}

// Close and clean connection
static void close_conn_slot(int slot) {
    if (slot < 0 || slot >= g_config.max_conns) return;
    if (g_conn_list[slot].state == CONN_STATE_CLOSED) return;

    XLOGD("[http] Closing slot %d, client_sock=%d, socks5_sock=%d, current_state=%d",
          slot, (int)g_conn_list[slot].client_sock,
          (int)g_conn_list[slot].socks5_sock, (int)g_conn_list[slot].state);

    /* Both fds are owned by their xchannel from creation; destroying the
     * channel closes the fd (xchannel_destroy never re-enters close_cb). */
    if (g_conn_list[slot].client_ch) {
        xChannel* ch = g_conn_list[slot].client_ch;
        g_conn_list[slot].client_ch = NULL;
        xchannel_destroy(ch);
    }
    if (g_conn_list[slot].socks5_ch) {
        xChannel* ch = g_conn_list[slot].socks5_ch;
        g_conn_list[slot].socks5_ch = NULL;
        xchannel_destroy(ch);
    }

    // Reset connection structure
    g_conn_list[slot].client_sock = INVALID_SOCKET;
    g_conn_list[slot].socks5_sock = INVALID_SOCKET;
    g_conn_list[slot].state = CONN_STATE_CLOSED;
    g_conn_list[slot].closing = false;
    g_conn_list[slot].req_size = 0;
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
static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud);
static size_t socks5_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud);
static void socks5_channel_connect_cb(xChannel* ch, void* ud);
static void tunnel_channel_close_cb(xChannel* ch, const char* reason, void* ud);
static void tunnel_channel_eof_cb(xChannel* ch, const char* reason, void* ud);
static int handle_client_request(int slot);

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

    /* Every open fd is wrapped by an xchannel from creation, so teardown is
     * uniform: close the channels and let tunnel_channel_close_cb finish via
     * close_conn_slot. Closing the first channel may already tear the whole
     * slot down, hence the state re-check. */
    xChannel* c = conn->client_ch;
    xChannel* s = conn->socks5_ch;
    if (c) xchannel_close(c, reason);
    if (s && conn->state != CONN_STATE_CLOSED) {
        xchannel_close(s, reason);
    }
    if (conn->state != CONN_STATE_CLOSED &&
        !conn->client_ch && !conn->socks5_ch) {
        close_conn_slot(slot);
    }
}

static void shutdown_conn_from_ptr(ProxyConn* conn, const char* reason) {
    int slot = proxy_conn_slot(conn);
    if (slot >= 0) shutdown_conn_slot(slot, reason);
}

static void close_conn_from_ptr(ProxyConn* conn) {
    int slot = proxy_conn_slot(conn);
    if (slot >= 0) close_conn_slot(slot);
}

/* Create one tunnel-leg channel. Both legs use RAW framing and the shared
 * close/eof callbacks; only packet_cb (and connect_cb for the SOCKS5 leg)
 * differ. The channel owns `fd` from here on. */
static xChannel* tunnel_channel_create(SOCKET_T fd, ProxyConn* conn,
                                       xChannelPacketProc packet_cb,
                                       xChannelConnectProc connect_cb) {
    xChannelConfig cfg = XCHANNEL_CONFIG_INIT;
    cfg.frame = XCHANNEL_FRAME_RAW;
    cfg.connect_cb = connect_cb;
    cfg.packet_cb = packet_cb;
    cfg.close_cb = tunnel_channel_close_cb;
    cfg.eof_cb = tunnel_channel_eof_cb;
    cfg.userdata = conn;

    xChannel* ch = xchannel_create(fd, &cfg);
    if (!ch) return NULL;
    xchannel_set_max_send(ch, 16 * 1024 * 1024);
    xchannel_set_max_recv(ch, 16 * 1024 * 1024);
    return ch;
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

/* Forward one tunnel direction with backpressure. `ch` is the source channel
 * (the one that received data); `dst` is where it goes. On dst backpressure we
 * pause reads on `ch` and hold the bytes in its input buffer (return 0), or
 * proactively pause once dst crosses the high water. https_proxy_update()
 * resumes `ch` after dst drains. Returns bytes consumed (xchannel RAW semantics). */
static size_t tunnel_forward(xChannel* ch, xChannel* dst, ProxyConn* conn,
                             const char* data, size_t len, const char* what) {
    int rc = xchannel_send_raw(dst, data, len);
    if (rc == -2) {
        /* Destination at its send cap: keep the data buffered in the source and
         * stop reading until it drains. */
        xchannel_pause_read(ch);
        return 0;
    }
    if (rc != 0) {
        XLOGE("[http] tunnel %s send failed", what);
        shutdown_conn_from_ptr(conn, what);
        return len;
    }

    size_t send_buf = 0;
    xchannel_get_stats(dst, &send_buf, NULL, NULL, NULL);
    if (send_buf >= HTTP_TUNNEL_SEND_HIGH_WATER) {
        xchannel_pause_read(ch);
    }
    return len;
}

static size_t client_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud) {
    ProxyConn* conn = (ProxyConn*)ud;
    if (!conn || conn->closing) return len;
    if (len == 0) return 0;

    switch (conn->state) {
    case CONN_STATE_NEW: {
        /* Accumulate the request; everything received before the tunnel is up
         * (headers plus any early body bytes) is forwarded from req_buf once
         * the SOCKS5 handshake completes. */
        size_t room = sizeof(conn->req_buf) - 1 - (size_t)conn->req_size;
        if (len > room) {
            XLOGE("[http] Request too large, closing connection");
            shutdown_conn_from_ptr(conn, "request_too_large");
            return len;
        }
        memcpy(conn->req_buf + conn->req_size, data, len);
        conn->req_size += (int)len;
        conn->req_buf[conn->req_size] = '\0';

        if (strstr(conn->req_buf, "\r\n\r\n") == NULL) {
            return len; /* headers incomplete, keep reading */
        }

        int ret = handle_client_request(proxy_conn_slot(conn));
        if (ret == -2) {
            XLOGI("[http] PAC request handled, closing connection");
            shutdown_conn_from_ptr(conn, "pac_handled");
        } else if (ret != 0) {
            XLOGE("[http] request handling failed, closing connection");
            shutdown_conn_from_ptr(conn, "request_error");
        } else {
            /* Client bytes that race ahead of the SOCKS5 handshake stay in
             * the channel input buffer; resumed once the tunnel is up. */
            xchannel_pause_read(ch);
        }
        return len;
    }

    case CONN_STATE_SOCKS5_OK:
        if (!conn->socks5_ch) return len;
        return tunnel_forward(ch, conn->socks5_ch, conn, data, len,
                              "tunnel_client_send_failed");

    default:
        /* SOCKS5 handshake still in flight: hold the data in the channel
         * input buffer until the tunnel opens. */
        return 0;
    }
}

/* Connect completion for the SOCKS5 leg (fired by xchannel_attach_connect;
 * a failed connect closes the channel with "connect_error" instead). */
static void socks5_channel_connect_cb(xChannel* ch, void* ud) {
    ProxyConn* conn = (ProxyConn*)ud;
    if (!conn || conn->closing || conn->state != CONN_STATE_TCP_CONNECTING) return;

    XLOGD("[http] connect succeeded, host=%s:%d", conn->host, conn->port);
    conn->state = CONN_STATE_AUTHING;

    static const char handshake_req[] = {0x05, 0x01, 0x00};
    if (xchannel_send_raw(ch, handshake_req, sizeof(handshake_req)) != 0) {
        XLOGE("[http] socks5 handshake send failed");
        shutdown_conn_from_ptr(conn, "socks5_handshake_send_failed");
    }
}

static size_t socks5_channel_packet_cb(xChannel* ch, const char* data, size_t len, void* ud) {
    ProxyConn* conn = (ProxyConn*)ud;
    if (!conn || conn->closing) return len;
    if (len == 0) return 0;

    switch (conn->state) {
    case CONN_STATE_AUTHING: {
        if (len < 2) return 0; /* need the 2-byte method reply */
        const uint8_t* resp = (const uint8_t*)data;
        if (resp[0] != 0x05 || resp[1] != 0x00) {
            XLOGE("socks5 domain auth failed (only no-auth supported)");
            shutdown_conn_from_ptr(conn, "socks5_auth_failed");
            return len;
        }

        /* Send the CONNECT request: VER CMD RSV ATYP=domain LEN host port */
        size_t domain_len = strlen(conn->host);
        if (domain_len == 0 || domain_len > 255) {
            XLOGE("socks5 domain connect request build failed, host=%s", conn->host);
            shutdown_conn_from_ptr(conn, "socks5_connect_build_failed");
            return len;
        }
        uint8_t connect_req[5 + 255 + 2];
        connect_req[0] = 0x05;
        connect_req[1] = 0x01;
        connect_req[2] = 0x00;
        connect_req[3] = 0x03;
        connect_req[4] = (uint8_t)domain_len;
        memcpy(connect_req + 5, conn->host, domain_len);
        uint16_t port_nbo = htons(conn->port);
        memcpy(connect_req + 5 + domain_len, &port_nbo, 2);

        conn->state = CONN_STATE_CONNECTING;
        if (xchannel_send_raw(ch, (const char*)connect_req,
                              5 + domain_len + 2) != 0) {
            XLOGE("socks5 domain connect send failed, host=%s", conn->host);
            shutdown_conn_from_ptr(conn, "socks5_connect_send_failed");
            return len;
        }
        return 2; /* leave any further bytes for the CONNECTING state */
    }

    case CONN_STATE_CONNECTING: {
        int expected = socks5_reply_expected_len((const uint8_t*)data, (int)len);
        if (expected < 0) {
            XLOGE("[http] invalid SOCKS5 connect response");
            shutdown_conn_from_ptr(conn, "socks5_connect_bad_response");
            return len;
        }
        if (expected == 0 || (int)len < expected) return 0; /* need more */

        const uint8_t* resp = (const uint8_t*)data;
        if (resp[0] != 0x05) {
            XLOGE("socks5 domain connect invalid version: %d", resp[0]);
            shutdown_conn_from_ptr(conn, "socks5_connect_bad_version");
            return len;
        }
        if (resp[1] != 0x00) {
            XLOGE("socks5 domain connect target failed, code: %d", resp[1]);
            shutdown_conn_from_ptr(conn, "socks5_connect_failed");
            return len;
        }

        conn->state = CONN_STATE_SOCKS5_OK;

        /* HTTPS answers the client's CONNECT; HTTP forwards the buffered
         * (already rewritten) request. */
        if (conn->is_https) {
            static const char ok_resp[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
            conn->req_size = 0;
            if (!conn->client_ch ||
                xchannel_send_raw(conn->client_ch, ok_resp, sizeof(ok_resp) - 1) != 0) {
                XLOGE("[http] failed to send CONNECT 200 response");
                shutdown_conn_from_ptr(conn, "connect_200_send_failed");
                return len;
            }
            XLOGD("[http] HTTPS tunnel established");
        } else if (conn->req_size > 0) {
            if (xchannel_send_raw(ch, conn->req_buf, (size_t)conn->req_size) != 0) {
                XLOGE("[http] failed to forward initial HTTP request");
                shutdown_conn_from_ptr(conn, "initial_request_send_failed");
                return len;
            }
            conn->req_size = 0;
            XLOGD("[http] HTTP plaintext request forwarded");
        }

        /* Release client bytes held back during the handshake. */
        if (conn->client_ch && xchannel_resume_read(conn->client_ch) != 0) {
            shutdown_conn_from_ptr(conn, "client_resume_failed");
            return len;
        }
        /* Any remaining bytes re-enter this callback in SOCKS5_OK state. */
        return (size_t)expected;
    }

    case CONN_STATE_SOCKS5_OK:
        if (!conn->client_ch) return len;
        return tunnel_forward(ch, conn->client_ch, conn, data, len,
                              "tunnel_socks5_send_failed");

    default:
        return 0; /* no data expected before connect completes */
    }
}

static void tunnel_channel_close_cb(xChannel* ch, const char* reason, void* ud) {
    ProxyConn* conn = (ProxyConn*)ud;
    XLOGW("[http] tunnel channel closed: reason=%s", reason ? reason : "unknown");
    if (!conn) {
        xchannel_destroy(ch);
        return;
    }

    bool half_closed = (reason && strcmp(reason, "half_closed") == 0);

    if (conn->client_ch == ch) {
        conn->client_ch = NULL;
        conn->client_sock = INVALID_SOCKET;
    }
    if (conn->socks5_ch == ch) {
        conn->socks5_ch = NULL;
        conn->socks5_sock = INVALID_SOCKET;
    }

    xchannel_destroy(ch);

    if (half_closed) {
        if (!conn->client_ch && !conn->socks5_ch) {
            close_conn_from_ptr(conn);
        }
        return;
    }

    close_conn_from_ptr(conn);
}

static void tunnel_channel_eof_cb(xChannel* ch, const char* reason, void* ud) {
    ProxyConn* conn = (ProxyConn*)ud;
    XLOGW("[http] tunnel channel EOF: reason=%s", reason ? reason : "unknown");
    if (!conn) return;

    if (conn->state != CONN_STATE_SOCKS5_OK) {
        /* EOF while the request/handshake is still in flight: no tunnel can
         * be produced anymore, drop the connection. */
        shutdown_conn_from_ptr(conn, "handshake_eof");
        return;
    }

    if (conn->client_ch == ch && conn->socks5_ch) {
        if (xchannel_shutdown_write_after_flush(conn->socks5_ch, "client_eof") != 0) {
            shutdown_conn_from_ptr(conn, "client_eof_shutdown_failed");
        }
    } else if (conn->socks5_ch == ch && conn->client_ch) {
        if (xchannel_shutdown_write_after_flush(conn->client_ch, "socks5_eof") != 0) {
            shutdown_conn_from_ptr(conn, "socks5_eof_shutdown_failed");
        }
    }
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

    if (!xpac_proxy_client_allowed(conn->client_ip)) {
        XLOGW("[http] Reject proxy request from %s to %s:%d: not in proxy whitelist",
              conn->client_ip, conn->host, conn->port);
        return -1;
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
    if (ret != 0 && !socket_check_eagain()) {
        XLOGE("[http] connect() failed immediately, host=%s", conn->host);
        CLOSE_SOCKET(socks5_sock);
        return -1;
    }

    conn->socks5_ch = tunnel_channel_create(socks5_sock, conn,
                                            socks5_channel_packet_cb,
                                            socks5_channel_connect_cb);
    if (!conn->socks5_ch) {
        XLOGE("[http] Failed to create SOCKS5 channel");
        CLOSE_SOCKET(socks5_sock);
        return -1;
    }
    conn->socks5_sock = socks5_sock;
    conn->state = CONN_STATE_TCP_CONNECTING;
    conn->is_https = is_https;

    /* attach_connect drives both the in-progress and the already-connected
     * case: the first WRITABLE event checks SO_ERROR and fires connect_cb
     * (or closes the channel with "connect_error"). */
    if (xchannel_attach_connect(conn->socks5_ch) != 0) {
        XLOGE("[http] Failed to attach SOCKS5 channel");
        xchannel_destroy(conn->socks5_ch);
        conn->socks5_ch = NULL;
        conn->socks5_sock = INVALID_SOCKET;
        return -1;
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
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        XLOGI("[http] New client connected: %s:%d (socket %d)",
               client_ip, ntohs(client_addr.sin_port), (int)client_sock);

        // Add new connection to list
        int slot = add_new_client_conn(client_sock, client_ip);
        if (slot == -1) {
            XLOGE("[http] Connection list full, rejecting new connection");
            CLOSE_SOCKET(client_sock);
            return;
        }

        socket_set_nonblocking(client_sock);

        ProxyConn* conn = &g_conn_list[slot];
        conn->client_ch = tunnel_channel_create(client_sock, conn,
                                                client_channel_packet_cb, NULL);
        if (!conn->client_ch) {
            XLOGE("[http] Failed to create client channel");
            CLOSE_SOCKET(client_sock);
            conn->client_sock = INVALID_SOCKET;
            close_conn_slot(slot);
            return;
        }
        if (xchannel_attach(conn->client_ch) != 0) {
            XLOGE("[http] Failed to attach client channel");
            close_conn_slot(slot);
        }
    } else if (!socket_check_eagain()) {
        XLOGE("[http] accept failed, ERRNO=%d", GET_ERRNO());
    }
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

/* Resume a paused tunnel direction once its destination has drained below the
 * low water. `src` was paused because `dst` filled up; re-read `src` to flush
 * any held bytes and re-arm its reads. Returns -1 if the resume failed. */
static int tunnel_resume_if_drained(xChannel* src, xChannel* dst) {
    if (!src || !dst || !xchannel_is_read_paused(src)) return 0;

    size_t send_buf = 0;
    xchannel_get_stats(dst, &send_buf, NULL, NULL, NULL);
    if (send_buf > HTTP_TUNNEL_SEND_LOW_WATER) return 0;  /* still draining */

    return xchannel_resume_read(src);
}

void https_proxy_update(void) {
    if (!g_conn_list) return;

    for (int slot = 0; slot < g_config.max_conns; slot++) {
        ProxyConn* conn = &g_conn_list[slot];
        if (conn->state != CONN_STATE_SOCKS5_OK || conn->closing) continue;

        /* Download: socks5_ch reads paused because client_ch (toward the real
         * client) backed up. Resuming here lets backpressure propagate all the
         * way to the SSH/remote side instead of dropping the connection. */
        if (tunnel_resume_if_drained(conn->socks5_ch, conn->client_ch) != 0) {
            shutdown_conn_slot(slot, "tunnel_resume_socks5_failed");
            continue;
        }
        /* Upload: client_ch reads paused because socks5_ch backed up. */
        if (tunnel_resume_if_drained(conn->client_ch, conn->socks5_ch) != 0) {
            shutdown_conn_slot(slot, "tunnel_resume_client_failed");
            continue;
        }
    }
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
