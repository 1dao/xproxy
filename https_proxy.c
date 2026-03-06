#include "https_proxy.h"
#include "socket_util.h"
#include "xpoll.h"
#include "xpac_server.h"
#ifdef LOG_TAG
    #undef LOG_TAG
#endif
#define LOG_TAG "xhttp"
#include "xlog.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// ===================== Connection State =====================
typedef enum {
    CONN_STATE_NEW,
    CONN_STATE_AUTHING,
    CONN_STATE_CONNECTING,
    CONN_STATE_SOCKS5_OK,
    CONN_STATE_CLOSED
} ConnState;

// ===================== Connection Structure =====================
typedef struct {
    SOCKET_T client_sock;
    SOCKET_T socks5_sock;
    ConnState state;

    // request buf
    char req_buf[32767];
    int req_head;
    int req_size;

    // response buf
    char rep_buf[65536];
    int rep_head;
    int rep_size;

    int is_https;
    char host[128];
    uint16_t port;
} ProxyConn;

// ===================== HTTP Parsing Functions =====================
// Parse CONNECT request, extract target host and port
int https_parse_connect(const char* req_buf, int req_len, char* target_host, int host_len, uint16_t* target_port);

// Send 200 Connection Established response to client
int https_send_200(SOCKET_T client_sock);

// Parse normal HTTP request (GET/POST etc.), extract target host and port
int http_parse_request(char* req_buf, int* req_len, int buf_size, char* target_host, int host_len, uint16_t* target_port);

// ===================== Global Variables =====================
static HttpProxyConfig g_config;
static ProxyConn* g_conn_list = NULL;
static int g_conn_count = 0;
static int g_running = 1;
static SOCKET_T g_listen_sock = INVALID_SOCKET;  // 监听套接字
static xPollState* g_xpoll = NULL;

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

// Send 200 Connection Established response to client
int https_send_200(SOCKET_T client_sock) {
    // const char* resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
    // return send(client_sock, resp, strlen(resp), 0);
    const char* resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
    int len = strlen(resp);
    int sent = send(client_sock, resp, len, 0);
    return sent == len ? 0 : -1;
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
    if (space2 - url_start < 7) return 0; // "http://" 最短 7 字节
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
        memmove(req_buf + method_len + 1, slash, path_len + remaining_len);
        *req_len = method_len + 1 + path_len + remaining_len;

        // Safety check: ensure we don't exceed buffer
        if (*req_len >= buf_size) {
            XLOGE("[http] slash convert_http_request_inplace overwrite...");
            XLOGE("[http] slash convert_http_request_inplace overwrite...");
            XLOGE("[http] slash convert_http_request_inplace overwrite...");
            return -1;
        }
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
    XLOGD("convert before:");
    XLOGD("\n%s\n", req_buf);
    convert_http_request_inplace(req_buf, req_len, buf_size);
    XLOGD("convert after:");
    XLOGD("\n%s\n", req_buf);

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
        g_conn_list[i].state = CONN_STATE_CLOSED;
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

// Find connection slot by socket
static int find_conn_slot_by_sock(SOCKET_T sock) {
    for (int i = 0; i < g_config.max_conns; i++) {
        if (g_conn_list[i].client_sock == sock || g_conn_list[i].socks5_sock == sock) {
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
    g_conn_list[slot].state = CONN_STATE_NEW;
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

    if (g_conn_list[slot].client_sock != INVALID_SOCKET) {
        if (g_xpoll) {
            xpoll_del_event(g_xpoll, g_conn_list[slot].client_sock, XPOLL_ALL);
        }
        CLOSE_SOCKET(g_conn_list[slot].client_sock);
    }

    if (g_conn_list[slot].socks5_sock != INVALID_SOCKET) {
        if (g_xpoll) {
            xpoll_del_event(g_xpoll, g_conn_list[slot].socks5_sock, XPOLL_ALL);
        }
        CLOSE_SOCKET(g_conn_list[slot].socks5_sock);
    }

    // Reset connection structure
    g_conn_list[slot].client_sock = INVALID_SOCKET;
    g_conn_list[slot].socks5_sock = INVALID_SOCKET;
    g_conn_list[slot].state = CONN_STATE_CLOSED;
    g_conn_list[slot].req_size = 0; g_conn_list[slot].req_head = 0;
    g_conn_list[slot].rep_size = 0; g_conn_list[slot].rep_head = 0;
    memset(g_conn_list[slot].req_buf, 0, sizeof(g_conn_list[slot].req_buf));

    if (g_conn_count > 0) g_conn_count--;

    XLOGI("[http] Slot %d connection closed, current connections: %d", slot, g_conn_count);
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
static void accept_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData);
static void client_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData);
static void socks5_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData);
static void client_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData);
static void socks5_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData);

// ===================== Core Processing Functions =====================
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
    if (strcmp(conn->host, "127.0.0.1") == 0 || strcmp(conn->host, "localhost") == 0) {
        if (conn->port == g_config.listen_port) {
            // Handle management request
            return xpac_handle_request(conn->client_sock, conn->req_buf, conn->req_size)==1?-2:-1;
        }
    }

    // Connect to Socks5 server
    SOCKET_T socks5_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (socks5_sock == INVALID_SOCKET) {
        XLOGE("[http] create socks4 socket failed");
        return -1;
    }

    struct sockaddr_in socks5_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr(g_config.socks5_server_ip),
        .sin_port = htons(g_config.socks5_server_port)
    };

    if (connect(socks5_sock, (struct sockaddr*)&socks5_addr, sizeof(socks5_addr)) != 0) {
        XLOGE("[http] Failed to connect Socks5 server, from host=%s, client socket=%d", conn->host, (int)conn->client_sock);
        CLOSE_SOCKET(socks5_sock);
        return -1;
    }

    // // Socks5 域名直接转发（建立与目标服务器的连接）
    // if (socks5_connect_domain(socks5_sock, conn->host, conn->port) != 0) {
    //     fprintf(stderr, "[请求处理] Socks5 域名转发失败 (目标: %s:%d, SOCKS5: %s:%d)",
    //             conn->host, conn->port,
    //             g_config.socks5_server_ip, g_config.socks5_server_port);
    //     CLOSE_SOCKET(socks5_sock);
    //     return -1;
    // } else {
    //     //printf("[调试] SOCKS5 域名转发成功:%s:%d", conn->host, conn->port);
    // }

    // 1. First step: Socks5 no-authentication handshake (same as IPv4 mode)
    uint8_t handshake_req[] = {0x05, 0x01, 0x00}; // 简化：直接用数组代替结构体
    if (send(socks5_sock, (const char*)handshake_req, sizeof(handshake_req), 0) <= 0) {
        XLOGE("socks5 domain handshake send failed");
        CLOSE_SOCKET(socks5_sock);
        return -1;
    }

    // // HTTPS 需返回 200 响应，建立隧道
    // if (is_https) {
    //     https_send_200(conn->client_sock);
    //     printf("[请求处理] HTTPS 隧道建立完成");
    // } else {
    //     // HTTP 直接转发原始请求到目标服务器
    //     send(socks5_sock, (const char*)conn->req_buf, conn->req_size, 0);
    //     printf("[请求处理] HTTP 明文请求转发完成");
    // }

    // Update connection state and Socks5 socket
    conn->socks5_sock = socks5_sock;
    conn->state = CONN_STATE_AUTHING;
    conn->is_https = is_https;

    if (xpoll_add_event(g_xpoll, socks5_sock, XPOLL_READABLE,
                        socks5_read_cb, NULL, socks5_error_cb, (void*)(INT_PTR)slot) != 0) {
        XLOGE("[http] Failed to register SOCKS5 socket event");
        CLOSE_SOCKET(socks5_sock);
        return -1;
    }

    // Immediately set to non-blocking mode
    socket_set_nonblocking(socks5_sock);
    return 0;
}

// Ring send: sends data from the head pointer (head) and swipes the head pointer backwards after sending
static int rb_send(SOCKET_T fd, char* buf, int capacity, int* head, int* size) {
    if (*size == 0) return 0; // no data

    // Calculate contiguous memory length to the end of the physics
    int contiguous_data = capacity - *head;
    if (contiguous_data > *size)
        contiguous_data = *size; // If not reversed, only the length owned is actually issued

    int ret = send(fd, buf + *head, contiguous_data, 0);
    if (ret > 0) {
        *head = (*head + ret) % capacity; // Move the read pointer (may wrap around 0)
        *size -= ret;                     // reduce sent
    }
    return ret;
}

// Ring reception: find the tail pointer gap and read the network card data into
static int rb_recv(SOCKET_T fd, char* buf, int capacity, int* head, int* size) {
    if (*size == capacity) return 0; // 缓冲区满

    // If the buffer is empty, reset the pointer immediately for maximum continuous read space
    if (*size == 0)
        *head = 0;

    int tail = (*head + *size) % capacity;
    int contiguous_space;

    if (tail >= *head) {
        // The tail is on the right side of the read pointer, first read to the end of the physics
        contiguous_space = capacity - tail;
    } else {
        // has been folded back, the tail is on the left side of the reading pointer, you can only read
        contiguous_space = *head - tail;
    }

    int ret = recv(fd, buf + tail, contiguous_space, 0);
    if (ret > 0) {
        *size += ret;
    }
    return ret;
}

static int forward2socks5(ProxyConn* conn) {
    // 1. Send existing backlog data in buf to socks5 as much as possible
    if (conn->req_size > 0) {
        int ret = rb_send(conn->socks5_sock, conn->req_buf, sizeof(conn->req_buf),
                          &conn->req_head, &conn->req_size);
        if (ret < 0 && !socket_check_eagain()) {
            XLOGE("[http] forward2socks5 send failed");
            return -1;
        }
    }

    // 2. Read new data from client if buf is still free
    if (conn->req_size < sizeof(conn->req_buf)) {
        int ret = rb_recv(conn->client_sock, conn->req_buf, sizeof(conn->req_buf),
                          &conn->req_head, &conn->req_size);
        if (ret == 0) {
            XLOGE("[http] forward2socks5, client closed");
            return -1; // 对端关闭
        } else if (ret < 0 && !socket_check_eagain()) {
            XLOGE("[http] forward2socks5 recv failed");
            return -1;
        }
    }

    // 3. If you just read the new data, take advantage of the system call and send it again
    if (conn->req_size > 0) {
        int ret = rb_send(conn->socks5_sock, conn->req_buf, sizeof(conn->req_buf),
                          &conn->req_head, &conn->req_size);
        if (ret < 0 && !socket_check_eagain()) return -1;
    }

    return 0;
}

static int forward2client(ProxyConn* conn) {
    // The logic is exactly the same as above, only in the opposite direction
    if (conn->rep_size > 0) {
        int ret = rb_send(conn->client_sock, conn->rep_buf, sizeof(conn->rep_buf),
                          &conn->rep_head, &conn->rep_size);
        if (ret < 0 && !socket_check_eagain()) return -1;
    }

    if (conn->rep_size < sizeof(conn->rep_buf)) {
        int ret = rb_recv(conn->socks5_sock, conn->rep_buf, sizeof(conn->rep_buf),
                          &conn->rep_head, &conn->rep_size);
        if (ret == 0) return -1;
        if (ret < 0 && !socket_check_eagain()) return -1;
    }

    if (conn->rep_size > 0) {
        int ret = rb_send(conn->client_sock, conn->rep_buf, sizeof(conn->rep_buf),
                          &conn->rep_head, &conn->rep_size);
        if (ret < 0 && !socket_check_eagain()) return -1;
    }

    return 0;
}

static void accept_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
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
        if (xpoll_add_event(g_xpoll, client_sock, XPOLL_READABLE,
                            client_read_cb, NULL, client_error_cb, (void*)(INT_PTR)slot) != 0) {
            XLOGE("[http] Connection list full, rejecting new connection");
            close_conn_slot(slot);
        }
        socket_set_nonblocking(client_sock);
    }
}

// Client read callback
static void client_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    int slot = (int)(intptr_t)clientData;
    if (slot < 0 || slot >= g_config.max_conns) return;

    ProxyConn* conn = &g_conn_list[slot];
    if (conn->state == CONN_STATE_CLOSED) return;

    if (conn->state == CONN_STATE_NEW) {
        // New connection: read client request (unparsed)
        int recv_len = recv(conn->client_sock, conn->req_buf + conn->req_size,
                           sizeof(conn->req_buf) - conn->req_size - 1, 0);

        if (recv_len <= 0) {
            if(!socket_check_eagain() && recv_len < 0) {
                XLOGE("[http] Client socket %d closed, ERRNO=%d", (int)conn->client_sock, GET_ERRNO());
                close_conn_slot(slot);
            }
            return;
        }

        // Update request buffer length
        conn->req_size += recv_len;
        conn->req_buf[conn->req_size] = '\0';

        // Try to parse request (complete request received)
        if (strstr(conn->req_buf, "\r\n\r\n") != NULL) {
            int ret = handle_client_request(slot);
            if(ret==-2)
                XLOGI("[http] PAC request handled, closing connection");
            else if (ret != 0) {
                XLOGE("[http] PAC request handling exception, closing connection");
                close_conn_slot(slot);
            }
        } else if (conn->req_size >= sizeof(conn->req_buf) - 1) {
            // Request too large
            XLOGE("[http] Request too large, closing connection");
            close_conn_slot(slot);
        }
    } else if (conn->state == CONN_STATE_SOCKS5_OK) {
        // trans to socks5
        if (forward2socks5(conn) != 0) {
            XLOGE("[Read Callback] Client → Socks5 forwarding failed, closing connection");
            close_conn_slot(slot);
        }
    }
}

static inline int socks5_send_connect(SOCKET_T fd, char* host, uint16_t port) {
    // 2. Second step: construct domain name mode connection request (variable length, need dynamic memory allocation)
    int domain_len = strlen(host);
    // Total message length: fixed header (5 bytes) + domain name length (domain_len) + port (2 bytes)
    int req_total_len = 5 + domain_len + 2;
    uint8_t* connect_req = (uint8_t*)malloc(req_total_len);
    if (connect_req == NULL) {
        XLOGE("socks5 domain req malloc failed");
        return -1;
    }

    // Fill fixed header fields
    connect_req[0] = 0x05; // ver: Socks5 protocol version
    connect_req[1] = 0x01; // cmd: TCP connection request
    connect_req[2] = 0x00; // rsv: reserved field, must be 0
    connect_req[3] = 0x03; // atyp: domain name type (0x03)
    connect_req[4] = (uint8_t)domain_len; // domain name length (1 byte, max 255)

    // Fill variable length: domain name content
    memcpy(connect_req + 5, host, domain_len);

    // Fill port (network byte order, placed after domain name)
    uint16_t target_port_nbo = htons(port);
    memcpy(connect_req + 5 + domain_len, &target_port_nbo, 2);

    // 3. Third step: send domain name connection request
    if (send(fd, (const char*)connect_req, req_total_len, 0) <= 0) {
        XLOGE("socks5 domain connect send failed");
        free(connect_req); // Memory release: avoid memory leak
        return -1;
    }
    free(connect_req); // Free allocated memory
    return 0;
}

// SOCKS5 server read callback
static void socks5_read_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    int slot = (int)(intptr_t)clientData;
    if (slot < 0 || slot >= g_config.max_conns) return;

    ProxyConn* conn = &g_conn_list[slot];
    switch (conn->state) {
    case CONN_STATE_AUTHING:{
        // Receive handshake response
        uint8_t handshake_resp[2];
        if (recv(fd, handshake_resp, sizeof(handshake_resp), 0) <= 0) {
            XLOGE("socks5 domain handshake recv failed");
            close_conn_slot(slot);
            return;
        }
        if (handshake_resp[0] != 0x05 || handshake_resp[1] != 0x00) {
            XLOGE("socks5 domain auth failed (only no-auth supported)");
            close_conn_slot(slot);
            return;
        }
        if(socks5_send_connect(fd, conn->host, conn->port)!=0) {
            XLOGE("socks5 domain connect send failed, host=%s", conn->host);
            close_conn_slot(slot);
            return;
        }
        conn->state = CONN_STATE_CONNECTING;
        break;
    }
    case CONN_STATE_CONNECTING: {
        uint8_t connect_resp[10]; // Response fixed 10 bytes (regardless of ATYP)
        if (recv(conn->socks5_sock, (char*)connect_resp, sizeof(connect_resp), 0) <= 0) {
            XLOGE("socks5 domain connect recv failed");
            close_conn_slot(slot);
            return;
        }

        // Verify response result: 0x00 means connection successful
        if (connect_resp[1] != 0x00) {
            XLOGE("socks5 domain connect target failed, code: %d", connect_resp[1]);
            close_conn_slot(slot);
            return;
        }
        conn->state = CONN_STATE_SOCKS5_OK;

        // HTTPS needs to return 200 response, establish tunnel
        if (conn->is_https) {
            conn->req_size = 0;conn->req_head = 0;
            conn->rep_size = 0;conn->rep_head = 0;
            https_send_200(conn->client_sock);
            XLOGD("[http] HTTPS tunnel established");
        } else {
            forward2socks5(conn);
            XLOGD("[http] HTTP plaintext request forwarded");
        }
        break;
    }
    case CONN_STATE_SOCKS5_OK:
        // Forward Socks5 server data to client
        if (forward2client(conn) != 0) {
            XLOGE("[http] Socks5 → Client forwarding failed, closing connection");
            close_conn_slot(slot);
        }
        break;
    default:
        break;
    }
}

static void client_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    int slot = (int)(intptr_t)clientData;
    XLOGE("[http] Client socket %d error, closing connection", (int)fd);
    close_conn_slot(slot);
}

static void socks5_error_cb(xPollState *loop, SOCKET_T fd, int mask, void *clientData) {
    int slot = (int)(intptr_t)clientData;
    XLOGE("[http] SOCKS5 socket %d error, closing connection", (int)fd);
    close_conn_slot(slot);
}

// ===================== Exported Interface Functions =====================
// Start HTTP/HTTPS proxy service
int https_proxy_start(const HttpProxyConfig* config, xPollState *xpoll) {
    if (!config || !xpoll) {
        XLOGE("[http] Config or xpoll is null");
        return -1;
    }

    // Save configuration
    memcpy(&g_config, config, sizeof(HttpProxyConfig));
    g_xpoll = xpoll;

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
    //setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

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
    if (xpoll_add_event(g_xpoll, g_listen_sock, XPOLL_READABLE,
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
    g_running = 0;

    // Close listening socket
    if (g_listen_sock != INVALID_SOCKET) {
        if (g_xpoll) {
            xpoll_del_event(g_xpoll, g_listen_sock, XPOLL_ALL);
        }
        CLOSE_SOCKET(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
    }

    // Clean all connections
    cleanup_conn_list();

    XLOGW("[http] HTTP/HTTPS service stoped");
}
