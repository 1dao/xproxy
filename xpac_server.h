#ifndef XPAC_SERVER_H
#define XPAC_SERVER_H

#include "xsock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROXY_TYPE_HTTP,
    PROXY_TYPE_SOCKS5,
    PROXY_TYPE_AUTO
} ProxyType;

typedef struct {
    int http_proxy_port;
    int socks5_proxy_port;
    const char* bind_address;
    const char* proxy_host;
    const char* config_file;
    int enable_web_admin;
    int enable_proxy_whitelist;
    const char* admin_username;
    const char* admin_password;
} XpacConfig;

void xpac_init(const XpacConfig* config);
void xpac_uninit(void);

int xpac_handle_request(SOCKET_T client_sock, const char* req_buf, int req_len);
int xpac_proxy_client_allowed(const char* client_ip);

/* host 是否命中 @bulk 大流量分流域名（等于或以 ".域名" 结尾） */
int xpac_is_bulk_domain(const char* host);

#ifdef __cplusplus
}
#endif

#endif
