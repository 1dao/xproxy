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
    const char* admin_password;
} XpacConfig;

void xpac_init(const XpacConfig* config);
void xpac_uninit(void);

int xpac_handle_request(SOCKET_T client_sock, const char* req_buf, int req_len);

#ifdef __cplusplus
}
#endif

#endif
