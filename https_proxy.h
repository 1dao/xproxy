#ifndef HTTPS_PROXY_H
#define HTTPS_PROXY_H

#include "socket_util.h"
#include <stdint.h>

// Forward declaration
typedef struct xPollState xPollState;

// ===================== 配置结构 =====================
typedef struct {
    char socks5_server_ip[256];
    int32_t socks5_server_port;
    int32_t listen_port;
    int32_t max_conns;
} HttpProxyConfig;

// ===================== 接口函数 =====================
// 启动 HTTP/HTTPS 代理服务
int https_proxy_start(const HttpProxyConfig* config, xPollState *xpoll);

// 更新状态（用于主循环）
void https_proxy_update(void);

// 停止代理服务
void https_proxy_stop(void);

#endif // HTTPS_PROXY_H
