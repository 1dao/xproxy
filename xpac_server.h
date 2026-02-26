#ifndef XPAC_SERVER_H
#define XPAC_SERVER_H

#include "socket_util.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===================== 代理类型定义 =====================
typedef enum {
    PROXY_TYPE_HTTP,    // HTTP代理
    PROXY_TYPE_SOCKS5,  // SOCKS5代理
    PROXY_TYPE_AUTO     // 自动选择（根据PAC类型）
} ProxyType;

// ===================== 配置结构 =====================
typedef struct {
    int http_proxy_port;          // HTTP代理端口（如7890）
    int socks5_proxy_port;        // SOCKS5代理端口（如1081）
    const char* config_file;      // 配置文件路径（可为NULL）
    int enable_web_admin;         // 是否启用Web管理界面
    const char* admin_password;   // 管理密码（可为NULL）
} XpacConfig;

// ===================== 核心函数 =====================
// 初始化PAC服务器
void xpac_init(const XpacConfig* config);
void xpac_uninit(void);

// 处理HTTP请求（检查并响应PAC请求或管理请求）
// 返回值：1=已处理，0=未处理（是代理请求），-1=错误
int xpac_handle_request(SOCKET_T client_sock, const char* req_buf, int req_len);

#ifdef __cplusplus
}
#endif

#endif // XPAC_SERVER_H
