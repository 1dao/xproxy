#ifndef SSH_TUNNEL_H
#define SSH_TUNNEL_H

#include <libssh2.h>
#include "socket_util.h"

#define SSH_MAX_BUFFER_SIZE 16384

typedef enum {
    SSH_TUNNEL_STATE_DISCONNECTED,
    SSH_TUNNEL_STATE_CONNECTING,
    SSH_TUNNEL_STATE_CONNECTED,
    SSH_TUNNEL_STATE_ERROR
} SSHTunnelState;

typedef struct {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    SOCKET_T sock;
    SSHTunnelState state;
    char *username;
    char *password;
    char *host;
    int port;
} SSHTunnel;

// 初始化SSH隧道
int ssh_tunnel_init(SSHTunnel *tunnel, const char *host, int port, 
                    const char *username, const char *password);

// 连接到SSH服务器
int ssh_tunnel_connect(SSHTunnel *tunnel);

// 打开通道到目标主机
int ssh_tunnel_open_channel(SSHTunnel *tunnel, const char *dest_host, int dest_port,
                            const char *source_host, int source_port);

// 从SSH通道读取数据
int ssh_tunnel_read(SSHTunnel *tunnel, void *buffer, size_t buffer_size);

// 向SSH通道写入数据
int ssh_tunnel_write(SSHTunnel *tunnel, const void *buffer, size_t buffer_size);

// 关闭SSH隧道
void ssh_tunnel_close(SSHTunnel *tunnel);

// 清理SSH隧道资源
void ssh_tunnel_cleanup(SSHTunnel *tunnel);

// 获取SSH隧道状态
SSHTunnelState ssh_tunnel_get_state(SSHTunnel *tunnel);

// 获取错误信息
int ssh_tunnel_get_error(SSHTunnel *tunnel, char **errmsg);

#endif // SSH_TUNNEL_H
