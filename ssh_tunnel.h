#ifndef SSH_TUNNEL_V1_H
#define SSH_TUNNEL_V1_H

#include <libssh2.h>
#include <stddef.h>
#include "socket_util.h"

// SSH session 初始化以及连接等
LIBSSH2_SESSION* ssh_tunnel_session_open(const char *host, int port,
                                         const char *username, const char *password);
void ssh_tunnel_session_close(LIBSSH2_SESSION* session);

// 打开SSH通道
LIBSSH2_CHANNEL* ssh_tunnel_channel_open(LIBSSH2_SESSION* session,
                                         const char *dest_host, int dest_port,
                                         const char *source_host, int source_port);
void ssh_tunnel_channel_close(LIBSSH2_CHANNEL* channel);

// 从SSH通道读取数据（非阻塞）
int ssh_tunnel_read(LIBSSH2_CHANNEL *channel, void *buffer, size_t buffer_size);

// 向SSH通道写入数据（非阻塞）
int ssh_tunnel_write(LIBSSH2_CHANNEL *channel, const void *buffer, size_t buffer_size);

// 获取SSH session的socket描述符，用于select监听
SOCKET_T ssh_tunnel_session_get_socket(LIBSSH2_SESSION* session);

// 获取错误信息
int ssh_tunnel_get_error(LIBSSH2_SESSION* session, char **errmsg);

#endif // SSH_TUNNEL_V1_H
