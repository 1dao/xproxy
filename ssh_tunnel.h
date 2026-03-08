#ifndef SSH_TUNNEL_V2_H
#define SSH_TUNNEL_V2_H

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <stddef.h>
#include <stdint.h>
#include "socket_util.h"

/* Forward declaration */
typedef struct WOLFSSH WOLFSSH;
typedef struct WOLFSSH_CHANNEL WOLFSSH_CHANNEL;

/* SSH session 初始化以及连接等 */
WOLFSSH* wolfSSH_session_open(const char *host, int port,
                              const char *username, const char *password);
void wolfSSH_session_close(WOLFSSH* session);
void wolfSSH_channel_callback(WOLFSSH* session
    , WS_CallbackChannelClose fclose
    , WS_CallbackChannelOpen ffini
    , WS_CallbackChannelOpen ffail, void* ctx);

/* 打开SSH通道 (Direct TCP/IP) */
WOLFSSH_CHANNEL* wolfSSH_channel_open(WOLFSSH* session,
                                       const char *dest_host, int dest_port,
                                       const char *source_host, int source_port);
void wolfSSH_channel_close(WOLFSSH_CHANNEL* channel);

/* 从SSH通道读取数据（非阻塞） */
int wolfSSH_channel_read(WOLFSSH_CHANNEL *channel, void *buffer, size_t buffer_size);

/* 向SSH通道写入数据（非阻塞） */
int wolfSSH_channel_write(WOLFSSH_CHANNEL *channel, const void *buffer, size_t buffer_size);

/* 获取SSH session的socket描述符，用于select监听 */
SOCKET_T wolfSSH_session_get_socket(WOLFSSH* session);

/* 处理SSH事件（轮询模式下调用） */
int wolfSSH_process_events(WOLFSSH* session, word32* channelId);

/*保活*/
int wolfSSH_session_keepalive(WOLFSSH* session);

/* 检查channel是否EOF */
int wolfSSH_channel_eof(WOLFSSH_CHANNEL *channel);

/* 获取错误信息 */
int wolfSSH_get_error_code(WOLFSSH* session);

/* 判断是否为临时错误状态 */
BOOL wolfSSH_is_temporary_state(WOLFSSH* ssh);

#endif /* SSH_TUNNEL_V2_H */
