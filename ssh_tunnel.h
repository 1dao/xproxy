#ifndef SSH_TUNNEL_V2_H
#define SSH_TUNNEL_V2_H

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <stddef.h>
#include <stdint.h>
#include "xsock.h"

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

/* CHANNEL_OPEN 现在发得出整包吗？发不出就别开——wolfSSH 会在 WS_WANT_WRITE 时
 * 删掉通道结构，但报文已经进了输出缓冲、必然发出去，服务端那条通道就漏了。
 * 详见 ssh_tunnel.c 中该函数上方的说明。 */
int wolfSSH_session_can_open_channel(WOLFSSH* session);

/* 打开SSH通道 (Direct TCP/IP) */
WOLFSSH_CHANNEL* wolfSSH_channel_open(WOLFSSH* session,
                                       const char *dest_host, int dest_port,
                                       const char *source_host, int source_port);
void wolfSSH_channel_close(WOLFSSH_CHANNEL* channel);
int wolfSSH_channel_send_eof(WOLFSSH_CHANNEL* channel);

/* 从SSH通道读取数据（非阻塞） */
int wolfSSH_channel_read(WOLFSSH_CHANNEL *channel, void *buffer, size_t buffer_size);

/* 向SSH通道写入数据（非阻塞） */
int wolfSSH_channel_write(WOLFSSH_CHANNEL *channel, const void *buffer, size_t buffer_size);

/* 获取SSH session的socket描述符，用于select监听 */
SOCKET_T wolfSSH_session_get_socket(WOLFSSH* session);
int wolfSSH_session_has_buffered_input(WOLFSSH* session);
int wolfSSH_session_has_pending_output(WOLFSSH* session);

/* 把 outputBuffer 冲到 socket 上：1=冲干净，0=socket 缓冲满还有剩，-1=致命错误。
 * wolfSSH_process_events() 在这一轮没收到数据时不会 flush，详见实现处说明。 */
int wolfSSH_session_flush_output(WOLFSSH* session);

/* 处理SSH事件（轮询模式下调用） */
int wolfSSH_process_events(WOLFSSH* session, word32* channelId);

/*保活*/
int wolfSSH_session_keepalive(WOLFSSH* session);

/* 检查channel是否EOF */
int wolfSSH_channel_eof(WOLFSSH_CHANNEL *channel);

/* channel上是否还有收到但未被读走的数据 */
int wolfSSH_channel_has_buffered_input(WOLFSSH_CHANNEL* channel);

/* 获取错误信息 */
int wolfSSH_get_error_code(WOLFSSH* session);

/* 判断是否为临时错误状态 */
BOOL wolfSSH_is_temporary_state(WOLFSSH* ssh);

/* 判断wolfSSH fatal错误状态 */
int wolfSSH_check_fatal(int err_code);

#endif /* SSH_TUNNEL_V2_H */
