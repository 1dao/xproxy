#include "ssh_tunnel.h"
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssh/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef LOG_TAG
#define LOG_TAG "ssh"
#endif
#include "xlog.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#endif

static int wolf_ssh_initialized = 0;
static int g_ssh_session_count = 0;   /* 存活会话数，共享 g_ssh_ctx 的引用计数 */
static WOLFSSH_CTX* g_ssh_ctx = NULL;
inline static int is_temporary_state(int error_code);

/* Route wolfssh's internal logs through xlog. wolfssh's logLevel global is
 * fixed at WS_LOG_DEBUG and has no public setter, so we drop DEBUG here to
 * keep volume manageable; INFO/WARN/ERROR pass through. The INFO line we
 * actually care about for diagnosis is:
 *     "channel open failure reason code: %u"  (RFC4254 1..4)
 *     "description: ..."
 * logged from DoChannelOpenFail in 3rd/wolfssh/src/internal.c. */
static void wolfssh_log_bridge(enum wolfSSH_LogLevel level, const char* msg) {
    if (!msg) return;
    if (level == WS_LOG_DEBUG) return;
    switch (level) {
        case WS_LOG_ERROR: XLOGE("[wolfssh] %s", msg); break;
        case WS_LOG_WARN:  XLOGW("[wolfssh] %s", msg); break;
        default:           XLOGI("[wolfssh] %s", msg); break;
    }
}

static int wsUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    const char* password = (const char*)ctx;
    int ret = WOLFSSH_USERAUTH_SUCCESS;

    (void)authType;
    if (password != NULL) {
        word32 passwordSz = (word32)strlen(password);
        authData->sf.password.password = (const byte*)password;
        authData->sf.password.passwordSz = passwordSz;
    }
    else {
        ret = WOLFSSH_USERAUTH_FAILURE;
    }

    return ret;
}

static int wsPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    (void)pubKey;
    (void)pubKeySz;
    (void)ctx;
    return 0;
}

WOLFSSH* wolfSSH_session_open(const char *host, int port,
                              const char *username, const char *password) {
    if (!host || !username || !password) {
        printf("wolfSSH_session_open: Invalid arguments\n");
        return NULL;
    }

    struct sockaddr_in sin;
    SOCKET_T sock;
    int ret;

    wolfSSH_SetLoggingCb(wolfssh_log_bridge);
    wolfSSH_Debugging_ON();

    printf("[DEBUG] 1. Calling wolfSSH_Init...\n");
    ret = wolfSSH_Init();
    if (ret != WS_SUCCESS) {
        XLOGE("wolfSSH_Init failed: %d", ret);
        return NULL;
    }
    wolf_ssh_initialized = 1;
    printf("[DEBUG] 2. wolfSSH_Init OK\n");

    printf("[DEBUG] 3. Creating socket...\n");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        XLOGE("socket creation failed: %d", GET_ERRNO());

        return NULL;
    }
    printf("[DEBUG] 6. Socket created: %d\n", (int)sock);

    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sin.sin_addr) <= 0) {
        XLOGE("Invalid address: %s", host);
        CLOSE_SOCKET(sock);

        return NULL;
    }

    printf("[DEBUG] 7. Connecting to %s:%d...\n", host, port);
    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        XLOGE("Connect failed: host=%s, port=%d", host, port);
        CLOSE_SOCKET(sock);

        return NULL;
    }
    printf("[DEBUG] 8. Connected OK\n");

    printf("[DEBUG] 9. Creating SSH context...\n");
    if (g_ssh_ctx == NULL) {
        g_ssh_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
        if (g_ssh_ctx == NULL) {
            XLOGE("Could not initialize SSH context");
            CLOSE_SOCKET(sock);
            return NULL;
        }
        wolfSSH_SetUserAuth(g_ssh_ctx, wsUserAuth);
        wolfSSH_CTX_SetWindowPacketSize(g_ssh_ctx, 1024*1024, 32*1024);
    }
    printf("[DEBUG] 8. SSH context OK\n");

    printf("[DEBUG] 9. Creating SSH session...\n");
    WOLFSSH* ssh = wolfSSH_new(g_ssh_ctx);
    if (ssh == NULL) {
        XLOGE("Could not create SSH session");
        CLOSE_SOCKET(sock);
        return NULL;
    }
    printf("[DEBUG] 10. SSH session created: %p\n", ssh);

    printf("[DEBUG] 11. Setting auth context...\n");
    wolfSSH_SetUserAuthCtx(ssh, (void*)password);

    printf("[DEBUG] 12. Setting fd...\n");
    ret = wolfSSH_set_fd(ssh, sock);
    if (ret != WS_SUCCESS) {
        XLOGE("wolfSSH_set_fd failed: %d", ret);
        wolfSSH_free(ssh);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    printf("[DEBUG] 13. Setting username...\n");
    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS) {
        XLOGE("wolfSSH_SetUsername failed: %d", ret);
        wolfSSH_free(ssh);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)"socks5_proxy");
    wolfSSH_CTX_SetPublicKeyCheck(g_ssh_ctx, wsPublicKeyCheck);

    printf("[DEBUG] 14. Calling wolfSSH_connect...\n");
    ret = wolfSSH_connect(ssh);
    if (ret != WS_SUCCESS) {
        XLOGE("wolfSSH_connect failed: %d (%s)", ret, wolfSSH_get_error_name(ssh));
        wolfSSH_free(ssh);
        CLOSE_SOCKET(sock);
        return NULL;
    }
    printf("[DEBUG] 15. Connected!\n");

    /* 握手用阻塞 socket 一次跑完，之后必须切成非阻塞再交给事件循环。
     *
     * wolfSSH 读包时走 GetInputData()，里面是 do { ReceiveData() } while(size)
     * ——要凑齐整个 SSH 包才返回。包最大 32KB（见上面的 SetWindowPacketSize），
     * 远大于一个 MSS，所以一个包常常跨十几个 TCP 段。socket 是阻塞的时候，
     * epoll 报了可读、我们进去 recv，读完前几段后剩下的还没到，recv 就直接
     * 睡在那里——整个单线程事件循环（两条 SSH 会话 + 所有客户端）全停住，
     * 直到对端把这个包的剩余字节发完。丢一个段就是一个 RTO 的卡顿。
     * 非阻塞后 recv 返回 EAGAIN -> WS_CBIO_ERR_WANT_READ -> WS_WANT_READ，
     * is_temporary_state() 判为临时错误，事件循环继续跑，下次可读再续上。 */
    if (socket_set_nonblocking(sock) != 0) {
        XLOGE("failed to set SSH socket non-blocking");
        wolfSSH_free(ssh);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    /* SSH 包是一个个独立的小消息，Nagle 会把控制包（CHANNEL_OPEN /
     * WINDOW_ADJUST）压在后面等 ACK，直接放大新连接建立的延迟。 */
    {
        int one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
    }

    g_ssh_session_count++;
    return ssh;
}

void wolfSSH_session_close(WOLFSSH* ssh) {
    if (!ssh) {
        return;
    }

    SOCKET_T sock = wolfSSH_get_fd(ssh);

    wolfSSH_shutdown(ssh);
    wolfSSH_free(ssh);

    if (sock != INVALID_SOCKET) {
        CLOSE_SOCKET(sock);
    }

    /* g_ssh_ctx 是所有会话共享的，只有最后一条会话关闭时才能清理，
     * 否则另一条还活着的会话会踩到已释放的 CTX。 */
    if (g_ssh_session_count > 0) g_ssh_session_count--;
    if (g_ssh_session_count > 0) return;

    if (wolf_ssh_initialized) {
        wolfSSH_Cleanup();

        wolf_ssh_initialized = 0;
    }

    if (g_ssh_ctx) {
        wolfSSH_CTX_free(g_ssh_ctx);
        g_ssh_ctx = NULL;
    }
}

void wolfSSH_channel_callback(WOLFSSH* session, WS_CallbackChannelClose fclose, WS_CallbackChannelOpen ffini, WS_CallbackChannelOpen ffail, void* ctx) {
    wolfSSH_SetChannelCloseCtx(session, ctx);
    wolfSSH_SetChannelOpenCtx(session, ctx);
    wolfSSH_CTX_SetChannelCloseCb(g_ssh_ctx, fclose);
    wolfSSH_CTX_SetChannelOpenRespCb(g_ssh_ctx, ffini, ffail);
}

/* socket 现在能不能整包吞下一个 CHANNEL_OPEN？
 *
 * 切非阻塞后必须先问这个。wolfSSH_ChannelFwdNewLocal() 里
 * SendChannelOpenForward() 一旦返回 WS_WANT_WRITE，它会 ChannelDelete 掉通道并
 * 返回 NULL —— 可 CHANNEL_OPEN 已经加密进 ssh->outputBuffer，必然会发出去、撤
 * 不回。服务端随后确认一个我们已经不认识的 channel id，DoChannelOpenConf 里
 * ChannelFind 失败返回 WS_INVALID_CHANID（不在 check_fatal_err 名单里，会被当成
 * 临时错误吞掉），那条通道就在服务端泄漏，而调用方还会再开一条。
 *
 * wolfssh 是第三方库不能改，所以从调用方规避：不安全就干脆不发起 open。
 * 两个条件——
 *   1. outputBuffer 已排空，说明上一次 flush 是整包写出去的；
 *   2. socket 此刻可写。TCP 的 POLLOUT 条件是发送缓冲至少空出三分之一
 *      （Linux sk_stream_min_wspace），远大于一个 CHANNEL_OPEN 包（约百字节），
 *      所以可写就等于这个包能被整包收下。 */
int wolfSSH_session_can_open_channel(WOLFSSH* ssh) {
    if (!ssh) return 0;
    if (wolfSSH_session_has_pending_output(ssh)) return 0;

    SOCKET_T fd = wolfSSH_get_fd(ssh);
    if (fd == INVALID_SOCKET) return 0;

#ifdef _WIN32
    WSAPOLLFD pfd;
    pfd.fd = fd;
    pfd.events = POLLWRNORM;
    pfd.revents = 0;
    int rc = WSAPoll(&pfd, 1, 0);
    return rc > 0 && (pfd.revents & POLLWRNORM) && !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL));
#else
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int rc = poll(&pfd, 1, 0);
    return rc > 0 && (pfd.revents & POLLOUT) && !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL));
#endif
}

WOLFSSH_CHANNEL* wolfSSH_channel_open(WOLFSSH* ssh,
                                       const char *dest_host, int dest_port,
                                       const char *source_host, int source_port) {
    if (!ssh || !dest_host) {
        return NULL;
    }

    if (!source_host) {
        source_host = "127.0.0.1";
    }
    if (source_port == 0) {
        source_port = 12345;
    }

    /* 发不出整包就别开，否则会在服务端漏一条通道（见上面的说明）。
     * 报 WS_WANT_WRITE 让调用方走它已有的“临时错误 -> 挂可写 -> 重试”分支。 */
    if (!wolfSSH_session_can_open_channel(ssh)) {
        XLOGD("Deferring channel open to %s:%d, SSH socket not drained",
              dest_host, dest_port);
        ssh->error = WS_WANT_WRITE;
        return NULL;
    }

    WOLFSSH_CHANNEL* channel = wolfSSH_ChannelFwdNew(ssh,
        dest_host, (word16)dest_port,
        source_host, (word16)source_port);

    if (channel) {
        XLOGI("SSH channel opened successfully to %s:%d, address=%p, error=%d",
              dest_host, dest_port, channel, wolfSSH_get_error(channel->ssh));
    } else {
        /* 上面的门槛过了还撞上 WS_WANT_WRITE，说明缓冲在这一小段里被灌满了：
         * 通道已经被库删掉但 CHANNEL_OPEN 会发出去，服务端那条是泄漏的。
         * 改不了库，至少让它在日志里可见。 */
        int err = wolfSSH_get_error(ssh);
        if (err == WS_WANT_WRITE) {
            XLOGE("CHANNEL_OPEN to %s:%d hit WS_WANT_WRITE after drain check; "
                  "channel leaked on the server side", dest_host, dest_port);
        }
        XLOGE("Failed to open channel to %s:%d, error: %d",
              dest_host, dest_port, err);
    }

    return channel;
}

void wolfSSH_channel_close(WOLFSSH_CHANNEL* channel) {
    if (!channel)
        return;

    XLOGI("SSH channel closed, address=%p", channel);
    if (channel->openConfirmed) {
        if (!channel->eofTxd) {
            int ret = SendChannelEof(channel->ssh, channel->peerChannel);
            if (ret < 0 && !is_temporary_state(ret)) {
                XLOGE("SendChannelEof failed: %d:%s",
                      ret, wolfSSH_ErrorToName(ret));
            }
        }
        if (!channel->closeTxd) {
            int ret = SendChannelClose(channel->ssh, channel->peerChannel);
            if (ret < 0 && !is_temporary_state(ret)) {
                XLOGE("SendChannelClose failed: %d:%s",
                      ret, wolfSSH_ErrorToName(ret));
            }
        }
    }
    wolfSSH_ChannelFree(channel);
}

static inline int check_fatal_err(int err_code) {
    switch (err_code) {
        /* 传输层致命错误 - 必须关闭 */
        case WS_SOCKET_ERROR_E:
        case WS_FATAL_ERROR:
        case WS_CRYPTO_FAILED:

        /* 握手阶段错误 - 无法建立连接 */
        case WS_VERSION_E:
        case WS_MATCH_KEX_ALGO_E:
        case WS_MATCH_KEY_ALGO_E:
        case WS_MATCH_ENC_ALGO_E:
        case WS_MATCH_MAC_ALGO_E:

        /* 认证错误 - 凭据无效 */
        case WS_USER_AUTH_E:
        case WS_PUBKEY_REJECTED_E:
        case WS_INVALID_USERNAME:

        /* 安全错误 - 可能存在攻击或数据损坏 */
        case WS_VERIFY_MAC_E:
        case WS_DECRYPT_E:
        case WS_ENCRYPT_E:
        case WS_CREATE_MAC_E:
        case WS_CERT_EXPIRED_E:
        case WS_CERT_REVOKED_E:
        case WS_CERT_SIG_CONFIRM_E:

        /* 协议错误 - 无法继续 */
        case WS_PARSE_E:
        case WS_INVALID_STATE_E:
        case WS_MSGID_NOT_ALLOWED_E:
            return 1;

        default:
            return 0;
    }
}

inline static int is_temporary_state(int error_code) {
    return !check_fatal_err(error_code);
}

int wolfSSH_channel_send_eof(WOLFSSH_CHANNEL* channel) {
    if (!channel)
        return -1;
    if (!channel->openConfirmed || channel->eofTxd)
        return 1;

    int ret = SendChannelEof(channel->ssh, channel->peerChannel);
    if (ret == WS_SUCCESS)
        return 1;

    int err = wolfSSH_get_error(channel->ssh);
    if (is_temporary_state(err) || is_temporary_state(ret))
        return 0;

    XLOGE("SendChannelEof failed: %d:%s", ret, wolfSSH_ErrorToName(ret));
    return -1;
}

int wolfSSH_channel_read(WOLFSSH_CHANNEL *channel, void *buffer, size_t buffer_size) {
    if (!channel || !buffer || buffer_size == 0)
        return -1;

    int ret = wolfSSH_ChannelRead(channel, (byte*)buffer, (word32)buffer_size);
    if (ret < 0) {
        if (is_temporary_state(wolfSSH_get_error(channel->ssh)))
            return 0;
        return -1;
    }

    return ret;
}

int wolfSSH_channel_write(WOLFSSH_CHANNEL *channel, const void *buffer, size_t buffer_size) {
    if (!channel || !buffer || buffer_size == 0)
        return -1;

    int ret = wolfSSH_ChannelSend(channel, (const byte*)buffer, (word32)buffer_size);
    if (ret < 0) {
        if (is_temporary_state(wolfSSH_get_error(channel->ssh)))
            return 0;
        return ret;
    }

    return ret;
}

SOCKET_T wolfSSH_session_get_socket(WOLFSSH* ssh) {
    if (!ssh) {
        return INVALID_SOCKET;
    }
    return wolfSSH_get_fd(ssh);
}

int wolfSSH_session_has_buffered_input(WOLFSSH* ssh) {
    if (!ssh) return 0;
    return ssh->inputBuffer.length > ssh->inputBuffer.idx;
}

int wolfSSH_session_has_pending_output(WOLFSSH* ssh) {
    if (!ssh) return 0;
    return ssh->outputBuffer.length > ssh->outputBuffer.idx;
}

/* Data received on the channel that nobody has read yet. wolfSSH_channel_read()
 * returns 0 both when the channel really is drained and when the read was only
 * temporarily refused (WS_REKEYING is the reachable case -- ChannelRead bails
 * out while ssh->isKeying), so callers cannot use a 0-read alone to conclude
 * there is nothing left. */
int wolfSSH_channel_has_buffered_input(WOLFSSH_CHANNEL* channel) {
    if (!channel) return 0;
    return channel->inputBuffer.length > channel->inputBuffer.idx;
}

/* 直接把 outputBuffer 冲到 socket 上。
 *
 * wolfSSH_worker() 只在 DoReceive() 返回 WS_SUCCESS / WS_WANT_READ /
 * WS_CHAN_RXD 时才调 wolfSSH_SendPacket()（3rd/wolfssh/src/ssh.c 的 flush 分支），
 * 可 GetInputData() 在 socket 没数据可读时把 ssh->error 置成 WS_WANT_READ 却
 * 返回 WS_FATAL_ERROR（3rd/wolfssh/src/internal.c），于是纯 POLLOUT 唤醒那一轮
 * 根本走不到 flush —— 待发字节一直卡在 outputBuffer 里，只能等某个 channel 恰好
 * 写数据、借 wolfSSH_ChannelSend() 内部的 SendPacket 顺手带出去。期间
 * has_pending_output() 恒真，调用方摘不掉 EPOLLOUT，事件循环空转。
 *
 * 返回 1 = 已冲干净，0 = 还有剩（socket 发送缓冲满，等下次可写），-1 = 致命错误。 */
int wolfSSH_session_flush_output(WOLFSSH* ssh) {
    if (!ssh) return -1;
    if (ssh->outputBuffer.length <= ssh->outputBuffer.idx)
        return 1;

    int ret = wolfSSH_SendPacket(ssh);
    if (ret == WS_SUCCESS)
        return 1;

    if (is_temporary_state(ret) && is_temporary_state(wolfSSH_get_error(ssh)))
        return 0;

    XLOGE("wolfSSH_SendPacket failed: %d:%s", ret, wolfSSH_ErrorToName(ret));
    return -1;
}

int wolfSSH_process_events(WOLFSSH* ssh, word32* channelId) {
    if (!ssh)
        return -1;

    int ret = wolfSSH_worker(ssh, channelId);
    if(ret >=0 ) return ret;
    if (is_temporary_state(wolfSSH_get_error(ssh)))
        return 0;

    return ret;
}

int wolfSSH_session_keepalive(WOLFSSH* session) {
    int rc = wolfSSH_SendIgnore(session, NULL, 0);
    if (rc < 0 && is_temporary_state(wolfSSH_get_error(session)))
        return 0;
    return rc;
}

int wolfSSH_channel_eof(WOLFSSH_CHANNEL *channel) {
    if (!channel) {
        return -1;
    }
    return wolfSSH_ChannelGetEof(channel);
}

int wolfSSH_get_error_code(WOLFSSH* ssh) {
    if (!ssh) {
        return -1;
    }
    return wolfSSH_get_error(ssh);
}

BOOL wolfSSH_is_temporary_state(WOLFSSH* ssh) {
    return is_temporary_state(wolfSSH_get_error(ssh));
}

/* 判断wolfSSH fatal错误状态 */
int wolfSSH_check_fatal(int err_code) {
    return check_fatal_err(err_code);
}
