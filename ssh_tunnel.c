#include "ssh_tunnel.h"
#include <wolfssl/wolfcrypt/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

static int wolf_ssh_initialized = 0;
static WOLFSSH_CTX* g_ssh_ctx = NULL;

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

    wolfSSH_Debugging_ON();

    printf("[DEBUG] 1. Calling wolfSSH_Init...\n");
    ret = wolfSSH_Init();
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "wolfSSH_Init failed: %d\n", ret);
        return NULL;
    }
    wolf_ssh_initialized = 1;
    printf("[DEBUG] 2. wolfSSH_Init OK\n");

    printf("[DEBUG] 3. Creating socket...\n");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("socket");

        return NULL;
    }
    printf("[DEBUG] 6. Socket created: %d\n", (int)sock);

    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sin.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", host);
        CLOSE_SOCKET(sock);

        return NULL;
    }

    printf("[DEBUG] 7. Connecting to %s:%d...\n", host, port);
    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        fprintf(stderr, "Connect failed: host=%s, port=%d\n", host, port);
        CLOSE_SOCKET(sock);

        return NULL;
    }
    printf("[DEBUG] 8. Connected OK\n");

    printf("[DEBUG] 9. Creating SSH context...\n");
    if (g_ssh_ctx == NULL) {
        g_ssh_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
        if (g_ssh_ctx == NULL) {
            fprintf(stderr, "Could not initialize SSH context\n");
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
        fprintf(stderr, "Could not create SSH session\n");
        CLOSE_SOCKET(sock);
        return NULL;
    }
    printf("[DEBUG] 10. SSH session created: %p\n", ssh);

    printf("[DEBUG] 11. Setting auth context...\n");
    wolfSSH_SetUserAuthCtx(ssh, (void*)password);

    printf("[DEBUG] 12. Setting fd...\n");
    ret = wolfSSH_set_fd(ssh, sock);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "wolfSSH_set_fd failed: %d\n", ret);
        wolfSSH_free(ssh);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    printf("[DEBUG] 13. Setting username...\n");
    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "wolfSSH_SetUsername failed: %d\n", ret);
        wolfSSH_free(ssh);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)"socks5_proxy");
    wolfSSH_CTX_SetPublicKeyCheck(g_ssh_ctx, wsPublicKeyCheck);

    printf("[DEBUG] 14. Calling wolfSSH_connect...\n");
    ret = wolfSSH_connect(ssh);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "wolfSSH_connect failed: %d (%s)\n", ret, wolfSSH_get_error_name(ssh));
        wolfSSH_free(ssh);
        CLOSE_SOCKET(sock);
        return NULL;
    }
    printf("[DEBUG] 15. Connected!\n");

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

    WOLFSSH_CHANNEL* channel = wolfSSH_ChannelFwdNew(ssh,
        dest_host, (word16)dest_port,
        source_host, (word16)source_port);

    if (channel) {
        fprintf(stderr, "SSH channel opened successfully to %s:%d, address=%p, error=%d\n", dest_host, dest_port, channel, wolfSSH_get_error(channel->ssh));
    } else {
        fprintf(stderr, "Failed to open channel to %s:%d, error: %d\n",
                dest_host, dest_port, wolfSSH_get_error(ssh));
    }

    return channel;
}

void wolfSSH_channel_close(WOLFSSH_CHANNEL* channel) {
    if (!channel)
        return;

    // int ssh_error = wolfSSH_get_error(channel->ssh);
    // if(ssh_error != WS_SOCKET_ERROR_E
    //     && ssh_error != WS_CHANNEL_CLOSED
    //     && ssh_error != WS_EOF
    //     && ssh_error != WS_FATAL_ERROR) {
    //     if (wolfSSH_channel_eof(channel) == 0) {
    //         // read remain data
    //         char temp[1024];int n;
    //         while ((n = wolfSSH_ChannelRead(channel, temp, sizeof(temp))) > 0) {}
    //     }
    // }

    fprintf(stderr, "SSH channel closed, address=%p\n", channel);
    wolfSSH_ChannelFree(channel);
}

inline static int is_temporary_state(int error_code) {
    switch (error_code) {
        case WS_WANT_READ:
        case WS_WANT_WRITE:
        case WS_REKEYING:
        case WS_CHAN_RXD:
        case WS_CHANNEL_NOT_CONF:
        case WS_WINDOW_FULL:
            return 1;  // 是临时状态
        default:
            return 0;  // 不是临时状态
    }
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
