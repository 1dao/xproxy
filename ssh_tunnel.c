#include "ssh_tunnel.h"
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

static int libssh2_initialized = 0;

LIBSSH2_SESSION* ssh_tunnel_session_open(const char *host, int port,
                                         const char *username, const char *password) {
    if (!host || !username || !password) {
        printf("ssh_tunnel_session_open: Invalid arguments\n");
        return NULL;
    }

    struct sockaddr_in sin;
    int rc;
    SOCKET_T sock;
    // 创建socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("socket");
        return NULL;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sin.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", host);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    // 连接到SSH服务器
    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        // perror("connect");
        // CLOSE_SOCKET(sock);
        fprintf(stderr, "Connect failed: host=%s,port=%d, user=%s, password=%s\n", host, port, username, password);

        #ifdef _WIN32
                int error_code = WSAGetLastError();
                char error_msg[256];
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                              NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                              error_msg, sizeof(error_msg), NULL);
                fprintf(stderr, "connect failed: %s\n", error_msg);
        #else
                perror("connect");
        #endif
                CLOSE_SOCKET(sock);
                fprintf(stderr, "Connect failed: host=%s,port=%d, user=%s, password=%s\n", host, port, username, password);
        return NULL;
    }

    // 初始化libssh2
    if (!libssh2_initialized) {
        rc = libssh2_init(0);
        if (rc != 0) {
            fprintf(stderr, "libssh2_init failed: %d\n", rc);
            return NULL;
        }
        libssh2_initialized = 1;
    }

    // 创建SSH session
    LIBSSH2_SESSION *session = libssh2_session_init_ex(NULL, NULL, NULL, (void*)(intptr_t)sock);
    if (!session) {
        fprintf(stderr, "Could not initialize SSH session\n");
        CLOSE_SOCKET(sock);
        return NULL;
    }

    // SSH握手
    while ((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        int dir = libssh2_session_block_directions(session);
        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
            FD_SET(sock, &read_fds);
        }
        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            FD_SET(sock, &write_fds);
        }
        select((int)sock + 1, &read_fds, &write_fds, NULL, NULL);
    }

    if (rc) {
        fprintf(stderr, "Error when starting up SSH session: %d\n", rc);
        libssh2_session_free(session);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    // 获取支持的认证方法
    char *userauthlist = libssh2_userauth_list(session, username, (unsigned int)strlen(username));
    if (userauthlist) {
        fprintf(stderr, "Authentication methods: %s\n", userauthlist);
    }

    int auth_success = 0;

    // 尝试keyboard-interactive认证
    if (userauthlist && strstr(userauthlist, "keyboard-interactive")) {
        fprintf(stderr, "Trying keyboard-interactive authentication...\n");
        while ((rc = libssh2_userauth_keyboard_interactive(session, username, NULL)) == LIBSSH2_ERROR_EAGAIN) {
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            int dir = libssh2_session_block_directions(session);
            if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
                FD_SET(sock, &read_fds);
            }
            if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
                FD_SET(sock, &write_fds);
            }
            select((int)sock + 1, &read_fds, &write_fds, NULL, NULL);
        }
        if (rc == 0) {
            auth_success = 1;
            fprintf(stderr, "Keyboard-interactive authentication succeeded\n");
        } else {
            fprintf(stderr, "Keyboard-interactive authentication failed: %d\n", rc);
        }
    }

    // 尝试密码认证
    if (!auth_success && userauthlist && strstr(userauthlist, "password")) {
        fprintf(stderr, "Trying password authentication...\n");
        while ((rc = libssh2_userauth_password(session, username, password)) == LIBSSH2_ERROR_EAGAIN) {
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            int dir = libssh2_session_block_directions(session);
            if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
                FD_SET(sock, &read_fds);
            }
            if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
                FD_SET(sock, &write_fds);
            }
            select((int)sock + 1, &read_fds, &write_fds, NULL, NULL);
        }
        if (rc == 0) {
            auth_success = 1;
            fprintf(stderr, "Password authentication succeeded\n");
        } else {
            fprintf(stderr, "Password authentication failed: %d\n", rc);
        }
    }

    if (!auth_success) {
        fprintf(stderr, "All authentication methods failed\n");
        libssh2_session_free(session);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    // 设置为非阻塞模式
    libssh2_session_set_blocking(session, 0);
    libssh2_keepalive_config(session, 0, 30);
    printf("SSH session established on socket (%d-%d)\n", sock, (SOCKET_T)(intptr_t)(*libssh2_session_abstract(session)));
    return session;
}

void ssh_tunnel_session_close(LIBSSH2_SESSION* session) {
    if (!session) {
        return;
    }

    // 获取socket文件描述符
    SOCKET_T sock = (SOCKET_T)(intptr_t)(*libssh2_session_abstract(session));

    if (session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }

    if (sock != INVALID_SOCKET) {
        CLOSE_SOCKET(sock);
    }
}

LIBSSH2_CHANNEL* ssh_tunnel_channel_open(LIBSSH2_SESSION* session,
                                         const char *dest_host, int dest_port,
                                         const char *source_host, int source_port) {
    if (!session || !dest_host)
        return NULL;
    if (!source_host)
        source_host = "127.0.0.1";
    if (source_port == 0)
        source_port = 12345;

    int rc;
    int retry_count = 0;
    int max_retries = 100;
    SOCKET_T sock = (SOCKET_T)(intptr_t)(*libssh2_session_abstract(session));
    LIBSSH2_CHANNEL *channel = NULL;
    while (retry_count < max_retries) {
        channel = libssh2_channel_direct_tcpip_ex(session,
                            dest_host, dest_port,
                            source_host, source_port);
        if (channel)
            break;

        rc = libssh2_session_last_error(session, NULL, NULL, 0);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            retry_count++;
            if (retry_count >= max_retries) {
                fprintf(stderr, "Timeout opening SSH channel after %d retries\n", max_retries);
                break;
            }

            fd_set read_fds, write_fds;
            struct timeval timeout;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            int dir = libssh2_session_block_directions(session);
            if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
                FD_SET(sock, &read_fds);
            if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
                FD_SET(sock, &write_fds);

            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;
            select((int)sock + 1, &read_fds, &write_fds, NULL, &timeout);
        } else {
            char *error_msg = NULL;
            libssh2_session_last_error(session, &error_msg, NULL, 0);
            fprintf(stderr, "Failed to open direct-tcpip channel to %s:%d. Error %d: %s\n",
                    dest_host, dest_port, rc, error_msg ? error_msg : "Unknown error");
            libssh2_session_set_blocking(session, 1);
            return NULL;
        }
    }

    if (channel) {
        fprintf(stderr, "SSH channel opened successfully to %s:%d\n", dest_host, dest_port);
    } else {
        char *error_msg = NULL;
        int rc = libssh2_session_last_error(session, &error_msg, NULL, 0);
        fprintf(stderr, "Failed to open direct-tcpip channel to %s:%d. Error %d: %s\n",
                dest_host, dest_port, rc, error_msg ? error_msg : "Unknown error");
    }

    return channel;
}

void ssh_tunnel_channel_close(LIBSSH2_CHANNEL* channel) {
    if (!channel)
        return;

    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
}

int ssh_tunnel_read(LIBSSH2_CHANNEL *channel, void *buffer, size_t buffer_size) {
    if (!channel || !buffer || buffer_size == 0) {
        return -1;
    }

    int total_read = 0;

    while (total_read < buffer_size) {
        int rc = libssh2_channel_read(channel,
                                      (char*)buffer + total_read,
                                      buffer_size - total_read);

        if (rc > 0) {
            // 成功读取数据
            total_read += rc;
        } else if (rc == LIBSSH2_ERROR_EAGAIN) {
            // 暂时没有更多数据
            if (total_read == 0) {
                return 0;  // 没有读取到任何数据
            }
            break;  // 返回已读取的数据
        } else if (rc == 0) {
            // EOF - 连接关闭
            if (total_read == 0) {
                return -1;  // 没有数据时遇到EOF
            }
            break;  // 返回已读取的数据
        } else {
            // 其他错误
            return -1;
        }
    }

    return total_read;
}

int ssh_tunnel_write(LIBSSH2_CHANNEL *channel, const void *buffer, size_t buffer_size) {
    if (!channel || !buffer || buffer_size == 0) {
        return -1;
    }

    int rc = libssh2_channel_write(channel, buffer, buffer_size);
    if (rc < 0)
        return rc == LIBSSH2_ERROR_EAGAIN?0:rc;
    return rc;
}

SOCKET_T ssh_tunnel_session_get_socket(LIBSSH2_SESSION* session) {
    if (!session) {
        return INVALID_SOCKET;
    }
    return (SOCKET_T)(intptr_t)(*libssh2_session_abstract(session));
}

int ssh_tunnel_get_error(LIBSSH2_SESSION* session, char **errmsg) {
    if (!session) {
        return -1;
    }

    return libssh2_session_last_error(session, errmsg, NULL, 0);
}
