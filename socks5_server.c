#include "socks5_server.h"
#include "ssh_tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;
static int g_active_connections = 0;
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;
#define MAX_CONCURRENT_CONNECTIONS 8192
#define MAX_ERROR_COUNT 10

typedef struct {
    SOCKET_T sock;
    struct sockaddr_in addr;
    LIBSSH2_SESSION *ssh_session;  // 线程级SSH session
} ClientInfo;

void socks5_send_reply(Socks5Client* client, uint8_t rep) {
    uint8_t response[10] = {0};
    response[0] = 0x05;  // SOCKS version 5
    response[1] = rep;   // Reply field
    response[2] = 0x00;  // Reserved
    response[3] = 0x01;  // ATYP: IPv4
    // DST.ADDR: 0.0.0.0
    response[4] = 0x00;
    response[5] = 0x00;
    response[6] = 0x00;
    response[7] = 0x00;
    // DST.PORT: 0
    response[8] = 0x00;
    response[9] = 0x00;

    int sent = send(client->client_sock, response, 10, 0);
    if (sent != 10) {
        fprintf(stderr, "Failed to send SOCKS5 reply: sent %d bytes\n", sent);
    } else {
        fprintf(stderr, "SOCKS5 reply sent successfully (rep: 0x%02X)\n", rep);
    }
    fflush(stderr);
}

int socks5_handle_handshake(Socks5Client* client) {
    uint8_t buf[4096];
    int n = recv(client->client_sock, buf, sizeof(buf), 0);
    if (n < 3) return -1;
    if (buf[0] != 0x05) return -1;

    uint8_t nmethods = buf[1];
    fprintf(stderr, "SOCKS5 handshake: version=0x%02X, nmethods=%d\n", buf[0], nmethods);
    fflush(stderr);

    if (n < 2 + nmethods) return -1;

    uint8_t selected_method = 0xFF;
    for (int i = 0; i < nmethods; i++) {
        fprintf(stderr, "  Method %d: 0x%02X\n", i, buf[2 + i]);
        fflush(stderr);
        if (buf[2 + i] == SOCKS5_AUTH_NONE) {
            selected_method = SOCKS5_AUTH_NONE;
            break;
        }
    }

    if (selected_method == 0xFF) {
        fprintf(stderr, "No acceptable authentication method found\n");
        fflush(stderr);
        uint8_t response[2] = {0x05, SOCKS5_AUTH_NO_ACCEPTABLE};
        send(client->client_sock, response, 2, 0);
        return -1;
    }

    fprintf(stderr, "Selected authentication method: 0x%02X\n", selected_method);
    fflush(stderr);
    uint8_t response[2] = {0x05, selected_method};
    if (send(client->client_sock, response, 2, 0) != 2) return -1;

    client->auth_method = selected_method;
    client->state = SOCKS5_STATE_AUTH;
    return 0;
}

int socks5_accout_auth(Socks5Client* client) {
    if (client->auth_method == SOCKS5_AUTH_NONE) {
        client->state = SOCKS5_STATE_REQUEST;
        return 0;
    }
    return -1;
}

int socks5_client_auth(Socks5Client* client) {
    uint8_t buf[4096];
    int n = recv(client->client_sock, buf, sizeof(buf), 0);
    if (n < 10) return -1;
    if (buf[0] != 0x05) return -1;

    client->cmd = buf[1];
    if (client->cmd != SOCKS5_CMD_CONNECT) {
        socks5_send_reply(client, SOCKS5_REP_COMMAND_NOT_SUPPORTED);
        return -1;
    }

    uint8_t atyp = buf[3];
    fprintf(stderr, "SOCKS5 request: cmd=0x%02X, atyp=0x%02X\n", buf[1], atyp);
    fflush(stderr);

    char target_host[256];
    uint16_t target_port;
    int pos = 4;

    if (atyp == SOCKS5_ATYP_IPV4) {
        fprintf(stderr, "ATYP: IPv4\n");
        fflush(stderr);
        if (n < pos + 6) return -1;
        struct in_addr addr;
        memcpy(&addr, &buf[pos], 4);
        inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
        pos += 4;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        uint8_t domain_len = buf[pos++];  // 修复这里的typo
        fprintf(stderr, "ATYP: Domain name, length=%d\n", domain_len);
        fflush(stderr);
        if (n < pos + domain_len + 2) return -1;
        if (domain_len >= sizeof(target_host)) return -1;
        memcpy(target_host, &buf[pos], domain_len);
        target_host[domain_len] = '\0';
        pos += domain_len;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        fprintf(stderr, "ATYP: IPv6\n");
        fflush(stderr);
        if (n < pos + 18) return -1;
        struct in6_addr addr6;
        memcpy(&addr6, &buf[pos], 16);
        inet_ntop(AF_INET6, &addr6, target_host, sizeof(target_host));
        pos += 16;
    } else {
        fprintf(stderr, "ATYP not supported: 0x%02X\n", atyp);
        fflush(stderr);
        socks5_send_reply(client, SOCKS5_REP_ADDRESS_NOT_SUPPORTED);
        return -1;
    }

    target_port = ntohs(*(uint16_t*)&buf[pos]);
    strncpy(client->target_host, target_host, sizeof(client->target_host) - 1);
    client->target_port = target_port;

    fprintf(stderr, "SOCKS5 request: connect to %s:%d\n", target_host, target_port);
    fflush(stderr);

    // 使用线程级的SSH session创建channel
    if (!client->ssh_session) {
        fprintf(stderr, "SSH session not available\n");
        socks5_send_reply(client, SOCKS5_REP_GENERAL_FAILURE);
        return -1;
    }

    // 尝试多次打开channel，处理EAGAIN情况
    int max_retries = 50;
    client->ssh_channel = ssh_tunnel_channel_open(client->ssh_session,
                                                   client->target_host, client->target_port,
                                                   client->client_host, client->client_port);
    if (!client->ssh_channel) {
        fprintf(stderr, "Failed to open SSH channel\n");
        socks5_send_reply(client, SOCKS5_REP_NETWORK_UNREACHABLE);
        return -1;
    }

    socks5_send_reply(client, SOCKS5_REP_SUCCESS);
    client->state = SOCKS5_STATE_CONNECTED;
    return 0;
}

void socks5_client_free(Socks5Client* client) {
    if (client->client_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(client->client_sock);
        client->client_sock = INVALID_SOCKET;
    }

    if (client->ssh_channel) {
        ssh_tunnel_channel_close(client->ssh_channel);
        client->ssh_channel = NULL;
    }

    // 注意：不在这里关闭SSH session，因为它是线程级别的

    client->state = SOCKS5_STATE_ERROR;
}

int socks5_handle_client(SOCKET_T client_sock, struct sockaddr_in* client_addr,
                         LIBSSH2_SESSION *ssh_session) {
    Socks5Client client = {0};
    client.client_sock = client_sock;
    client.ssh_session = ssh_session;
    client.state = SOCKS5_STATE_INIT;

    if (client_addr) {
        inet_ntop(AF_INET, &client_addr->sin_addr, client.client_host, sizeof(client.client_host));
        client.client_port = ntohs(client_addr->sin_port);
        fprintf(stderr, "New client connection from %s:%d, socket=%d\n",
                client.client_host, client.client_port, client_sock);
    } else {
        strcpy(client.client_host, "127.0.0.1");
        client.client_port = 0;
        fprintf(stderr, "New client connection, socket=%d\n", client_sock);
    }
    fflush(stderr);

    if (socks5_handle_handshake(&client) != 0) {
        fprintf(stderr, "SOCKS5 handshake failed\n");
        fflush(stderr);
        socks5_client_free(&client);
        return -1;
    }

    if (socks5_accout_auth(&client) != 0) {
        socks5_client_free(&client);
        return -1;
    }

    if (socks5_client_auth(&client) != 0) {
        socks5_client_free(&client);
        return -1;
    }

    fd_set read_fds, write_fds;
    SOCKET_T ssh_socket = ssh_tunnel_session_get_socket(ssh_session);

    while (client.state == SOCKS5_STATE_CONNECTED) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(client.client_sock, &read_fds);

        int max_fd = client.client_sock;

        // 添加SSH session的socket到监听集合
        if (ssh_socket != INVALID_SOCKET) {
            FD_SET(ssh_socket, &read_fds);
            if (ssh_socket > max_fd) {
                max_fd = ssh_socket;
            }

            // 如果有待写入的数据，也监听SSH socket的可写事件
            if (client.write_buffer_size > 0) {
                FD_SET(ssh_socket, &write_fds);
            }
        } else {
            // 如果没有SSH socket，直接跳过处理
            break;
        }

        struct timeval tv = {1, 0};
        int ret = select((int)max_fd + 1, &read_fds, &write_fds, NULL, &tv);
        if (ret < 0) {
            printf("Select error: %d\n", WSAGetLastError());
            break;
        }

        if (ret == 0) {
            continue; // 超时，继续等待
        }

        // 先处理SSH socket可能的可写事件（如果有待写入的数据）
        if (client.write_buffer_size > 0 && FD_ISSET(ssh_socket, &write_fds)) {
            // 计算缓冲区中剩余未写入的数据
            int remaining = client.write_buffer_size;
            int written = ssh_tunnel_write(client.ssh_channel,client.write_buffer, remaining);
            if (written < 0) {
                fprintf(stderr, "Failed to write buffered data to SSH channel, written=%d\n", written);
                break;
            } else if (written == 0) {
                // 仍然无法写入，继续等待
                fprintf(stderr, "SSH channel still not ready for write, will retry...\n");
            } else {
                // 成功写入部分或全部数据
                if (written >= remaining) {
                    // 所有数据都已写入
                    client.write_buffer_size = 0;
                    fprintf(stderr, "All buffered data (%d bytes) written to SSH channel\n", written);
                } else {
                    memmove(client.write_buffer, client.write_buffer + written, remaining - written);
                    client.write_buffer_size = remaining - written;
                    fprintf(stderr, "Partially buffered data written: %d/%d bytes\n", written, client.write_buffer_size);
                }
            }
        }

        // 检查客户端是否有数据可读
        if (FD_ISSET(client.client_sock, &read_fds)) {
            int n = recv(client.client_sock, client.read_buffer, sizeof(client.read_buffer), 0);
            if (n <= 0) {
                printf("Client disconnected\n");
                break;
            }

            if (client.ssh_channel) {
                // 检查缓冲区是否还有未写入的数据
                if (client.write_buffer_size > 0) {
                    // 缓冲区有未写入的数据，需要追加新数据到缓冲区

                    // 计算缓冲区中剩余空间
                    int buffer_space = sizeof(client.write_buffer) - client.write_buffer_size;
                    if (n > buffer_space) {
                        fprintf(stderr, "ERROR: Buffer overflow. Available: %d, needed: %d\n",
                               buffer_space, n);
                        // 缓冲区空间不足，这种情况下可能需要：
                        // 1. 增大缓冲区
                        // 2. 丢弃新数据
                        // 3. 等待缓冲区清空（暂不处理新数据）
                        fprintf(stderr, "Dropping new data, waiting for buffer to clear\n");
                        fprintf(stderr, "Dropping new data, waiting for buffer to clear\n");
                        fprintf(stderr, "Dropping new data, waiting for buffer to clear\n");
                        // 简单处理：丢弃新数据，等待缓冲区清空
                    }

                    // 将新数据追加到缓冲区末尾
                    memcpy(client.write_buffer + client.write_buffer_size, client.read_buffer, n);
                    client.write_buffer_size += n;

                    fprintf(stderr, "Appended %d bytes to write buffer, total buffered: %d bytes\n",
                           n, client.write_buffer_size);
                    // 等待socket可写事件来处理缓冲区
                    // 此处不能continue，因为需要处理可读事件
                    // 如果continue，将导致socket可读事件被忽略
                } else {
                    // 缓冲区为空，尝试直接写入
                    int written = ssh_tunnel_write(client.ssh_channel, client.read_buffer, n);
                    if (written < 0) {
                        // 写入失败，尝试缓冲数据
                        client.write_error_count++;
                        fprintf(stderr, "Failed to write to SSH channel: error count=%d\n", client.write_error_count);

                        if (client.write_error_count >= MAX_ERROR_COUNT) {
                            fprintf(stderr, "Max write error count exceeded, closing connection\n");
                            break;
                        }

                        // 尝试缓冲数据
                        if (n <= sizeof(client.write_buffer)) {
                            memcpy(client.write_buffer, client.read_buffer, n);
                            client.write_buffer_size = n;
                            fprintf(stderr, "Buffered %d bytes for retry\n", n);
                        } else {
                            fprintf(stderr, "ERROR: Data too large to buffer (%d bytes)\n", n);
                            break;
                        }
                    } else if (written == 0) {
                        // SSH channel暂时无法写入，需要缓冲所有数据
                        fprintf(stderr, "SSH channel not ready for write (EAGAIN), buffering %d bytes...\n", n);

                        if (n > sizeof(client.write_buffer)) {
                            fprintf(stderr, "ERROR: Buffer too small for %d bytes, dropping data\n", n);
                            break;
                        }

                        memcpy(client.write_buffer, client.read_buffer, n);
                        client.write_buffer_size = n;
                        fprintf(stderr, "Buffered %d bytes, will retry writing\n", n);
                    } else {
                        // 部分或全部写入成功
                        client.write_error_count = 0;  // 重置错误计数
                        fprintf(stderr, "SSH channel wrote %d bytes\n", written);

                        if (written < n) {
                            // 只写入了部分数据，需要缓冲剩余的数据
                            int remaining = n - written;
                            fprintf(stderr, "Partially written: %d/%d bytes, buffering remaining %d bytes...\n",
                                   written, n, remaining);

                            if (remaining > sizeof(client.write_buffer)) {
                                fprintf(stderr, "ERROR: Buffer too small for %d bytes, dropping data\n", remaining);
                                break;
                            }

                            // 缓冲剩余的数据
                            memcpy(client.write_buffer, client.read_buffer + written, remaining);
                            client.write_buffer_size = remaining;
                            fprintf(stderr, "Buffered remaining %d bytes\n", remaining);
                        }
                    }
                }

            }
        }

        // 检查SSH socket是否有数据可读
        if (ssh_socket != INVALID_SOCKET && FD_ISSET(ssh_socket, &read_fds)) {
            // 尝试读取尽可能多的数据
            int n = ssh_tunnel_read(client.ssh_channel, client.read_buffer, sizeof(client.read_buffer));
            if (n > 0) {
                int sent = send(client.client_sock, client.read_buffer, n, 0);
                if (sent != n) {
                    fprintf(stderr, "Failed to send %d bytes to client (sent=%d)\n", n, sent);
                    fprintf(stderr, "Failed to send %d bytes to client (sent=%d)\n", n, sent);
                    fprintf(stderr, "Failed to send %d bytes to client (sent=%d)\n", n, sent);
                    break;
                }
            } else if (n < 0) {
                fprintf(stderr, "Failed to read from SSH channel, n=%d\n", n);
                break;
            }
            // n == 0 表示暂时没有数据，继续循环
        }
    }

    socks5_client_free(&client);
    return 0;
}

static void* socks5_client_thread(void* arg) {
    ClientInfo* info = (ClientInfo*)arg;

    // 在线程开始时创建SSH session
    fprintf(stderr, "Creating SSH session to %s:%d...\n",
            g_server_config.ssh_host, g_server_config.ssh_port);
    info->ssh_session = ssh_tunnel_session_open(g_server_config.ssh_host,
                                                 g_server_config.ssh_port,
                                                 g_server_config.ssh_username,
                                                 g_server_config.ssh_password);
    if (!info->ssh_session) {
        fprintf(stderr, "Failed to create SSH session\n");
        CLOSE_SOCKET(info->sock);
        free(info);
        return NULL;
    }
    fprintf(stderr, "SSH session created successfully\n");

    pthread_mutex_lock(&g_conn_mutex);
    g_active_connections++;
    fprintf(stderr, "Active connections: %d\n", g_active_connections);
    pthread_mutex_unlock(&g_conn_mutex);

    // 处理客户端连接，传入线程级SSH session
    socks5_handle_client(info->sock, &info->addr, info->ssh_session);

    pthread_mutex_lock(&g_conn_mutex);
    g_active_connections--;
    fprintf(stderr, "Active connections: %d (connection closed)\n", g_active_connections);
    pthread_mutex_unlock(&g_conn_mutex);

    // 关闭线程级SSH session
    fprintf(stderr, "Closing SSH session...\n");
    ssh_tunnel_session_close(info->ssh_session);

    free(info);
    return NULL;
}

int socks5_server_init(const Socks5ServerConfig* config) {
    if (!config) return -1;
    memcpy(&g_server_config, config, sizeof(Socks5ServerConfig));
    return 0;
}

int socks5_server_run(void) {
    SOCKET_T listen_sock;
    struct sockaddr_in server_addr;

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        perror("socket creation failed");
        return -1;
    }

    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        CLOSE_SOCKET(listen_sock);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = g_server_config.bind_address ?
        inet_addr(g_server_config.bind_address) : INADDR_ANY;
    server_addr.sin_port = htons(g_server_config.bind_port);

    if (bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        CLOSE_SOCKET(listen_sock);
        return -1;
    }

    if (listen(listen_sock, SOMAXCONN) < 0) {
        perror("listen failed");
        CLOSE_SOCKET(listen_sock);
        return -1;
    }

    printf("SOCKS5 server v1 listening on %s:%d\n",
           g_server_config.bind_address ? g_server_config.bind_address : "0.0.0.0",
           g_server_config.bind_port);
    printf("SSH tunnel: %s:%d (user: %s)\n",
           g_server_config.ssh_host, g_server_config.ssh_port,
           g_server_config.ssh_username);

    g_server_running = 1;

    while (g_server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        SOCKET_T client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET) {
            if (g_server_running) perror("accept failed");
            continue;
        }

        printf("New client connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        pthread_mutex_lock(&g_conn_mutex);
        if (g_active_connections >= MAX_CONCURRENT_CONNECTIONS) {
            pthread_mutex_unlock(&g_conn_mutex);
            fprintf(stderr, "Too many connections (%d), rejecting new connection\n", g_active_connections);
            CLOSE_SOCKET(client_sock);
            continue;
        }
        pthread_mutex_unlock(&g_conn_mutex);

        ClientInfo* client_info = (ClientInfo*)malloc(sizeof(ClientInfo));
        if (!client_info) {
            perror("malloc failed");
            CLOSE_SOCKET(client_sock);
            continue;
        }
        client_info->sock = client_sock;
        memcpy(&client_info->addr, &client_addr, sizeof(client_addr));
        client_info->ssh_session = NULL;  // 将在线程中创建

        // 创建线程处理客户连接
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, socks5_client_thread, (void*)client_info) != 0) {
            perror("pthread_create failed");
            free(client_info);
            CLOSE_SOCKET(client_sock);
            continue;
        }

        // 分离线程，让它自行清理
        pthread_detach(thread_id);
    }

    CLOSE_SOCKET(listen_sock);
    return 0;
}

void socks5_server_stop(void) {
    g_server_running = 0;
}
