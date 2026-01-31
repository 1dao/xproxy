#include "socks5_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;
static int g_active_connections = 0;
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;
#define MAX_CONCURRENT_CONNECTIONS 8192

typedef struct {
    SOCKET_T sock;
    struct sockaddr_in addr;
} ClientInfo;

static void* socks5_client_thread(void* arg) {
    ClientInfo* info = (ClientInfo*)arg;

    pthread_mutex_lock(&g_conn_mutex);
    g_active_connections++;
    fprintf(stderr, "Active connections: %d\n", g_active_connections);
    pthread_mutex_unlock(&g_conn_mutex);

    socks5_handle_client(info->sock, &info->addr);

    pthread_mutex_lock(&g_conn_mutex);
    g_active_connections--;
    fprintf(stderr, "Active connections: %d (connection closed)\n", g_active_connections);
    pthread_mutex_unlock(&g_conn_mutex);

    free(info);
    return NULL;
}

void socks5_send_reply(Socks5Client* client, uint8_t rep) {
    uint8_t response[10] = {0};
    response[0] = 0x05;  // SOCKS version 5
    response[1] = rep;   // Reply field
    response[2] = 0x00;  // Reserved
    response[3] = 0x01;  // ATYP: IPv4
    // DST.ADDR: 0.0.0.0 (we don't know the real address, so use 0.0.0.0)
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
        fflush(stderr);
    } else {
        fprintf(stderr, "SOCKS5 reply sent successfully (rep: 0x%02X)\n", rep);
        fflush(stderr);
    }
}

// 简单的TCP转发到SSH服务器
static int forward_to_ssh_server(Socks5Client* client) {
    struct sockaddr_in ssh_addr;
    SOCKET_T ssh_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (ssh_sock == INVALID_SOCKET) return -1;

    memset(&ssh_addr, 0, sizeof(ssh_addr));
    ssh_addr.sin_family = AF_INET;
    ssh_addr.sin_port = htons(g_server_config.ssh_port);
    inet_pton(AF_INET, g_server_config.ssh_host, &ssh_addr.sin_addr);

    printf("Connecting to SSH server %s:%d...\n", g_server_config.ssh_host, g_server_config.ssh_port);
    if (connect(ssh_sock, (struct sockaddr*)&ssh_addr, sizeof(ssh_addr)) < 0) {
        perror("Failed to connect to SSH server");
        CLOSE_SOCKET(ssh_sock);
        return -1;
    }

    printf("Connected to SSH server\n");

    // 这里应该实现SSH协议握手和认证
    // 为了演示，我们直接转发数据
    // 实际应用中需要实现SSH协议

    client->remote_sock = ssh_sock;
    return 0;
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

int socks5_handle_auth(Socks5Client* client) {
    if (client->auth_method == SOCKS5_AUTH_NONE) {
        client->state = SOCKS5_STATE_REQUEST;
        return 0;
    }
    return -1;
}

int socks5_handle_request(Socks5Client* client) {
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
        uint8_t domain_len = buf[pos++];
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

    if (socks5_establish_ssh_tunnel(client, &g_server_config) != 0) {
        socks5_send_reply(client, SOCKS5_REP_NETWORK_UNREACHABLE);
        return -1;
    }

    socks5_send_reply(client, SOCKS5_REP_SUCCESS);
    client->state = SOCKS5_STATE_CONNECTED;
    return 0;
}

int socks5_establish_ssh_tunnel(Socks5Client* client, const Socks5ServerConfig* config) {
    // 为每个连接创建独立的SSH隧道
    SSHTunnel *tunnel = (SSHTunnel *)malloc(sizeof(SSHTunnel));
    if (!tunnel) {
        fprintf(stderr, "Failed to allocate SSH tunnel\n");
        return -1;
    }

    // 初始化SSH隧道
    if (ssh_tunnel_init(tunnel, config->ssh_host, config->ssh_port,
                       config->ssh_username, config->ssh_password) != 0) {
        fprintf(stderr, "Failed to initialize SSH tunnel\n");
        free(tunnel);
        return -1;
    }

    // 连接到SSH服务器
    printf("Connecting to SSH server %s:%d...\n", config->ssh_host, config->ssh_port);
    if (ssh_tunnel_connect(tunnel) != 0) {
        fprintf(stderr, "Failed to connect to SSH server\n");
        ssh_tunnel_cleanup(tunnel);
        free(tunnel);
        return -1;
    }

    printf("SSH connection established\n");

    // 打开通道到目标主机
    printf("Opening SSH channel to %s:%d...\n", client->target_host, client->target_port);
    if (ssh_tunnel_open_channel(tunnel, client->target_host, client->target_port,
                                client->client_host, client->client_port) != 0) {
        fprintf(stderr, "Failed to open SSH channel\n");

        // 添加详细的错误信息
        char* error_msg = NULL;
        int error_code = ssh_tunnel_get_error(tunnel, &error_msg);
        fprintf(stderr, "SSH tunnel error %d: %s\n", error_code, error_msg ? error_msg : "Unknown error");

        ssh_tunnel_close(tunnel);
        ssh_tunnel_cleanup(tunnel);
        free(tunnel);
        return -1;
    }

    printf("SSH channel opened successfully\n");

    client->ssh_tunnel = tunnel;
    client->remote_sock = INVALID_SOCKET;  // SSH隧道不使用socket
    return 0;
}

void socks5_client_free(Socks5Client* client) {
    if (client->client_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(client->client_sock);
        client->client_sock = INVALID_SOCKET;
    }
    if (client->remote_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(client->remote_sock);
        client->remote_sock = INVALID_SOCKET;
    }
    if (client->ssh_tunnel) {
        ssh_tunnel_close(client->ssh_tunnel);
        ssh_tunnel_cleanup(client->ssh_tunnel);
        free(client->ssh_tunnel);
        client->ssh_tunnel = NULL;
    }
    client->state = SOCKS5_STATE_ERROR;
}

int socks5_handle_client(SOCKET_T client_sock, struct sockaddr_in* client_addr) {
    Socks5Client client = {0};
    client.client_sock = client_sock;
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

    if (socks5_handle_auth(&client) != 0) {
        socks5_client_free(&client);
        return -1;
    }

    if (socks5_handle_request(&client) != 0) {
        socks5_client_free(&client);
        return -1;
    }

    fd_set read_fds;
    char buffer[8192];

    while (client.state == SOCKS5_STATE_CONNECTED) {
        FD_ZERO(&read_fds);
        FD_SET(client.client_sock, &read_fds);

        int max_fd = client.client_sock;

        // 如果SSH隧道有套接字，也添加到fd_set中
        if (client.ssh_tunnel && client.ssh_tunnel->sock != INVALID_SOCKET) {
            FD_SET(client.ssh_tunnel->sock, &read_fds);
            if (client.ssh_tunnel->sock > max_fd) {
                max_fd = client.ssh_tunnel->sock;
            }
        }

        struct timeval tv = {1, 0};
        int ret = select((int)max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            printf("Select error: %d\n", WSAGetLastError());
            break;
        }

        if (ret == 0) {
            continue; // 超时，继续等待
        }

        // 检查客户端是否有数据可读
        if (FD_ISSET(client.client_sock, &read_fds)) {
            int n = recv(client.client_sock, buffer, sizeof(buffer), 0);
            if (n <= 0) {
                printf("Client disconnected\n");
                break;
            }

            // 通过SSH隧道写入数据
            if (client.ssh_tunnel) {
                fprintf(stderr, "Writing %d bytes to SSH tunnel (client -> target)...\n", n);
                fflush(stderr);
                int written = ssh_tunnel_write(client.ssh_tunnel, buffer, n);
                if (written <= 0) {
                    fprintf(stderr, "Failed to write to SSH tunnel, written=%d\n", written);

                    // 添加详细的错误信息
                    char* error_msg = NULL;
                    int error_code = ssh_tunnel_get_error(client.ssh_tunnel, &error_msg);
                    fprintf(stderr, "SSH tunnel write error %d: %s\n", error_code, error_msg ? error_msg : "Unknown error");
                    fflush(stderr);

                    break;
                } else {
                    fprintf(stderr, "Successfully wrote %d bytes to SSH tunnel\n", written);
                    fflush(stderr);
                }
            }
        }

        // 检查SSH隧道是否有数据可读
            if (client.ssh_tunnel && client.ssh_tunnel->sock != INVALID_SOCKET &&
                FD_ISSET(client.ssh_tunnel->sock, &read_fds)) {
                fprintf(stderr, "Reading from SSH tunnel (target -> client)...\n");
                fflush(stderr);
                int n = ssh_tunnel_read(client.ssh_tunnel, buffer, sizeof(buffer));
                if (n > 0) {
                    fprintf(stderr, "Read %d bytes from SSH tunnel, sending to client...\n", n);
                    fflush(stderr);
                    int sent = send(client.client_sock, buffer, n, 0);
                    if (sent != n) {
                        fprintf(stderr, "Failed to send %d bytes to client (sent=%d)\n", n, sent);
                        fflush(stderr);
                        break;
                    } else {
                        fprintf(stderr, "Successfully sent %d bytes to client\n", sent);
                        fflush(stderr);
                    }
                } else if (n < 0) {
                    fprintf(stderr, "Failed to read from SSH tunnel, n=%d\n", n);

                    // 添加详细的错误信息
                    char* error_msg = NULL;
                    int error_code = ssh_tunnel_get_error(client.ssh_tunnel, &error_msg);
                    fprintf(stderr, "SSH tunnel read error %d: %s\n", error_code, error_msg ? error_msg : "Unknown error");
                    fflush(stderr);

                    break;
                } else {
                    fprintf(stderr, "SSH tunnel read returned 0 (EOF or no data)\n");
                    fflush(stderr);
                }
            }
    }

    socks5_client_free(&client);
    return 0;
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

    printf("SOCKS5 server listening on %s:%d\n",
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
