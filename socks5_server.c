#include "socks5_server.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static Socks5ServerConfig g_server_config;
static int g_server_running = 0;
static int g_active_connections = 0;
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;
#define MAX_CONCURRENT_CONNECTIONS 8192

// SSH tunnel pool configuration
#define MAX_TUNNEL_POOL_SIZE 10
#define TUNNEL_POOL_TIMEOUT_MS 30000 // 30 second idle timeout

typedef struct {
  SSHTunnel *tunnel;
  int in_use;
  time_t last_used;
  char current_target_host[256];
  int current_target_port;
} TunnelPoolEntry;

static TunnelPoolEntry g_tunnel_pool[MAX_TUNNEL_POOL_SIZE];
static pthread_mutex_t g_tunnel_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  SOCKET_T sock;
  struct sockaddr_in addr;
} ClientInfo;

// Tunnel pool management function declarations
static void tunnel_pool_init(void);
static SSHTunnel *tunnel_pool_acquire(const char *target_host, int target_port,
                                      const char *source_host, int source_port);
static void tunnel_pool_release(SSHTunnel *tunnel);
static void tunnel_pool_cleanup(void);
static SSHTunnel *create_new_tunnel(void);
static int is_tunnel_reusable(SSHTunnel *tunnel);

// Tunnel pool management function implementation
static void tunnel_pool_init(void) {
  pthread_mutex_lock(&g_tunnel_pool_mutex);
  for (int i = 0; i < MAX_TUNNEL_POOL_SIZE; i++) {
    g_tunnel_pool[i].tunnel = NULL;
    g_tunnel_pool[i].in_use = 0;
    g_tunnel_pool[i].last_used = 0;
    g_tunnel_pool[i].current_target_host[0] = '\0';
    g_tunnel_pool[i].current_target_port = 0;
  }
  pthread_mutex_unlock(&g_tunnel_pool_mutex);
}

static SSHTunnel *create_new_tunnel(void) {
  SSHTunnel *tunnel = (SSHTunnel *)malloc(sizeof(SSHTunnel));
  if (!tunnel) {
    fprintf(stderr, "Failed to allocate SSH tunnel\n");
    return NULL;
  }

  // Initialize SSH tunnel
  if (ssh_tunnel_init(tunnel, g_server_config.ssh_host,
                      g_server_config.ssh_port, g_server_config.ssh_username,
                      g_server_config.ssh_password) != 0) {
    fprintf(stderr, "Failed to initialize SSH tunnel\n");
    free(tunnel);
    return NULL;
  }

  // Connect to SSH server
  if (ssh_tunnel_connect(tunnel) != 0) {
    fprintf(stderr, "Failed to connect to SSH server\n");
    ssh_tunnel_cleanup(tunnel);
    free(tunnel);
    return NULL;
  }

  return tunnel;
}

static int is_tunnel_reusable(SSHTunnel *tunnel) {
  if (!tunnel)
    return 0;

  // Check if session is still valid
  if (ssh_tunnel_is_session_valid(tunnel) == 0) {
    return 0;
  }

  // Check if tunnel has been idle too long
  time_t now = time(NULL);
  pthread_mutex_lock(&g_tunnel_pool_mutex);
  for (int i = 0; i < MAX_TUNNEL_POOL_SIZE; i++) {
    if (g_tunnel_pool[i].tunnel == tunnel) {
      if (g_tunnel_pool[i].in_use == 0 &&
          (now - g_tunnel_pool[i].last_used) * 1000 > TUNNEL_POOL_TIMEOUT_MS) {
        pthread_mutex_unlock(&g_tunnel_pool_mutex);
        return 0; // Tunnel idle timeout
      }
      pthread_mutex_unlock(&g_tunnel_pool_mutex);
      return 1;
    }
  }
  pthread_mutex_unlock(&g_tunnel_pool_mutex);
  return 0;
}

static SSHTunnel *tunnel_pool_acquire(const char *target_host, int target_port,
                                      const char *source_host,
                                      int source_port) {
  pthread_mutex_lock(&g_tunnel_pool_mutex);

  time_t now = time(NULL);

  // 1. First try to find idle and reusable tunnels
  for (int i = 0; i < MAX_TUNNEL_POOL_SIZE; i++) {
    if (g_tunnel_pool[i].tunnel != NULL && g_tunnel_pool[i].in_use == 0) {
      // Check if tunnel is still valid
      if (ssh_tunnel_is_session_valid(g_tunnel_pool[i].tunnel) == 1) {
        // Check if it's the same target (can reuse channel)
        if (strcmp(g_tunnel_pool[i].current_target_host, target_host) == 0 &&
            g_tunnel_pool[i].current_target_port == target_port) {
          // Same target, can reuse directly
          g_tunnel_pool[i].in_use = 1;
          g_tunnel_pool[i].last_used = now;
          SSHTunnel *tunnel = g_tunnel_pool[i].tunnel;
          pthread_mutex_unlock(&g_tunnel_pool_mutex);
          return tunnel;
        }

        // Different target, but can reuse session (close old channel, open new
        // channel)
        g_tunnel_pool[i].in_use = 1;
        g_tunnel_pool[i].last_used = now;
        strncpy(g_tunnel_pool[i].current_target_host, target_host,
                sizeof(g_tunnel_pool[i].current_target_host) - 1);
        g_tunnel_pool[i]
            .current_target_host[sizeof(g_tunnel_pool[i].current_target_host) -
                                 1] = '\0';
        g_tunnel_pool[i].current_target_port = target_port;

        SSHTunnel *tunnel = g_tunnel_pool[i].tunnel;
        pthread_mutex_unlock(&g_tunnel_pool_mutex);

        // Reopen channel to new target
        if (ssh_tunnel_reopen_channel(tunnel, target_host, target_port,
                                      source_host, source_port) != 0) {
          fprintf(stderr, "Failed to reopen SSH channel to %s:%d\n",
                  target_host, target_port);
          tunnel_pool_release(tunnel);
          return NULL;
        }

        return tunnel;
      } else {
        // Tunnel invalid, clean it up
        ssh_tunnel_close(g_tunnel_pool[i].tunnel);
        ssh_tunnel_cleanup(g_tunnel_pool[i].tunnel);
        free(g_tunnel_pool[i].tunnel);
        g_tunnel_pool[i].tunnel = NULL;
        g_tunnel_pool[i].in_use = 0;
        g_tunnel_pool[i].last_used = 0;
      }
    }
  }

  // 2. Find empty slot to create new tunnel
  for (int i = 0; i < MAX_TUNNEL_POOL_SIZE; i++) {
    if (g_tunnel_pool[i].tunnel == NULL) {
      SSHTunnel *tunnel = create_new_tunnel();
      if (!tunnel) {
        pthread_mutex_unlock(&g_tunnel_pool_mutex);
        return NULL;
      }

      // Open channel to target host
      if (ssh_tunnel_open_channel(tunnel, target_host, target_port, source_host,
                                  source_port) != 0) {
        fprintf(stderr, "Failed to open SSH channel to %s:%d\n", target_host,
                target_port);
        ssh_tunnel_close(tunnel);
        ssh_tunnel_cleanup(tunnel);
        free(tunnel);
        pthread_mutex_unlock(&g_tunnel_pool_mutex);
        return NULL;
      }

      g_tunnel_pool[i].tunnel = tunnel;
      g_tunnel_pool[i].in_use = 1;
      g_tunnel_pool[i].last_used = now;
      strncpy(g_tunnel_pool[i].current_target_host, target_host,
              sizeof(g_tunnel_pool[i].current_target_host) - 1);
      g_tunnel_pool[i]
          .current_target_host[sizeof(g_tunnel_pool[i].current_target_host) -
                               1] = '\0';
      g_tunnel_pool[i].current_target_port = target_port;

      pthread_mutex_unlock(&g_tunnel_pool_mutex);
      return tunnel;
    }
  }

  // 3. All slots are in use, return NULL (caller should create temporary
  // tunnel)
  pthread_mutex_unlock(&g_tunnel_pool_mutex);
  return NULL;
}

static void tunnel_pool_release(SSHTunnel *tunnel) {
  if (!tunnel)
    return;

  pthread_mutex_lock(&g_tunnel_pool_mutex);

  // Find tunnel position in pool
  for (int i = 0; i < MAX_TUNNEL_POOL_SIZE; i++) {
    if (g_tunnel_pool[i].tunnel == tunnel) {
      // Close only the channel, keep session and connection
      ssh_tunnel_close_channel_only(tunnel);

      g_tunnel_pool[i].in_use = 0;
      g_tunnel_pool[i].last_used = time(NULL);

      pthread_mutex_unlock(&g_tunnel_pool_mutex);
      return;
    }
  }

  pthread_mutex_unlock(&g_tunnel_pool_mutex);

  // Tunnel not in pool, close completely
  ssh_tunnel_close(tunnel);
  ssh_tunnel_cleanup(tunnel);
  free(tunnel);
}

static void tunnel_pool_cleanup(void) {
  pthread_mutex_lock(&g_tunnel_pool_mutex);

  for (int i = 0; i < MAX_TUNNEL_POOL_SIZE; i++) {
    if (g_tunnel_pool[i].tunnel != NULL) {
      ssh_tunnel_close(g_tunnel_pool[i].tunnel);
      ssh_tunnel_cleanup(g_tunnel_pool[i].tunnel);
      free(g_tunnel_pool[i].tunnel);
      g_tunnel_pool[i].tunnel = NULL;
      g_tunnel_pool[i].in_use = 0;
      g_tunnel_pool[i].last_used = 0;
      g_tunnel_pool[i].current_target_host[0] = '\0';
      g_tunnel_pool[i].current_target_port = 0;
    }
  }

  pthread_mutex_unlock(&g_tunnel_pool_mutex);
}

static void *socks5_client_thread(void *arg) {
  ClientInfo *info = (ClientInfo *)arg;

  pthread_mutex_lock(&g_conn_mutex);
  g_active_connections++;

  pthread_mutex_unlock(&g_conn_mutex);

  socks5_handle_client(info->sock, &info->addr);

  pthread_mutex_lock(&g_conn_mutex);
  g_active_connections--;

  pthread_mutex_unlock(&g_conn_mutex);

  free(info);
  return NULL;
}

void socks5_send_reply(Socks5Client *client, uint8_t rep) {
  uint8_t response[10] = {0};
  response[0] = 0x05; // SOCKS version 5
  response[1] = rep;  // Reply field
  response[2] = 0x00; // Reserved
  response[3] = 0x01; // ATYP: IPv4
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
  }
}

int socks5_handle_handshake(Socks5Client *client) {
  uint8_t buf[4096];
  int n = recv(client->client_sock, buf, sizeof(buf), 0);
  if (n < 3)
    return -1;
  if (buf[0] != 0x05)
    return -1;

  uint8_t nmethods = buf[1];

  if (n < 2 + nmethods)
    return -1;

  uint8_t selected_method = 0xFF;
  for (int i = 0; i < nmethods; i++) {

    if (buf[2 + i] == SOCKS5_AUTH_NONE) {
      selected_method = SOCKS5_AUTH_NONE;
      break;
    }
  }

  if (selected_method == 0xFF) {
    fprintf(stderr, "No acceptable authentication method found\n");
    uint8_t response[2] = {0x05, SOCKS5_AUTH_NO_ACCEPTABLE};
    send(client->client_sock, response, 2, 0);
    return -1;
  }

  uint8_t response[2] = {0x05, selected_method};
  if (send(client->client_sock, response, 2, 0) != 2)
    return -1;

  client->auth_method = selected_method;
  client->state = SOCKS5_STATE_AUTH;
  return 0;
}

int socks5_handle_auth(Socks5Client *client) {
  if (client->auth_method == SOCKS5_AUTH_NONE) {
    client->state = SOCKS5_STATE_REQUEST;
    return 0;
  }
  return -1;
}

int socks5_handle_request(Socks5Client *client) {
  uint8_t buf[4096];
  int n = recv(client->client_sock, buf, sizeof(buf), 0);
  if (n < 10)
    return -1;
  if (buf[0] != 0x05)
    return -1;

  client->cmd = buf[1];
  if (client->cmd != SOCKS5_CMD_CONNECT) {
    socks5_send_reply(client, SOCKS5_REP_COMMAND_NOT_SUPPORTED);
    return -1;
  }

  uint8_t atyp = buf[3];

  char target_host[256];
  uint16_t target_port;
  int pos = 4;

  if (atyp == SOCKS5_ATYP_IPV4) {

    if (n < pos + 6)
      return -1;
    struct in_addr addr;
    memcpy(&addr, &buf[pos], 4);
    inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
    pos += 4;
  } else if (atyp == SOCKS5_ATYP_DOMAIN) {
    uint8_t domain_len = buf[pos++];
    if (n < pos + domain_len + 2)
      return -1;
    if (domain_len >= sizeof(target_host))
      return -1;
    memcpy(target_host, &buf[pos], domain_len);
    target_host[domain_len] = '\0';
    pos += domain_len;
  } else if (atyp == SOCKS5_ATYP_IPV6) {

    if (n < pos + 18)
      return -1;
    struct in6_addr addr6;
    memcpy(&addr6, &buf[pos], 16);
    inet_ntop(AF_INET6, &addr6, target_host, sizeof(target_host));
    pos += 16;
  } else {
    fprintf(stderr, "ATYP not supported: 0x%02X\n", atyp);
    socks5_send_reply(client, SOCKS5_REP_ADDRESS_NOT_SUPPORTED);
    return -1;
  }

  target_port = ntohs(*(uint16_t *)&buf[pos]);
  strncpy(client->target_host, target_host, sizeof(client->target_host) - 1);
  client->target_port = target_port;

  if (socks5_establish_ssh_tunnel(client, &g_server_config) != 0) {
    socks5_send_reply(client, SOCKS5_REP_NETWORK_UNREACHABLE);
    return -1;
  }

  socks5_send_reply(client, SOCKS5_REP_SUCCESS);
  client->state = SOCKS5_STATE_CONNECTED;
  return 0;
}

int socks5_establish_ssh_tunnel(Socks5Client *client,
                                const Socks5ServerConfig *config) {
  // Try to get existing tunnel from tunnel pool
  SSHTunnel *tunnel =
      tunnel_pool_acquire(client->target_host, client->target_port,
                          client->client_host, client->client_port);

  if (!tunnel) {
    // If no tunnel available in pool, create a temporary tunnel

    tunnel = (SSHTunnel *)malloc(sizeof(SSHTunnel));
    if (!tunnel) {
      fprintf(stderr, "Failed to allocate SSH tunnel\n");
      return -1;
    }

    // Initialize SSH tunnel
    if (ssh_tunnel_init(tunnel, config->ssh_host, config->ssh_port,
                        config->ssh_username, config->ssh_password) != 0) {
      fprintf(stderr, "Failed to initialize SSH tunnel\n");
      free(tunnel);
      return -1;
    }

    // Connect to SSH server

    if (ssh_tunnel_connect(tunnel) != 0) {
      fprintf(stderr, "Failed to connect to SSH server\n");
      ssh_tunnel_cleanup(tunnel);
      free(tunnel);
      return -1;
    }

    // Open channel to target host

    if (ssh_tunnel_open_channel(tunnel, client->target_host,
                                client->target_port, client->client_host,
                                client->client_port) != 0) {
      fprintf(stderr, "Failed to open SSH channel\n");

      // Add detailed error information
      char *error_msg = NULL;
      int error_code = ssh_tunnel_get_error(tunnel, &error_msg);
      fprintf(stderr, "SSH tunnel error %d: %s\n", error_code,
              error_msg ? error_msg : "Unknown error");

      ssh_tunnel_close(tunnel);
      ssh_tunnel_cleanup(tunnel);
      free(tunnel);
      return -1;
    }
  } else {
  }

  client->ssh_tunnel = tunnel;
  client->remote_sock = INVALID_SOCKET; // SSH tunnel doesn't use socket
  return 0;
}

void socks5_client_free(Socks5Client *client) {
  if (client->client_sock != INVALID_SOCKET) {
    CLOSE_SOCKET(client->client_sock);
    client->client_sock = INVALID_SOCKET;
  }
  if (client->remote_sock != INVALID_SOCKET) {
    CLOSE_SOCKET(client->remote_sock);
    client->remote_sock = INVALID_SOCKET;
  }
  if (client->ssh_tunnel) {
    // Release tunnel back to pool instead of closing completely
    tunnel_pool_release(client->ssh_tunnel);
    client->ssh_tunnel = NULL;
  }
  client->state = SOCKS5_STATE_ERROR;
}

int socks5_handle_client(SOCKET_T client_sock,
                         struct sockaddr_in *client_addr) {
  Socks5Client client = {0};
  client.client_sock = client_sock;
  client.state = SOCKS5_STATE_INIT;

  if (client_addr) {
    inet_ntop(AF_INET, &client_addr->sin_addr, client.client_host,
              sizeof(client.client_host));
    client.client_port = ntohs(client_addr->sin_port);

  } else {
    strcpy(client.client_host, "127.0.0.1");
    client.client_port = 0;
  }

  if (socks5_handle_handshake(&client) != 0) {

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

    // If SSH tunnel has a socket, also add it to fd_set
    if (client.ssh_tunnel && client.ssh_tunnel->sock != INVALID_SOCKET) {
      FD_SET(client.ssh_tunnel->sock, &read_fds);
      if (client.ssh_tunnel->sock > max_fd) {
        max_fd = client.ssh_tunnel->sock;
      }
    }

    struct timeval tv = {1, 0};
    int ret = select((int)max_fd + 1, &read_fds, NULL, NULL, &tv);
    if (ret < 0) {
      fprintf(stderr, "Select error: %d\n", WSAGetLastError());
      break;
    }

    if (ret == 0) {
      continue; // Timeout, continue waiting
    }

    // Check if client has data to read
    if (FD_ISSET(client.client_sock, &read_fds)) {
      int n = recv(client.client_sock, buffer, sizeof(buffer), 0);
      if (n <= 0) {
        // Client disconnected
        break;
      }

      // Write data through SSH tunnel
      if (client.ssh_tunnel) {

        int written = ssh_tunnel_write(client.ssh_tunnel, buffer, n);
        if (written <= 0) {
          fprintf(stderr, "Failed to write to SSH tunnel, written=%d\n",
                  written);

          // Add detailed error information
          char *error_msg = NULL;
          int error_code = ssh_tunnel_get_error(client.ssh_tunnel, &error_msg);
          fprintf(stderr, "SSH tunnel write error %d: %s\n", error_code,
                  error_msg ? error_msg : "Unknown error");
          break;
        } else {
        }
      }
    }

    // Check if SSH tunnel has data to read
    if (client.ssh_tunnel && client.ssh_tunnel->sock != INVALID_SOCKET &&
        FD_ISSET(client.ssh_tunnel->sock, &read_fds)) {

      int n = ssh_tunnel_read(client.ssh_tunnel, buffer, sizeof(buffer));
      if (n > 0) {

        int sent = send(client.client_sock, buffer, n, 0);
        if (sent != n) {
          fprintf(stderr, "Failed to send %d bytes to client (sent=%d)\n", n,
                  sent);
          break;
        } else {
        }
      } else if (n < 0) {
        fprintf(stderr, "Failed to read from SSH tunnel, n=%d\n", n);

        // Add detailed error information
        char *error_msg = NULL;
        int error_code = ssh_tunnel_get_error(client.ssh_tunnel, &error_msg);
        fprintf(stderr, "SSH tunnel read error %d: %s\n", error_code,
                error_msg ? error_msg : "Unknown error");

        break;
      } else {
      }
    }
  }

  socks5_client_free(&client);
  return 0;
}

int socks5_server_init(const Socks5ServerConfig *config) {
  if (!config)
    return -1;
  memcpy(&g_server_config, config, sizeof(Socks5ServerConfig));
  tunnel_pool_init();
  return 0;
}

void socks5_server_cleanup(void) { tunnel_pool_cleanup(); }

int socks5_server_run(void) {
  SOCKET_T listen_sock;
  struct sockaddr_in server_addr;

  listen_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sock == INVALID_SOCKET) {
    perror("socket creation failed");
    return -1;
  }

  int opt = 1;
  if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
                 sizeof(opt)) < 0) {
    perror("setsockopt failed");
    CLOSE_SOCKET(listen_sock);
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = g_server_config.bind_address
                                    ? inet_addr(g_server_config.bind_address)
                                    : INADDR_ANY;
  server_addr.sin_port = htons(g_server_config.bind_port);

  if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("bind failed");
    CLOSE_SOCKET(listen_sock);
    return -1;
  }

  if (listen(listen_sock, SOMAXCONN) < 0) {
    perror("listen failed");
    CLOSE_SOCKET(listen_sock);
    return -1;
  }

  g_server_running = 1;

  while (g_server_running) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    SOCKET_T client_sock =
        accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock == INVALID_SOCKET) {
      if (g_server_running)
        perror("accept failed");
      continue;
    }

    pthread_mutex_lock(&g_conn_mutex);
    if (g_active_connections >= MAX_CONCURRENT_CONNECTIONS) {
      pthread_mutex_unlock(&g_conn_mutex);
      fprintf(stderr, "Too many connections (%d), rejecting new connection\n",
              g_active_connections);
      CLOSE_SOCKET(client_sock);
      continue;
    }
    pthread_mutex_unlock(&g_conn_mutex);

    ClientInfo *client_info = (ClientInfo *)malloc(sizeof(ClientInfo));
    if (!client_info) {
      perror("malloc failed");
      CLOSE_SOCKET(client_sock);
      continue;
    }
    client_info->sock = client_sock;
    memcpy(&client_info->addr, &client_addr, sizeof(client_addr));

    // Create thread to handle client connection
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, socks5_client_thread,
                       (void *)client_info) != 0) {
      perror("pthread_create failed");
      free(client_info);
      CLOSE_SOCKET(client_sock);
      continue;
    }

    // Detach thread to let it clean up itself
    pthread_detach(thread_id);
  }

  CLOSE_SOCKET(listen_sock);
  return 0;
}

void socks5_server_stop(void) { g_server_running = 0; }
