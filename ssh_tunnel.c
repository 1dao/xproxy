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

int ssh_tunnel_init(SSHTunnel *tunnel, const char *host, int port, 
                    const char *username, const char *password) {
    if (!tunnel || !host || !username || !password) {
        return -1;
    }
    
    memset(tunnel, 0, sizeof(SSHTunnel));
    
    tunnel->host = strdup(host);
    tunnel->port = port;
    tunnel->username = strdup(username);
    tunnel->password = strdup(password);
    tunnel->state = SSH_TUNNEL_STATE_DISCONNECTED;
    tunnel->sock = INVALID_SOCKET;
    
    return 0;
}

int ssh_tunnel_connect(SSHTunnel *tunnel) {
    if (!tunnel || tunnel->state != SSH_TUNNEL_STATE_DISCONNECTED) {
        return -1;
    }
    
    struct sockaddr_in sin;
    int rc;
    
    tunnel->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel->sock == INVALID_SOCKET) {
        perror("socket");
        tunnel->state = SSH_TUNNEL_STATE_ERROR;
        return -1;
    }
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons(tunnel->port);
    if (inet_pton(AF_INET, tunnel->host, &sin.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address\n");
        tunnel->state = SSH_TUNNEL_STATE_ERROR;
        return -1;
    }
    
    tunnel->state = SSH_TUNNEL_STATE_CONNECTING;
    
    if (connect(tunnel->sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("connect");
        tunnel->state = SSH_TUNNEL_STATE_ERROR;
        return -1;
    }
    
    if (!libssh2_initialized) {
        rc = libssh2_init(0);
        if (rc != 0) {
            fprintf(stderr, "libssh2_init failed: %d\n", rc);
            tunnel->state = SSH_TUNNEL_STATE_ERROR;
            return -1;
        }
        libssh2_initialized = 1;
    }
    
    tunnel->session = libssh2_session_init();
    if (!tunnel->session) {
        fprintf(stderr, "Could not initialize SSH session\n");
        tunnel->state = SSH_TUNNEL_STATE_ERROR;
        return -1;
    }
    
    // SSH handshake
    while ((rc = libssh2_session_handshake(tunnel->session, tunnel->sock)) == LIBSSH2_ERROR_EAGAIN) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        int dir = libssh2_session_block_directions(tunnel->session);
        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
            FD_SET(tunnel->sock, &read_fds);
        }
        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            FD_SET(tunnel->sock, &write_fds);
        }
        select((int)tunnel->sock + 1, &read_fds, &write_fds, NULL, NULL);
    }
    
    if (rc) {
        fprintf(stderr, "Error when starting up SSH session: %d\n", rc);
        tunnel->state = SSH_TUNNEL_STATE_ERROR;
        return -1;
    }
    
    char *userauthlist = libssh2_userauth_list(tunnel->session, tunnel->username, (unsigned int)strlen(tunnel->username));
    if (userauthlist) {
        // Authentication methods available, no debug print needed
    }
    
    int auth_success = 0;
    
    if (userauthlist && strstr(userauthlist, "keyboard-interactive")) {
        // Trying keyboard-interactive authentication
        while ((rc = libssh2_userauth_keyboard_interactive(tunnel->session, tunnel->username, NULL)) == LIBSSH2_ERROR_EAGAIN) {
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            int dir = libssh2_session_block_directions(tunnel->session);
            if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
                FD_SET(tunnel->sock, &read_fds);
            }
            if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
                FD_SET(tunnel->sock, &write_fds);
            }
            select((int)tunnel->sock + 1, &read_fds, &write_fds, NULL, NULL);
        }
        if (rc == 0) {
            auth_success = 1;
            // Keyboard-interactive authentication succeeded
        } else {
            // Keyboard-interactive authentication failed
        }
    }
    
    if (!auth_success && userauthlist && strstr(userauthlist, "password")) {
        // Trying password authentication
        while ((rc = libssh2_userauth_password(tunnel->session, tunnel->username, tunnel->password)) == LIBSSH2_ERROR_EAGAIN) {
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            int dir = libssh2_session_block_directions(tunnel->session);
            if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
                FD_SET(tunnel->sock, &read_fds);
            }
            if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
                FD_SET(tunnel->sock, &write_fds);
            }
            select((int)tunnel->sock + 1, &read_fds, &write_fds, NULL, NULL);
        }
        if (rc == 0) {
            auth_success = 1;
            // Password authentication succeeded
        } else {
            // Password authentication failed
        }
    }
    
    if (!auth_success) {
        fprintf(stderr, "All authentication methods failed\n");
        tunnel->state = SSH_TUNNEL_STATE_ERROR;
        return -1;
    }
    
    libssh2_session_set_blocking(tunnel->session, 1);
    
    tunnel->state = SSH_TUNNEL_STATE_CONNECTED;
    return 0;
}

int ssh_tunnel_open_channel(SSHTunnel *tunnel, const char *dest_host, int dest_port,
                            const char *source_host, int source_port) {
    if (!tunnel || tunnel->state != SSH_TUNNEL_STATE_CONNECTED || !dest_host) {
        return -1;
    }
    
    int rc;
    if (!source_host) {
        source_host = "127.0.0.1";
    }
    if (source_port == 0) {
        source_port = 12345;
    }
    
    // Opening SSH channel
    
    libssh2_session_set_blocking(tunnel->session, 0);
    
    int retry_count = 0;
    int max_retries = 50;
    
    while (retry_count < max_retries) {
        tunnel->channel = libssh2_channel_direct_tcpip_ex(tunnel->session, 
                                                          dest_host, dest_port,
                                                          source_host, source_port);
        
        if (tunnel->channel) {
            // SSH channel opened successfully
            break;
        }
        
        rc = libssh2_session_last_error(tunnel->session, NULL, NULL, 0);
        
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
            int dir = libssh2_session_block_directions(tunnel->session);
            if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
                FD_SET(tunnel->sock, &read_fds);
            }
            if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
                FD_SET(tunnel->sock, &write_fds);
            }
            
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;
            
            select((int)tunnel->sock + 1, &read_fds, &write_fds, NULL, &timeout);
        } else {
            char *error_msg = NULL;
            libssh2_session_last_error(tunnel->session, &error_msg, NULL, 0);
            fprintf(stderr, "Failed to open direct-tcpip channel to %s:%d. Error %d: %s\n", 
                    dest_host, dest_port, rc, error_msg ? error_msg : "Unknown error");
            libssh2_session_set_blocking(tunnel->session, 1);
            return -1;
        }
    }
    
    if (!tunnel->channel) {
        fprintf(stderr, "Could not open direct-tcpip channel to %s:%d\n", dest_host, dest_port);
        libssh2_session_set_blocking(tunnel->session, 1);
        return -1;
    }
    
    libssh2_session_set_blocking(tunnel->session, 1);
    return 0;
}

int ssh_tunnel_read(SSHTunnel *tunnel, void *buffer, size_t buffer_size) {
    if (!tunnel || !tunnel->channel || !buffer || buffer_size == 0) {
        return -1;
    }
    
    int rc;
    while ((rc = libssh2_channel_read(tunnel->channel, buffer, buffer_size)) == LIBSSH2_ERROR_EAGAIN) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        int dir = libssh2_session_block_directions(tunnel->session);
        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
            FD_SET(tunnel->sock, &read_fds);
        }
        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            FD_SET(tunnel->sock, &write_fds);
        }
        select((int)tunnel->sock + 1, &read_fds, &write_fds, NULL, NULL);
    }
    
    return rc;
}

int ssh_tunnel_write(SSHTunnel *tunnel, const void *buffer, size_t buffer_size) {
    if (!tunnel || !tunnel->channel || !buffer || buffer_size == 0) {
        return -1;
    }
    
    int rc;
    while ((rc = libssh2_channel_write(tunnel->channel, buffer, buffer_size)) == LIBSSH2_ERROR_EAGAIN) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        int dir = libssh2_session_block_directions(tunnel->session);
        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
            FD_SET(tunnel->sock, &read_fds);
        }
        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            FD_SET(tunnel->sock, &write_fds);
        }
        select((int)tunnel->sock + 1, &read_fds, &write_fds, NULL, NULL);
    }
    
    return rc;
}

void ssh_tunnel_close(SSHTunnel *tunnel) {
    if (!tunnel) {
        return;
    }
    
    if (tunnel->channel) {
        libssh2_channel_close(tunnel->channel);
        libssh2_channel_free(tunnel->channel);
        tunnel->channel = NULL;
    }
    
    if (tunnel->session) {
        libssh2_session_disconnect(tunnel->session, "Normal Shutdown");
        libssh2_session_free(tunnel->session);
        tunnel->session = NULL;
    }
    
    if (tunnel->sock != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(tunnel->sock);
#else
        close(tunnel->sock);
#endif
        tunnel->sock = INVALID_SOCKET;
    }
    
    tunnel->state = SSH_TUNNEL_STATE_DISCONNECTED;
}

void ssh_tunnel_cleanup(SSHTunnel *tunnel) {
    if (!tunnel) {
        return;
    }
    
    ssh_tunnel_close(tunnel);
    
    if (tunnel->host) {
        free(tunnel->host);
        tunnel->host = NULL;
    }
    
    if (tunnel->username) {
        free(tunnel->username);
        tunnel->username = NULL;
    }
    
    if (tunnel->password) {
        free(tunnel->password);
        tunnel->password = NULL;
    }
    
    // Only call libssh2_exit when all tunnels have been cleaned up
    static int tunnel_count = 0;
    tunnel_count--;
    if (tunnel_count == 0 && libssh2_initialized) {
        libssh2_exit();
        libssh2_initialized = 0;
    }
}

SSHTunnelState ssh_tunnel_get_state(SSHTunnel *tunnel) {
    if (!tunnel) {
        return SSH_TUNNEL_STATE_ERROR;
    }
    
    return tunnel->state;
}

int ssh_tunnel_get_error(SSHTunnel *tunnel, char **errmsg) {
  if (!tunnel || !tunnel->session) {
    return -1;
  }

  return libssh2_session_last_error(tunnel->session, errmsg, NULL, 0);
}

void ssh_tunnel_close_channel_only(SSHTunnel *tunnel) {
  if (!tunnel) {
    return;
  }

  if (tunnel->channel) {
    libssh2_channel_close(tunnel->channel);
    libssh2_channel_free(tunnel->channel);
    tunnel->channel = NULL;
  }
  
  // Keep session and socket open for reuse
  tunnel->state = SSH_TUNNEL_STATE_CONNECTED; // Still connected, just no channel
}

int ssh_tunnel_is_session_valid(SSHTunnel *tunnel) {
  if (!tunnel || !tunnel->session || tunnel->state != SSH_TUNNEL_STATE_CONNECTED) {
    return 0;
  }
  
  // Only check the state, assume session is valid if state is CONNECTED
  return 1;
}

int ssh_tunnel_reopen_channel(SSHTunnel *tunnel, const char *dest_host, int dest_port,
                              const char *source_host, int source_port) {
  if (!tunnel || tunnel->state != SSH_TUNNEL_STATE_CONNECTED || !dest_host) {
    return -1;
  }
  
  // First close any existing channel
  ssh_tunnel_close_channel_only(tunnel);
  
  // Now open new channel using existing session
  return ssh_tunnel_open_channel(tunnel, dest_host, dest_port, source_host, source_port);
}
