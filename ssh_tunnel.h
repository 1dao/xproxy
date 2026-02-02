#ifndef SSH_TUNNEL_H
#define SSH_TUNNEL_H

#include <libssh2.h>
#include "socket_util.h"

#define SSH_MAX_BUFFER_SIZE 16384

typedef enum {
    SSH_TUNNEL_STATE_DISCONNECTED,
    SSH_TUNNEL_STATE_CONNECTING,
    SSH_TUNNEL_STATE_CONNECTED,
    SSH_TUNNEL_STATE_ERROR
} SSHTunnelState;

typedef struct {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    SOCKET_T sock;
    SSHTunnelState state;
    char *username;
    char *password;
    char *host;
    int port;
} SSHTunnel;

// Initialize SSH tunnel
int ssh_tunnel_init(SSHTunnel *tunnel, const char *host, int port, 
                    const char *username, const char *password);

// Connect to SSH server
int ssh_tunnel_connect(SSHTunnel *tunnel);

// Open channel to target host
int ssh_tunnel_open_channel(SSHTunnel *tunnel, const char *dest_host, int dest_port,
                            const char *source_host, int source_port);

// Read data from SSH channel
int ssh_tunnel_read(SSHTunnel *tunnel, void *buffer, size_t buffer_size);

// Write data to SSH channel
int ssh_tunnel_write(SSHTunnel *tunnel, const void *buffer, size_t buffer_size);

// Close SSH tunnel
void ssh_tunnel_close(SSHTunnel *tunnel);

// Clean up SSH tunnel resources
void ssh_tunnel_cleanup(SSHTunnel *tunnel);

// Get SSH tunnel state
SSHTunnelState ssh_tunnel_get_state(SSHTunnel *tunnel);

// Get error information
int ssh_tunnel_get_error(SSHTunnel *tunnel, char **errmsg);

// Close only SSH channel without closing session and connection
void ssh_tunnel_close_channel_only(SSHTunnel *tunnel);

// Check if SSH session is still valid
int ssh_tunnel_is_session_valid(SSHTunnel *tunnel);

// Reopen SSH channel to new target (using existing session)
int ssh_tunnel_reopen_channel(SSHTunnel *tunnel, const char *dest_host, int dest_port,
                              const char *source_host, int source_port);

#endif // SSH_TUNNEL_H
