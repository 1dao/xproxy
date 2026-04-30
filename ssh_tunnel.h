#ifndef SSH_TUNNEL_V2_H
#define SSH_TUNNEL_V2_H

#include <stddef.h>
#include <stdint.h>
#include "socket_util.h"

/*
 * Compatibility names retained for the existing SOCKS5 code. The
 * implementation now uses libssh2 underneath.
 */
typedef uint32_t word32;
typedef struct WOLFSSH WOLFSSH;
typedef struct WOLFSSH_CHANNEL WOLFSSH_CHANNEL;

typedef int (*WS_CallbackChannelClose)(WOLFSSH_CHANNEL* channel, void* ctx);
typedef int (*WS_CallbackChannelOpen)(WOLFSSH_CHANNEL* channel, void* ctx);

#define WS_SUCCESS 0
#define WS_CHANOPEN_FAILED (-21)
#define WS_INVALID_CHANID (-23)

WOLFSSH* wolfSSH_session_open(const char *host, int port,
                              const char *username, const char *password);
void wolfSSH_session_close(WOLFSSH* session);

void wolfSSH_channel_callback(WOLFSSH* session,
                              WS_CallbackChannelClose fclose,
                              WS_CallbackChannelOpen ffini,
                              WS_CallbackChannelOpen ffail,
                              void* ctx);

WOLFSSH_CHANNEL* wolfSSH_channel_open(WOLFSSH* session,
                                      const char *dest_host, int dest_port,
                                      const char *source_host, int source_port);
void wolfSSH_channel_close(WOLFSSH_CHANNEL* channel);
void wolfSSH_ChannelExit(WOLFSSH_CHANNEL* channel);

int wolfSSH_channel_read(WOLFSSH_CHANNEL *channel, void *buffer, size_t buffer_size);
int wolfSSH_channel_write(WOLFSSH_CHANNEL *channel, const void *buffer, size_t buffer_size);

SOCKET_T wolfSSH_session_get_socket(WOLFSSH* session);
BOOL wolfSSH_session_want_read(WOLFSSH* session);
BOOL wolfSSH_session_want_write(WOLFSSH* session);
int wolfSSH_process_events(WOLFSSH* session, word32* channelId);
int wolfSSH_session_keepalive(WOLFSSH* session);
int wolfSSH_channel_eof(WOLFSSH_CHANNEL *channel);

int wolfSSH_get_error_code(WOLFSSH* session);
int wolfSSH_get_error(WOLFSSH* session);
const char* wolfSSH_get_error_message(WOLFSSH* session);
const char* wolfSSH_ErrorToName(int error);
BOOL wolfSSH_is_temporary_state(WOLFSSH* session);
int wolfSSH_check_fatal(int err_code);

#endif /* SSH_TUNNEL_V2_H */
