#include "ssh_tunnel.h"

#include <libssh2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct WOLFSSH {
    LIBSSH2_SESSION *session;
    SOCKET_T sock;
    int last_error;
    char last_error_text[128];
    WS_CallbackChannelClose channel_close_cb;
    WS_CallbackChannelOpen channel_open_cb;
    WS_CallbackChannelOpen channel_open_fail_cb;
    void *channel_cb_ctx;
};

struct WOLFSSH_CHANNEL {
    LIBSSH2_CHANNEL *channel;
    WOLFSSH *ssh;
    int eof;
};

static int g_libssh2_initialized = 0;

static int ssh_set_error(WOLFSSH *ssh, int error)
{
    if (ssh) {
        ssh->last_error = error;
        if (error == 0)
            ssh->last_error_text[0] = '\0';
    }
    return error;
}

static int ssh_last_error(WOLFSSH *ssh)
{
    int error = 0;
    char *errmsg = NULL;
    int errmsg_len = 0;

    if (!ssh || !ssh->session)
        return -1;

    error = libssh2_session_last_errno(ssh->session);
    ssh->last_error = error;
    if (libssh2_session_last_error(ssh->session, &errmsg, &errmsg_len, 0) == 0 &&
        errmsg && errmsg_len > 0) {
        size_t copy_len = (size_t)errmsg_len;
        if (copy_len >= sizeof(ssh->last_error_text))
            copy_len = sizeof(ssh->last_error_text) - 1;
        memcpy(ssh->last_error_text, errmsg, copy_len);
        ssh->last_error_text[copy_len] = '\0';
    } else {
        ssh->last_error_text[0] = '\0';
    }
    return error;
}

static int connect_tcp(const char *host, int port, SOCKET_T *out_sock)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;
    char portstr[16];
    int rc;

    if (!host || !out_sock)
        return -1;

    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, portstr, &hints, &result);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo failed for %s:%d\n", host, port);
        return -1;
    }

    for (rp = result; rp; rp = rp->ai_next) {
        SOCKET_T sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET)
            continue;

        if (connect(sock, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
            *out_sock = sock;
            freeaddrinfo(result);
            return 0;
        }

        CLOSE_SOCKET(sock);
    }

    freeaddrinfo(result);
    return -1;
}

WOLFSSH* wolfSSH_session_open(const char *host, int port,
                              const char *username, const char *password)
{
    WOLFSSH *ssh = NULL;
    LIBSSH2_SESSION *session = NULL;
    SOCKET_T sock = INVALID_SOCKET;
    int rc;

    if (!host || !username || !password) {
        fprintf(stderr, "wolfSSH_session_open: invalid arguments\n");
        return NULL;
    }

    if (!g_libssh2_initialized) {
        rc = libssh2_init(0);
        if (rc != 0) {
            fprintf(stderr, "libssh2_init failed: %d\n", rc);
            return NULL;
        }
        g_libssh2_initialized = 1;
    }

    if (connect_tcp(host, port, &sock) != 0) {
        fprintf(stderr, "SSH TCP connect failed: host=%s, port=%d\n", host, port);
        return NULL;
    }

    session = libssh2_session_init();
    if (!session) {
        fprintf(stderr, "libssh2_session_init failed\n");
        CLOSE_SOCKET(sock);
        return NULL;
    }

    libssh2_session_set_blocking(session, 1);

    rc = libssh2_session_handshake(session, (libssh2_socket_t)sock);
    if (rc != 0) {
        fprintf(stderr, "libssh2_session_handshake failed: %d\n", rc);
        libssh2_session_free(session);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    rc = libssh2_userauth_password(session, username, password);
    if (rc != 0) {
        char *errmsg = NULL;
        int errmsg_len = 0;
        libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
        fprintf(stderr, "libssh2_userauth_password failed: %d %.*s\n",
                rc, errmsg_len, errmsg ? errmsg : "");
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    if (socket_set_nonblocking(sock) != 0) {
        fprintf(stderr, "failed to set SSH socket nonblocking\n");
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    libssh2_session_set_blocking(session, 0);
    libssh2_keepalive_config(session, 1, 15);

    ssh = (WOLFSSH*)calloc(1, sizeof(WOLFSSH));
    if (!ssh) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    ssh->session = session;
    ssh->sock = sock;
    ssh->last_error = 0;
    return ssh;
}

void wolfSSH_session_close(WOLFSSH* ssh)
{
    if (!ssh)
        return;

    if (ssh->session) {
        libssh2_session_disconnect(ssh->session, "Normal Shutdown");
        libssh2_session_free(ssh->session);
        ssh->session = NULL;
    }

    if (ssh->sock != INVALID_SOCKET) {
        CLOSE_SOCKET(ssh->sock);
        ssh->sock = INVALID_SOCKET;
    }

    free(ssh);

    if (g_libssh2_initialized) {
        libssh2_exit();
        g_libssh2_initialized = 0;
    }
}

void wolfSSH_channel_callback(WOLFSSH* session,
                              WS_CallbackChannelClose fclose,
                              WS_CallbackChannelOpen ffini,
                              WS_CallbackChannelOpen ffail,
                              void* ctx)
{
    if (!session)
        return;

    session->channel_close_cb = fclose;
    session->channel_open_cb = ffini;
    session->channel_open_fail_cb = ffail;
    session->channel_cb_ctx = ctx;
}

WOLFSSH_CHANNEL* wolfSSH_channel_open(WOLFSSH* ssh,
                                      const char *dest_host, int dest_port,
                                      const char *source_host, int source_port)
{
    LIBSSH2_CHANNEL *channel = NULL;
    WOLFSSH_CHANNEL *wrapped = NULL;
    int error;

    if (!ssh || !ssh->session || !dest_host)
        return NULL;

    if (!source_host)
        source_host = "127.0.0.1";
    if (source_port == 0)
        source_port = 12345;

    channel = libssh2_channel_direct_tcpip_ex(ssh->session,
                                             dest_host, dest_port,
                                             source_host, source_port);
    if (!channel) {
        error = ssh_last_error(ssh);
        if (error != LIBSSH2_ERROR_EAGAIN) {
            fprintf(stderr, "libssh2 channel open failed to %s:%d: %d %s\n",
                    dest_host, dest_port, error, wolfSSH_get_error_message(ssh));
        }
        return NULL;
    }

    wrapped = (WOLFSSH_CHANNEL*)calloc(1, sizeof(WOLFSSH_CHANNEL));
    if (!wrapped) {
        libssh2_channel_free(channel);
        ssh_set_error(ssh, LIBSSH2_ERROR_ALLOC);
        return NULL;
    }

    wrapped->channel = channel;
    wrapped->ssh = ssh;
    wrapped->eof = 0;
    ssh_set_error(ssh, 0);

    fprintf(stderr, "SSH channel opened successfully to %s:%d, address=%p\n",
            dest_host, dest_port, (void*)wrapped);
    return wrapped;
}

void wolfSSH_channel_close(WOLFSSH_CHANNEL* channel)
{
    WOLFSSH *ssh;

    if (!channel)
        return;

    ssh = channel->ssh;
    if (channel->channel) {
        libssh2_channel_close(channel->channel);
        libssh2_channel_free(channel->channel);
        channel->channel = NULL;
    }

    if (ssh && ssh->channel_close_cb)
        ssh->channel_close_cb(channel, ssh->channel_cb_ctx);

    fprintf(stderr, "SSH channel closed, address=%p\n", (void*)channel);
    free(channel);
}

void wolfSSH_ChannelExit(WOLFSSH_CHANNEL* channel)
{
    wolfSSH_channel_close(channel);
}

int wolfSSH_channel_read(WOLFSSH_CHANNEL *channel, void *buffer, size_t buffer_size)
{
    ssize_t rc;
    WOLFSSH *ssh;

    if (!channel || !channel->channel || !buffer || buffer_size == 0)
        return -1;

    ssh = channel->ssh;
    rc = libssh2_channel_read(channel->channel, (char*)buffer, buffer_size);
    if (rc > 0) {
        if (ssh)
            ssh->last_error = 0;
        return (int)rc;
    }

    if (rc == LIBSSH2_ERROR_EAGAIN) {
        if (ssh)
            ssh->last_error = LIBSSH2_ERROR_EAGAIN;
        return 0;
    }

    if (rc == 0) {
        if (libssh2_channel_eof(channel->channel))
            channel->eof = 1;
        if (ssh)
            ssh->last_error = 0;
        return 0;
    }

    if (ssh)
        ssh->last_error = (int)rc;
    return -1;
}

int wolfSSH_channel_write(WOLFSSH_CHANNEL *channel, const void *buffer, size_t buffer_size)
{
    ssize_t rc;
    WOLFSSH *ssh;

    if (!channel || !channel->channel || !buffer || buffer_size == 0)
        return -1;

    ssh = channel->ssh;
    rc = libssh2_channel_write(channel->channel, (const char*)buffer, buffer_size);
    if (rc >= 0) {
        if (ssh)
            ssh->last_error = 0;
        return (int)rc;
    }

    if (rc == LIBSSH2_ERROR_EAGAIN) {
        if (ssh)
            ssh->last_error = LIBSSH2_ERROR_EAGAIN;
        return 0;
    }

    if (ssh)
        ssh->last_error = (int)rc;
    return (int)rc;
}

SOCKET_T wolfSSH_session_get_socket(WOLFSSH* ssh)
{
    if (!ssh)
        return INVALID_SOCKET;
    return ssh->sock;
}

BOOL wolfSSH_session_want_read(WOLFSSH* ssh)
{
    if (!ssh || !ssh->session)
        return FALSE;
    return (libssh2_session_block_directions(ssh->session) &
            LIBSSH2_SESSION_BLOCK_INBOUND) != 0;
}

BOOL wolfSSH_session_want_write(WOLFSSH* ssh)
{
    if (!ssh || !ssh->session)
        return FALSE;
    return (libssh2_session_block_directions(ssh->session) &
            LIBSSH2_SESSION_BLOCK_OUTBOUND) != 0;
}

int wolfSSH_process_events(WOLFSSH* ssh, word32* channelId)
{
    (void)ssh;
    if (channelId)
        *channelId = 0;
    return 0;
}

int wolfSSH_session_keepalive(WOLFSSH* session)
{
    int seconds_to_next = 0;
    int rc;

    if (!session || !session->session)
        return -1;

    rc = libssh2_keepalive_send(session->session, &seconds_to_next);
    if (rc == LIBSSH2_ERROR_EAGAIN) {
        session->last_error = rc;
        return 0;
    }
    session->last_error = rc;
    return rc;
}

int wolfSSH_channel_eof(WOLFSSH_CHANNEL *channel)
{
    if (!channel || !channel->channel)
        return 1;

    if (channel->eof)
        return 1;

    channel->eof = libssh2_channel_eof(channel->channel) ? 1 : 0;
    return channel->eof;
}

int wolfSSH_get_error_code(WOLFSSH* ssh)
{
    if (!ssh)
        return -1;
    return ssh->last_error;
}

int wolfSSH_get_error(WOLFSSH* ssh)
{
    return wolfSSH_get_error_code(ssh);
}

const char* wolfSSH_get_error_message(WOLFSSH* ssh)
{
    if (!ssh || ssh->last_error_text[0] == '\0')
        return "";
    return ssh->last_error_text;
}

BOOL wolfSSH_is_temporary_state(WOLFSSH* ssh)
{
    return ssh && ssh->last_error == LIBSSH2_ERROR_EAGAIN;
}

int wolfSSH_check_fatal(int err_code)
{
    switch (err_code) {
        case 0:
        case LIBSSH2_ERROR_EAGAIN:
        case LIBSSH2_ERROR_CHANNEL_FAILURE:
        case LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED:
        case LIBSSH2_ERROR_CHANNEL_UNKNOWN:
        case LIBSSH2_ERROR_CHANNEL_WINDOW_FULL:
            return 0;
        default:
            return 1;
    }
}

const char* wolfSSH_ErrorToName(int error)
{
    switch (error) {
        case 0:
            return "LIBSSH2_OK";
        case LIBSSH2_ERROR_EAGAIN:
            return "LIBSSH2_ERROR_EAGAIN";
        case LIBSSH2_ERROR_SOCKET_NONE:
            return "LIBSSH2_ERROR_SOCKET_NONE";
        case LIBSSH2_ERROR_SOCKET_SEND:
            return "LIBSSH2_ERROR_SOCKET_SEND";
        case LIBSSH2_ERROR_SOCKET_RECV:
            return "LIBSSH2_ERROR_SOCKET_RECV";
        case LIBSSH2_ERROR_SOCKET_DISCONNECT:
            return "LIBSSH2_ERROR_SOCKET_DISCONNECT";
        case LIBSSH2_ERROR_KEX_FAILURE:
            return "LIBSSH2_ERROR_KEX_FAILURE";
        case LIBSSH2_ERROR_HOSTKEY_INIT:
            return "LIBSSH2_ERROR_HOSTKEY_INIT";
        case LIBSSH2_ERROR_AUTHENTICATION_FAILED:
            return "LIBSSH2_ERROR_AUTHENTICATION_FAILED";
        case LIBSSH2_ERROR_CHANNEL_FAILURE:
            return "LIBSSH2_ERROR_CHANNEL_FAILURE";
        case LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED:
            return "LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED";
        case LIBSSH2_ERROR_CHANNEL_UNKNOWN:
            return "LIBSSH2_ERROR_CHANNEL_UNKNOWN";
        case LIBSSH2_ERROR_CHANNEL_CLOSED:
            return "LIBSSH2_ERROR_CHANNEL_CLOSED";
        case LIBSSH2_ERROR_CHANNEL_EOF_SENT:
            return "LIBSSH2_ERROR_CHANNEL_EOF_SENT";
        case LIBSSH2_ERROR_CHANNEL_WINDOW_FULL:
            return "LIBSSH2_ERROR_CHANNEL_WINDOW_FULL";
        case LIBSSH2_ERROR_ALLOC:
            return "LIBSSH2_ERROR_ALLOC";
        default:
            return "LIBSSH2_ERROR_UNKNOWN";
    }
}
