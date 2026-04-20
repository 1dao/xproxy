#ifndef SOCKS5_SERVER_H
#define SOCKS5_SERVER_H

#include "socket_util.h"
#include "xpoll.h"
#include <stdint.h>

#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_GSSAPI 0x01
#define SOCKS5_AUTH_PASSWORD 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_NOT_SUPPORTED 0x08

typedef enum {
    SOCKS5_STATE_INIT,
    SOCKS5_STATE_AUTH,
    SOCKS5_STATE_REQUEST,
    SOCKS5_STATE_OPENING,
    SOCKS5_STATE_CONNECTED,
    SOCKS5_STATE_ERROR
} Socks5ClientState;

typedef struct {
    const char* ssh_host;
    uint16_t ssh_port;
    const char* ssh_username;
    const char* ssh_password;
    const char* bind_address;
    uint16_t bind_port;
} Socks5ServerConfig;

/* Start socks5v service */
int socks5_server_start(const Socks5ServerConfig* config);

/* Keepalive for SSH session */
void socks5_server_update();

/* Stop server */
void socks5_server_stop(void);

#endif // SOCKS5_SERVER_H
