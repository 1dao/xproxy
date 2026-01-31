#ifndef SOCKS5_SERVER_H
#define SOCKS5_SERVER_H

#include "socket_util.h"
#include <stdint.h>
#include "ssh_tunnel.h"

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

typedef struct {
    const char* ssh_host;
    uint16_t ssh_port;
    const char* ssh_username;
    const char* ssh_password;
    const char* bind_address;
    uint16_t bind_port;
} Socks5ServerConfig;

typedef enum {
    SOCKS5_STATE_INIT,
    SOCKS5_STATE_AUTH,
    SOCKS5_STATE_REQUEST,
    SOCKS5_STATE_CONNECTED,
    SOCKS5_STATE_ERROR
} Socks5ClientState;

typedef struct {
    SOCKET_T client_sock;
    SOCKET_T remote_sock;
    Socks5ClientState state;
    uint8_t auth_method;
    char target_host[256];
    uint16_t target_port;
    uint8_t cmd;
    SSHTunnel *ssh_tunnel;
    char client_host[256];
    uint16_t client_port;
} Socks5Client;

int socks5_server_init(const Socks5ServerConfig* config);
int socks5_server_run(void);
void socks5_server_stop(void);
int socks5_handle_client(SOCKET_T client_sock, struct sockaddr_in* client_addr);
int socks5_handle_handshake(Socks5Client* client);
int socks5_handle_auth(Socks5Client* client);
int socks5_handle_request(Socks5Client* client);
int socks5_establish_ssh_tunnel(Socks5Client* client, const Socks5ServerConfig* config);
void socks5_send_reply(Socks5Client* client, uint8_t rep);
void socks5_client_free(Socks5Client* client);

#endif
