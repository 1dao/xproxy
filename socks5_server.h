#ifndef SOCKS5_SERVER_H
#define SOCKS5_SERVER_H

#include "xsock.h"
#include "xpoll.h"
#include <stdint.h>

typedef struct {
    const char* ssh_host;
    uint16_t ssh_port;
    const char* ssh_username;
    const char* ssh_password;
    const char* bind_address;
    uint16_t bind_port;
    const char* proxy_username; /* optional SOCKS5 auth user (RFC1929) */
    const char* proxy_password; /* optional SOCKS5 auth pass (RFC1929) */
} Socks5ServerConfig;

/* Start socks5v service */
int socks5_server_start(const Socks5ServerConfig* config);

/* Keepalive for SSH session */
void socks5_server_update();

/* Stop server */
void socks5_server_stop(void);

#endif // SOCKS5_SERVER_H
