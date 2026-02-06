#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "xargs.h"

#include "socket_util.h"
#include "xpoll.h"
#include "ssh_tunnel.h"
#include "socks5_server.h"

static int g_running = 0;

// Signal handler function
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nReceived interrupt signal, stopping SOCKS5 proxy...\n");
        g_running = 0;
    } else if (SIGSEGV) {
        printf("Generating dump file...\n");
        raise(SIGABRT);
    }
}

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
void get_hidden_input(const char* prompt, char* buffer, int size) {
    printf("%s", prompt);
    fflush(stdout);

    int pos = 0;

#ifdef _WIN32
    while (1) {
        int ch = _getch();
        if (ch == 13) {
            break;
        } else if (ch == 8) {
            if (pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (pos < size - 1 && ch >= 32 && ch <= 126) {
            buffer[pos++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCS)ANOW, &newt);

    while (1) {
        int ch = getchar();
        if (ch == '\n' || ch == '\r') {
            break;
        } else if (ch == 127 || ch == 8) {
            if (pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (pos < size - 1 && ch >= 32 && ch <= 126) {
            buffer[pos++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    buffer[pos] = '\0';
    printf("\n");
}

void interactive_config(Socks5ServerConfig *config) {
    static char bind_addr[256], ssh_host[256], ssh_user[256], ssh_pass[256];
    char buffer[256];

    printf("Enter SOCKS5 bind address [default: 127.0.0.1]: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    strcpy(bind_addr, buffer[0] ? buffer : "127.0.0.1");
    config->bind_address = bind_addr;

    printf("Enter SOCKS5 bind port [default: 1180]: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    config->bind_port = buffer[0] ? atoi(buffer) : 1180;

    printf("Enter SSH server address: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    strcpy(ssh_host, buffer);
    config->ssh_host = ssh_host;

    printf("Enter SSH port [default: 22]: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    config->ssh_port = buffer[0] ? atoi(buffer) : 22;

    printf("Enter SSH username: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    strcpy(ssh_user, buffer);
    config->ssh_username = ssh_user;

    get_hidden_input("Enter SSH password: ", ssh_pass, sizeof(ssh_pass));
    config->ssh_password = ssh_pass;
}

void show_help(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h, --host SSH server address\n");
    printf("  -p, --port SSH port (default: 22)\n");
    printf("  -u, --user SSH username\n");
    printf("  -P, --pass SSH password\n");
    printf("  -b, --bind SOCKS5 bind address (default: 127.0.0.1)\n");
    printf("  -l, --listen SOCKS5 listen port (default: 1180)\n");
    printf("  --help Show this help message\n");
    printf("\nIf no arguments provided, will enter interactive mode for configuration.\n");
}

int main(int argc, char *argv[]) {
    console_set_consolas_font();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGINT, signal_handler);
    signal(SIGSEGV, signal_handler);

    static char bind_addr[256], ssh_host[256], ssh_user[256], ssh_pass[256];
    strcpy(bind_addr, "127.0.0.1");
    strcpy(ssh_host, "");
    strcpy(ssh_user, "");
    strcpy(ssh_pass, "");

    xArgsCFG configs[] = {
        {'h', "host", ssh_host, 0},
        {'p', "port", "22", 0},
        {'u', "user", ssh_user, 0},
        {'P', "pass", ssh_pass, 0},
        {'b', "bind", "127.0.0.1", 0},
        {'l', "listen", "1180", 0}
    };

    xargs_init(configs, 6, argc, argv);

    if (xargs_get("help") || xargs_get("?")) {
        show_help(argv[0]);
        xargs_cleanup();
        return EXIT_SUCCESS;
    }

    strcpy(bind_addr, xargs_get("b"));
    strcpy(ssh_host, xargs_get("h"));
    strcpy(ssh_user, xargs_get("u"));
    strcpy(ssh_pass, xargs_get("P"));

    int has_args = strlen(ssh_host) > 0;

    if (has_args && strlen(ssh_host) == 0) {
        fprintf(stderr, "Error: SSH server address is required\n");
        show_help(argv[0]);
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    if (!has_args) {
        printf("Entering interactive configuration mode\n\n");
        Socks5ServerConfig config = {
            .bind_address = bind_addr,
            .bind_port = 1180,
            .ssh_host = ssh_host,
            .ssh_port = 22,
            .ssh_username = ssh_user,
            .ssh_password = ssh_pass
        };
        interactive_config(&config);

        if (strlen(config.ssh_host) == 0) {
            fprintf(stderr, "Error: SSH server address cannot be empty\n");
            xargs_cleanup();
            return EXIT_FAILURE;
        }
    }

    Socks5ServerConfig config = {
        .bind_address = bind_addr,
        .bind_port = atoi(xargs_get("l")),
        .ssh_host = ssh_host,
        .ssh_port = atoi(xargs_get("p")),
        .ssh_username = ssh_user,
        .ssh_password = ssh_pass
    };

    if (socket_init() != 0) {
        fprintf(stderr, "Socket library initialization failed\n");
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Initialize server
    if (socks5_server_init(&config) != 0) {
        fprintf(stderr, "SOCKS5 server initialization failed\n");
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Create global xpoll instance
    xPollState *xpoll = xpoll_create();
    if (!    xpoll) {
        fprintf(stderr, "Failed to create xpoll loop\n");
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Set xpoll instance to socks5_server
    socks5_server_set_xpoll(xpoll);

    // Create listening socket
    SOCKET_T listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        perror("socket creation failed");
        xpoll_free(xpoll);
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Set SO_REUSEADDR
    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        CLOSE_SOCKET(listen_sock);
        xpoll_free(xpoll);
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Bind address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = config.bind_address ?
        inet_addr(config.bind_address) : INADDR_ANY;
    server_addr.sin_port = htons(config.bind_port);

    if (bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        CLOSE_SOCKET(listen_sock);
        xpoll_free(xpoll);
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Listen
    if (listen(listen_sock, SOMAXCONN) < 0) {
        perror("listen failed");
        CLOSE_SOCKET(listen_sock);
        xpoll_free(xpoll);
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Create shared SSH session (shared by all clients)
    printf("Creating shared SSH session to %s:%d...\n", config.ssh_host, config.ssh_port);
    LIBSSH2_SESSION *shared_ssh_session = ssh_tunnel_session_open(
        config.ssh_host,
        config.ssh_port,
        config.ssh_username,
        config.ssh_password);

    if (!shared_ssh_session) {
        fprintf(stderr, "Failed to create shared SSH session\n");
        CLOSE_SOCKET(listen_sock);
        xpoll_free(xpoll);
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }
    printf("Shared SSH session created successfully\n");

    // Set shared SSH session to socks5_server
    socks5_server_set_shared_session(shared_ssh_session);

    printf("SOCKS5 proxy is running (single-threaded event loop mode)...\n");
    printf("Listen address: %s:%d\n", config.bind_address, config.bind_port);
    printf("SSH tunnel: %s:%d (user: %s)\n", config.ssh_host, config.ssh_port, config.ssh_username);
    printf("Using %s for I/O multiplexing\n", xpoll_name());
    printf("Press Ctrl+C to stop proxy\n");

    // Register readable event for listening socket
    if (xpoll_add_event(xpoll, listen_sock, XPOLL_READABLE,
                         socks5_server_get_accept_cb(), NULL, NULL, NULL) != 0) {
        fprintf(stderr, "Failed to register listen socket event\n");
        ssh_tunnel_session_close(shared_ssh_session);
        CLOSE_SOCKET(listen_sock);
        xpoll_free(xpoll);
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    g_running = 1;

    // Main event loop
    while (g_running) {
        int ret = xpoll_poll(xpoll, 1000);  // 1 second timeout
        if (ret < 0) {
            fprintf(stderr, "xpoll_poll error: %d\n", WSAGetLastError());
            break;
        }
        socks5_server_update();
    }

    // Cleanup
    socks5_server_stop();

    printf("Cleaning up...\n");
    xpoll_del_event(xpoll, listen_sock, XPOLL_READABLE);

    // Close shared SSH session
    printf("Closing shared SSH session...\n");
    ssh_tunnel_session_close(shared_ssh_session);

    CLOSE_SOCKET(listen_sock);
    xpoll_free(xpoll);

    xargs_cleanup();
    socket_cleanup();

    printf("\nSOCKS5 proxy stopped\n");
    return EXIT_SUCCESS;
}
