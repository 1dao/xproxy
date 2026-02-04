#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "xargs.h"

#include "socket_util.h"
#include "socks5_server.h"

static int g_running = 0;
static pthread_t g_thread;

// Signal handler function
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nReceived interrupt signal, stopping SOCKS5 proxy...\n");
        g_running = 0;
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
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

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

void* socks5_server_thread(void* arg) {
    socks5_server_run();
    return NULL;
}

int main(int argc, char *argv[]) {
    console_set_consolas_font();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGINT, signal_handler);

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

    // Start server thread
    if (pthread_create(&g_thread, NULL, socks5_server_thread, NULL) != 0) {
        fprintf(stderr, "Cannot create server thread\n");
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    g_running = 1;
    printf("SOCKS5 proxy is running...\n");
    printf("Listen address: %s:%d\n", config.bind_address, config.bind_port);
    printf("SSH tunnel: %s:%d (user: %s)\n", config.ssh_host, config.ssh_port, config.ssh_username);
    printf("Press Ctrl+C to stop proxy\n");

    // Main loop waiting for interrupt signal
    while (g_running) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
    }

    // Stop server
    socks5_server_stop();
    pthread_join(g_thread, NULL);

    // Clean up resources
    xargs_cleanup();
    socket_cleanup();

    printf("\nSOCKS5 proxy stopped\n");
    return EXIT_SUCCESS;
}
