#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "xpac_server.h"
#include "xargs.h"
#include "xpoll.h"
#include "xlog.h"
#include "socks5_server.h"
#include "https_proxy.h"
#include "xpac_server.h"

int g_running = 0;

// Signal handler function
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nReceived interrupt signal, stopping proxy servers...\n");
        g_running = 0;
    } else if (sig == SIGSEGV) {
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

    printf("Enter SOCKS5 bind port [default: 1080]: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    config->bind_port = buffer[0] ? atoi(buffer) : 1080;

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
    printf("\nSOCKS5 Server Options:\n");
    printf("Options:\n");
    printf("  -h, --host <address>   SSH server address\n");
    printf("  -p, --port <port>      SSH port (default: 22)\n");
    printf("  -u, --user <username>   SSH username\n");
    printf("  -P, --pass <password>   SSH password\n");
    printf("  -b, --bind <address>   SOCKS5/HTTP proxy bind address (default: 127.0.0.1)\n");
    printf("  -l, --listen <port>    SOCKS5/HTTP proxy listen port (default: 1080)\n");
    printf("  -t, --http_port <port>  HTTP proxy listen port (default: 7890)\n");
    printf("  --disable-http          Disable HTTP/HTTPS proxy (default: enabled)\n");
    printf("  --max-http-conns <num>  Max HTTP proxy connections (default: 1024)\n");
    printf("  --pac-file <path>       PAC configuration file (default: pac_config.txt)\n");
    printf("\nGeneral Options:\n");
    printf("  --help                  Show this help message\n");
    printf("\nIf no SSH arguments provided, will run HTTP proxy only.\n");
    printf("If SSH arguments provided, will run both SOCKS5 and HTTP proxy servers.\n");
    printf("\nExamples:\n");
    printf("  # Run SOCKS5 server with HTTP proxy (default)\n");
    printf("  %s -h ssh.example.com -u user -P pass\n", prog_name);
    printf("\n  # Run SOCKS5 server only\n");
    printf("  %s -h ssh.example.com -u user -P pass --disable-http\n", prog_name);
    printf("\n  # Run only HTTP proxy (no SSH, forwards to local SOCKS5 on 1080)\n");
    printf("  %s -l 1080 -t 7890\n", prog_name);
    printf("\n  # Run HTTP proxy with custom SOCKS5 backend\n");
    printf("  %s -l 1080 -t 7890 -b 192.168.1.100\n", prog_name);
}

#ifdef __ANDROID__
int xproxy_main(int argc, char *argv[]) {
#else
int main(int argc, char *argv[]) {
#endif
    XLOGI("[VPN] xproxy_main prepare to start with argc=%d", argc);

    console_set_consolas_font();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGINT, signal_handler);
    signal(SIGSEGV, signal_handler);

    // Configuration variables
    static char bind_addr[256], ssh_host[256], ssh_user[256], ssh_pass[256];
    static char http_port_str[16];
    static char max_http_conns_str[16], pac_file[256];

    strcpy(bind_addr, "127.0.0.1");
    strcpy(ssh_host, "");
    strcpy(ssh_user, "");
    strcpy(ssh_pass, "");
    strcpy(http_port_str, "7890");
    strcpy(max_http_conns_str, "1024");
    strcpy(pac_file, "pac_config.txt");

    xArgsCFG configs[] = {
        // Common options
        {'h', "host", ssh_host, 0},
        {'p', "port", "22", 0},
        {'u', "user", ssh_user, 0},
        {'P', "pass", ssh_pass, 0},
        {'b', "bind", "127.0.0.1", 0},
        {'l', "listen", "1080", 0},
        // HTTP proxy options
        {'t', "http_port", http_port_str, 0},
        {0, "disable-http", NULL, 1},
        {0, "max-http-conns", max_http_conns_str, 0},
        {0, "pac-file", pac_file, 0}
    };

    xargs_init(configs, sizeof(configs)/sizeof(configs[0]), argc, argv);

    if (xargs_get("help") || xargs_get("?")) {
        show_help(argv[0]);
        xargs_cleanup();
        return EXIT_SUCCESS;
    }

    // Parse common configuration
    strcpy(bind_addr, xargs_get("b"));
    strcpy(ssh_host, xargs_get("h"));
    strcpy(ssh_user, xargs_get("u"));
    strcpy(ssh_pass, xargs_get("P"));

    int has_ssh_args = strlen(ssh_host) > 0;
    int disable_http = (xargs_get("disable-http") != NULL);
    int enable_http = !disable_http;  // HTTP is enabled by default

    // Interactive mode for SOCKS5 server if no SSH args provided
    if (!has_ssh_args && enable_http) {
        XLOGE("No SSH arguments provided, running HTTP proxy only...");
    } else if (!has_ssh_args && !enable_http) {
        XLOGE("Error: No SSH arguments provided and HTTP proxy is disabled");
        show_help(argv[0]);
        xargs_cleanup();
        return EXIT_FAILURE;
    } else if (has_ssh_args) {
        // Check if we need to enter interactive mode
        if (strlen(ssh_user) == 0) {
            printf("Entering interactive configuration mode for SOCKS5 server\n\n");
            Socks5ServerConfig config = {
                .bind_address = bind_addr[0] ? bind_addr : "127.0.0.1",
                .bind_port = atoi(xargs_get("l")),
                .ssh_host = ssh_host,
                .ssh_port = atoi(xargs_get("p")),
                .ssh_username = ssh_user,
                .ssh_password = ssh_pass
            };
            interactive_config(&config);

            if (strlen(config.ssh_host) == 0) {
                XLOGE("Error: SSH server address cannot be empty");
                xargs_cleanup();
                return EXIT_FAILURE;
            }

            strcpy(ssh_host, config.ssh_host);
        }
    }

    // Initialize socket library
    if (socket_init() != 0) {
        XLOGE("Socket library initialization failed");
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    // Create global xpoll instance
    xPollState *xpoll = xpoll_create();
    if (!xpoll) {
        XLOGE("Failed to create xpoll loop");
        socket_cleanup();
        xargs_cleanup();
        return EXIT_FAILURE;
    }

    int socks5_started = 0;
    int http_proxy_started = 0;

    // Start SOCKS5 server if SSH host is provided
    if (has_ssh_args) {
        Socks5ServerConfig socks5_config = {
            .bind_address = bind_addr,
            .bind_port = atoi(xargs_get("l")),
            .ssh_host = ssh_host,
            .ssh_port = atoi(xargs_get("p")),
            .ssh_username = ssh_user,
            .ssh_password = ssh_pass
        };

        printf("\n========================================\n");
        printf("  SOCKS5 Proxy Server (SSH Tunnel)\n");
        printf("========================================\n");
        printf("Bind Address: %s\n", socks5_config.bind_address);
        printf("Bind Port:    %d\n", socks5_config.bind_port);
        printf("SSH Server:   %s:%d\n", socks5_config.ssh_host, socks5_config.ssh_port);
        printf("SSH Username: %s\n", socks5_config.ssh_username);
        printf("========================================\n\n");

        if (socks5_server_start(&socks5_config, xpoll) != 0) {
            XLOGE("Failed to start SOCKS5 server\n");
            xpoll_free(xpoll);
            socket_cleanup();
            xargs_cleanup();
            return EXIT_FAILURE;
        }
        socks5_started = 1;
    }

    // Start HTTP/HTTPS proxy if enabled
    if (enable_http) {
        int http_port = atoi(http_port_str);
        int socks5_port = atoi(xargs_get("l"));

        HttpProxyConfig http_config = {
            .listen_port = http_port,
            .socks5_server_port = socks5_port,
            .max_conns = atoi(max_http_conns_str)
        };

        strncpy(http_config.socks5_server_ip, bind_addr, sizeof(http_config.socks5_server_ip) - 1);
        http_config.socks5_server_ip[sizeof(http_config.socks5_server_ip) - 1] = '\0';

        XLOGI("\n========================================");
        XLOGI("  HTTP/HTTPS to SOCKS5 Proxy");
        XLOGI("========================================");
        XLOGI("HTTP Proxy Port:    %d", http_config.listen_port);
        XLOGI("SOCKS5 Backend:     %s:%d",
               http_config.socks5_server_ip,
               http_config.socks5_server_port);
        XLOGI("Max Connections:    %d", http_config.max_conns);
        XLOGI("========================================");

        if (https_proxy_start(&http_config, xpoll) != 0) {
            XLOGE("Failed to start HTTP/HTTPS proxy");
            if (socks5_started) {
                socks5_server_stop();
            }
            xpoll_free(xpoll);
            socket_cleanup();
            xargs_cleanup();
            return EXIT_FAILURE;
        }
        http_proxy_started = 1;

        // Initialize PAC server
        // 使用 xargs_get 获取实际的 pac-file 参数值（可能来自命令行）
        const char* pac_file_path = xargs_get("pac-file");
        if (!pac_file_path || strlen(pac_file_path) == 0) {
            pac_file_path = pac_file;  // 回退到默认值
        }
        XpacConfig pac_config = {
            .http_proxy_port = http_config.listen_port,
            .socks5_proxy_port = http_config.socks5_server_port,
            .config_file = pac_file_path,
            .enable_web_admin = 1,
            .admin_password = NULL
        };
        xpac_init(&pac_config);

        XLOGI("\nPAC Files:");
        XLOGI("  http://127.0.0.1:%d/proxy.pac", http_config.listen_port);
        XLOGI("  http://127.0.0.1:%d/proxy.socks5.pac", http_config.listen_port);
        XLOGI("  http://127.0.0.1:%d/proxy.http.pac", http_config.listen_port);
        XLOGI("\nWeb Admin Interface:");
        XLOGI("  http://127.0.0.1:%d/admin", http_config.listen_port);
        XLOGI("\n");
    }

    printf("Press Ctrl+C to stop\n");
    printf("========================================\n\n");

    g_running = 1;

    // Main event loop
    while (g_running) {
        int ret = xpoll_poll(xpoll, 100);  // 100 ms timeout
        if (ret < 0) {
#ifdef _WIN32
            fprintf(stderr, "xpoll_poll error: %d\n", WSAGetLastError());
#else
            fprintf(stderr, "xpoll_poll error\n");
#endif
            break;
        }

        if (socks5_started) {
            socks5_server_update();
        }
        if (http_proxy_started) {
            https_proxy_update();
        }
    }

    // Cleanup
    printf("\nCleaning up...\n");

    if (socks5_started) {
        socks5_server_stop();
    }

    if (http_proxy_started) {
        https_proxy_stop();
        xpac_uninit();
    }

    xpoll_free(xpoll);
    xargs_cleanup();
    socket_cleanup();

    if (socks5_started || http_proxy_started) {
        printf("\nProxy servers stopped\n");
    }

    return EXIT_SUCCESS;
}
