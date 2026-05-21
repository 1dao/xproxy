#include "xdaemon.h"

#if defined(__linux__) && !defined(__ANDROID__)
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int xdaemon_is_supported(void) {
    return 1;
}

int xdaemon_daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0) {
        _exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        return -1;
    }

#ifdef SIGHUP
    signal(SIGHUP, SIG_IGN);
#endif

    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0) {
        _exit(EXIT_SUCCESS);
    }

    int dev_null = open("/dev/null", O_RDWR);
    if (dev_null < 0) {
        return -1;
    }

    if (dup2(dev_null, STDIN_FILENO) < 0 ||
        dup2(dev_null, STDOUT_FILENO) < 0 ||
        dup2(dev_null, STDERR_FILENO) < 0) {
        close(dev_null);
        return -1;
    }

    if (dev_null > STDERR_FILENO) {
        close(dev_null);
    }

    return 0;
}

#else

int xdaemon_is_supported(void) {
    return 0;
}

int xdaemon_daemonize(void) {
    return -1;
}

#endif
