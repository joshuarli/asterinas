// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &set, NULL)) return 1;
    int fd = signalfd(-1, &set, SFD_CLOEXEC);
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (fd < 0 || master < 0 || grantpt(master) || unlockpt(master)) return 1;
    char *name = ptsname(master);
    if (!name) return 1;
    int slave = open(name, O_RDWR | O_NOCTTY);
    if (slave < 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0)) _exit(2);
        close(master);
        close(slave);
        _exit(0);
    }
    close(slave);
    struct pollfd p = { .fd = fd, .events = POLLIN };
    int ready = poll(&p, 1, 3000);
    struct signalfd_siginfo info = {0};
    ssize_t n = ready == 1 ? read(fd, &info, sizeof(info)) : -1;
    int status = 0;
    if (ready != 1) kill(child, SIGKILL);
    if (waitpid(child, &status, 0) != child) return 1;
    close(master);
    close(fd);
    if (ready != 1 || n != sizeof(info) || info.ssi_signo != SIGCHLD ||
        info.ssi_code != CLD_EXITED || info.ssi_pid != (unsigned)child ||
        info.ssi_uid != getuid() || info.ssi_status != 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status)) {
        fprintf(stderr, "ready=%d code=%d pid=%u expected=%d uid=%u status=%d wait=%#x\n",
                ready, info.ssi_code, info.ssi_pid, child, info.ssi_uid, info.ssi_status, status);
        return 1;
    }
    puts("session exit signal PASS");
    return 0;
}
