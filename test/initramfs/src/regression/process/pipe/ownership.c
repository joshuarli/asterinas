// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static int check_pair(int flags)
{
    int fds[2];
    if ((flags ? pipe2(fds, flags) : pipe(fds))) {
        perror("create pipe");
        return 1;
    }
    int failed = 0;
    struct stat st[2] = {0};
    for (int i = 0; i < 2; i++) {
        if (fstat(fds[i], &st[i])) {
            perror("stat pipe");
            failed = 1;
            continue;
        }
        if (!S_ISFIFO(st[i].st_mode) || (st[i].st_mode & 0777) != 0600 ||
            st[i].st_uid != getuid() || st[i].st_gid != getgid()) {
            fprintf(stderr, "pipe ownership: uid=%u gid=%u mode=%o; expected uid=%u gid=%u mode=600\n",
                st[i].st_uid, st[i].st_gid, st[i].st_mode & 0777, getuid(), getgid());
            failed = 1;
        }
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fds[i]);
        int reopened = open(path, (i ? O_WRONLY : O_RDONLY) | O_NONBLOCK);
        if (reopened < 0) {
            perror("reopen own pipe descriptor");
            failed = 1;
        } else {
            struct stat reopened_stat;
            if (fstat(reopened, &reopened_stat) || reopened_stat.st_ino != st[i].st_ino ||
                reopened_stat.st_dev != st[i].st_dev) failed = 1;
            if (i && write(reopened, "x", 1) != 1) failed = 1;
            if (close(reopened)) failed = 1;
        }
    }
    char byte;
    if (!failed && (read(fds[0], &byte, 1) != 1 || byte != 'x')) failed = 1;
    if (st[0].st_ino != st[1].st_ino || st[0].st_dev != st[1].st_dev) failed = 1;
    if (close(fds[0]) || close(fds[1])) failed = 1;
    return failed;
}

int main(void)
{
    if (getuid() == 0) {
        fputs("pipe ownership regression requires an unprivileged caller\n", stderr);
        return 1;
    }
    umask(0777);
    int failed = check_pair(0) | check_pair(O_NONBLOCK | O_CLOEXEC);
    if (!failed) puts("pipe ownership: both ends retain creator credentials and reopen through procfs");
    return failed;
}
