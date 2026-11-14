// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define DIR "/tmp/umount_busy_test"
#define CHILD DIR "/child"
#define FILEPATH DIR "/file"

static void check(int ok, const char *what)
{
    if (!ok) { perror(what); exit(1); }
}

static int mounted(const char *path)
{
    FILE *f = fopen("/proc/self/mountinfo", "r");
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    check(f != NULL, "mountinfo");
    while (getline(&line, &cap, f) >= 0) {
        char *save, *field = strtok_r(line, " ", &save);
        for (int i = 1; field && i < 5; i++) field = strtok_r(NULL, " ", &save);
        if (field && strcmp(field, path) == 0) { found = 1; break; }
    }
    free(line);
    fclose(f);
    return found;
}

static void busy(void)
{
    errno = 0;
    check(umount(DIR) == -1 && errno == EBUSY, "expected EBUSY");
    check(mounted(DIR), "busy mount disappeared");
}

static void exercise(const char *source, const char *type)
{
    char buf[8] = {0};
    check(mount(source, DIR, type, 0, NULL) == 0, "mount");
    int fd = open(FILEPATH, O_CREAT | O_RDWR | O_TRUNC, 0600);
    check(fd >= 0, "open");
    busy();
    check(close(fd) == 0, "close");
    check(chdir(DIR) == 0, "chdir");
    busy();
    check(chdir("/") == 0, "chdir /");
    check(mkdir(CHILD, 0700) == 0 || errno == EEXIST, "mkdir child");
    check(mount("tmpfs", CHILD, "tmpfs", 0, NULL) == 0, "mount child");
    busy();
    check(umount(CHILD) == 0, "umount child");
    fd = open(FILEPATH, O_RDWR);
    check(fd >= 0, "reopen");
    check(umount2(DIR, MNT_DETACH) == 0, "detach");
    check(!mounted(DIR), "detached mount visible");
    check(write(fd, "payload", 7) == 7, "write detached");
    check(lseek(fd, 0, SEEK_SET) == 0, "seek detached");
    check(read(fd, buf, 7) == 7 && !memcmp(buf, "payload", 7), "read detached");
    check(close(fd) == 0, "close detached");
    if (!strcmp(type, "ext2")) {
        check(mount(source, DIR, type, 0, NULL) == 0, "remount ext2");
        fd = open(FILEPATH, O_RDONLY);
        check(fd >= 0 && read(fd, buf, 7) == 7 && !memcmp(buf, "payload", 7), "read remounted");
        check(close(fd) == 0, "close remounted");
        check(umount(DIR) == 0, "umount ext2");
    }
    check(mount("tmpfs", DIR, "tmpfs", 0, NULL) == 0, "mount idle");
    check(umount(DIR) == 0, "umount idle");
}

int main(int argc, char **argv)
{
    check(mkdir(DIR, 0700) == 0 || errno == EEXIST, "mkdir");
    exercise("tmpfs", "tmpfs");
    if (argc > 1) exercise(argv[1], "ext2");
    check(rmdir(DIR) == 0, "rmdir");
    puts("umount busy witness passed");
    return 0;
}
