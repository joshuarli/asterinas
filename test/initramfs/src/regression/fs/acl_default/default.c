// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define DEFAULT "system.posix_acl_default"
#define ACCESS "system.posix_acl_access"
#define UNDEF UINT32_MAX
struct entry { uint16_t tag, perm; uint32_t id; };
struct acl { uint32_t version; struct entry entries[5]; };
static const struct acl acl = { 2, {{1,7,UNDEF},{2,7,12345},{4,7,UNDEF},{16,7,UNDEF},{32,7,UNDEF}} };
static void check(int condition, const char *message) {
    if (!condition) { perror(message); exit(1); }
}
static void mode_is(const char *path, mode_t expected) {
    struct stat st;
    check(stat(path, &st) == 0, path);
    if ((st.st_mode & 0777) != expected) {
        fprintf(stderr, "%s: mode %03o expected %03o\n", path, st.st_mode & 0777, expected);
        exit(1);
    }
}
int main(int argc, char **argv) {
    char root[4096], path[4096];
    const char *base = argc > 1 ? argv[1] : "/tmp";
    if (argc > 2) {
        check(snprintf(root, sizeof(root), "%s/persist", base) < (int)sizeof(root), "persist path");
        if (!strcmp(argv[2], "persist-set")) {
            check(mkdir(root, 0700) == 0, "persist mkdir");
            check(setxattr(root, DEFAULT, &acl, sizeof(acl), 0) == 0, "persist set");
        } else {
            struct acl saved;
            check(getxattr(root, DEFAULT, &saved, sizeof(saved)) == sizeof(saved) && !memcmp(&saved, &acl, sizeof(saved)), "persist get");
            check(removexattr(root, DEFAULT) == 0 && rmdir(root) == 0, "persist cleanup");
        }
        return 0;
    }
    check(snprintf(root, sizeof(root), "%s/acl-default-%ld", base, (long)getpid()) < (int)sizeof(root), "root path");
    check(mkdir(root, 0777) == 0, "mkdir root");
    check(setxattr(root, DEFAULT, &acl, sizeof(acl), 0) == 0, "set default");
    struct acl got;
    check(getxattr(root, DEFAULT, &got, sizeof(got)) == sizeof(got) && !memcmp(&got, &acl, sizeof(got)), "get default");
    if (geteuid() == 0) {
        pid_t pid = fork();
        check(pid >= 0, "fork");
        if (!pid) {
            if (setgid(1000) || setuid(1000)) _exit(2);
            _exit(setxattr(root, DEFAULT, &acl, sizeof(acl), 0) == -1 && errno == EPERM ? 0 : 1);
        }
        int status;
        check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "non-owner");
    }
    umask(0777);
    check(snprintf(path, sizeof(path), "%s/file", root) < (int)sizeof(path), "file path");
    int fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0750);
    check(fd >= 0, "create file"); close(fd);
    mode_is(path, 0750);
    check(getxattr(path, ACCESS, &got, sizeof(got)) == sizeof(got), "inherited access");
    check(got.entries[3].perm == 5, "inherited mask");
    errno = 0;
    check(setxattr(path, DEFAULT, &acl, sizeof(acl), 0) == -1 && errno == EACCES, "file default rejected");
    check(removexattr(path, DEFAULT) == 0, "remove file default");
    check(unlink(path) == 0, "unlink");
    check(snprintf(path, sizeof(path), "%s/fifo", root) < (int)sizeof(path), "fifo path");
    check(mknod(path, S_IFIFO | 0750, 0) == 0, "mknod"); mode_is(path, 0750); check(unlink(path) == 0, "unlink fifo");
    check(snprintf(path, sizeof(path), "%s/dir", root) < (int)sizeof(path), "dir path");
    check(mkdir(path, 0750) == 0, "mkdir child"); mode_is(path, 0750);
    check(getxattr(path, DEFAULT, &got, sizeof(got)) == sizeof(got) && !memcmp(&got, &acl, sizeof(got)), "inherited default");
    check(rmdir(path) == 0, "rmdir child");
    check(removexattr(root, DEFAULT) == 0, "remove default");
    errno = 0; check(getxattr(root, DEFAULT, &got, sizeof(got)) == -1 && errno == ENODATA, "missing default");
    check(rmdir(root) == 0, "rmdir root");
    puts("default ACL witness passed");
    return 0;
}
