// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

struct entry { uint16_t tag, perm; uint32_t id; };
struct acl { uint32_t version; struct entry e[5]; };
static char root[4096], merged[4096];
static int mounted;

static int remove_owned(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st; (void)type; (void)ftw;
    return remove(path);
}

static void cleanup(void)
{
    if (mounted && umount(merged)) return;
    if (*root) nftw(root, remove_owned, 16, FTW_DEPTH | FTW_PHYS);
}

static void need(int ok, const char *what)
{
    if (!ok) { perror(what); exit(1); }
}

static void access_as_named_user(const char *path, int allowed)
{
    pid_t pid = fork();
    need(pid >= 0, "fork overlay ACL check");
    if (!pid) {
        alarm(15);
        if (setgroups(0, NULL) || setgid(12347) || setuid(12345)) _exit(2);
        int fd = open(path, O_RDONLY);
        int result = (fd >= 0) == allowed && (allowed || errno == EACCES);
        if (fd >= 0) close(fd);
        _exit(result ? 0 : 3);
    }
    int status;
    need(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "overlay ACL controls named user despite owning-group grant");
}

int main(int argc, char **argv)
{
    need(geteuid() == 0, "overlay ACL check requires root");
    alarm(120);
    const char *base = argc > 1 ? argv[1] : getenv("TMPDIR");
    if (!base) base = "/tmp";
    need(snprintf(root, sizeof(root), "%s/overlay-acl-XXXXXX", base) < (int)sizeof(root), "root path");
    need(mkdtemp(root) != NULL, "mkdtemp overlay ACL");
    atexit(cleanup);
    need(chmod(root, 0755) == 0, "overlay root traversal");
    char lower[4096], upper[4096], work[4096], lower_file[4096], file[4096], options[16384];
    need(snprintf(lower, sizeof(lower), "%s/lower", root) < (int)sizeof(lower), "lower path");
    need(snprintf(upper, sizeof(upper), "%s/upper", root) < (int)sizeof(upper), "upper path");
    need(snprintf(work, sizeof(work), "%s/work", root) < (int)sizeof(work), "work path");
    need(snprintf(merged, sizeof(merged), "%s/merged", root) < (int)sizeof(merged), "merged path");
    need(mkdir(lower, 0755) == 0 && mkdir(upper, 0755) == 0 && mkdir(work, 0755) == 0 &&
         mkdir(merged, 0755) == 0, "overlay directories");
    need(snprintf(lower_file, sizeof(lower_file), "%s/file", lower) < (int)sizeof(lower_file), "lower file path");
    need(snprintf(file, sizeof(file), "%s/file", merged) < (int)sizeof(file), "merged file path");
    struct acl acl = { .version = htole32(2) };
    const uint16_t tags[] = {1, 2, 4, 16, 32}, perms[] = {6, 0, 4, 4, 0};
    for (int i = 0; i < 5; ++i)
        acl.e[i] = (struct entry){htole16(tags[i]), htole16(perms[i]), htole32(i == 1 ? 12345 : UINT32_MAX)};
    int fd = open(lower_file, O_CREAT | O_EXCL | O_RDWR, 0600);
    need(fd >= 0, "create lower ACL file");
    need(fchown(fd, 0, 12347) == 0 && fsetxattr(fd, "system.posix_acl_access", &acl, sizeof(acl), 0) == 0,
         "set lower named-user denial");
    need(write(fd, "x", 1) == 1 && close(fd) == 0, "initialize lower ACL file");
    need(snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
         < (int)sizeof(options), "overlay mount options");
    need(mount("overlay", merged, "overlay", 0, options) == 0, "mount ACL overlay");
    mounted = 1;
    access_as_named_user(file, 0);
    fd = open(file, O_WRONLY);
    need(fd >= 0 && close(fd) == 0, "promote lower ACL file");
    access_as_named_user(file, 0);
    struct acl got;
    need(getxattr(file, "system.posix_acl_access", &got, sizeof(got)) == sizeof(got) &&
         memcmp(&acl, &got, sizeof(got)) == 0, "copy-up preserves access ACL bytes");
    acl.e[1].perm = htole16(4);
    need(setxattr(file, "system.posix_acl_access", &acl, sizeof(acl), 0) == 0, "set ACL through overlay");
    access_as_named_user(file, 1);
    need(chmod(file, 0600) == 0, "chmod through overlay");
    access_as_named_user(file, 0);
    need(umount(merged) == 0, "unmount ACL overlay");
    mounted = 0;
    return 0;
}
