// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define NAME "system.posix_acl_access"
#define UNDEF UINT32_MAX

struct entry { uint16_t tag, perm; uint32_t id; };
struct acl { uint32_t version; struct entry entries[6]; };
static char dir[4096], file[4096];

enum operation { ACCESS, SET_DENIED, REMOVE_DENIED, OWNER_SET, READ_ACL };

static void cleanup(void)
{
    if (*file) unlink(file);
    if (*dir) rmdir(dir);
}

static void require(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "%s: %s\n", what, strerror(errno));
        exit(1);
    }
}

static void entry(struct entry *e, uint16_t tag, uint16_t perm, uint32_t id)
{
    e->tag = htole16(tag);
    e->perm = htole16(perm);
    e->id = htole32(id);
}

static struct acl make_acl(void)
{
    struct acl acl = { .version = htole32(2) };
    entry(&acl.entries[0], 1, 6, UNDEF);
    entry(&acl.entries[1], 2, 4, 12345);
    entry(&acl.entries[2], 4, 0, UNDEF);
    entry(&acl.entries[3], 8, 2, 12346);
    entry(&acl.entries[4], 16, 6, UNDEF);
    entry(&acl.entries[5], 32, 0, UNDEF);
    return acl;
}

static void child_check(const char *path, uid_t uid, gid_t gid, gid_t extra,
                        int flags, int expected, enum operation operation)
{
    pid_t pid = fork();
    require(pid >= 0, "fork");
    if (!pid) {
        alarm(15);
        if (setgroups(extra ? 1 : 0, extra ? &extra : NULL) || setgid(gid) || setuid(uid)) _exit(100);
        if (operation == OWNER_SET) {
            struct acl acl = make_acl();
            _exit(setxattr(path, NAME, &acl, sizeof(acl), 0) == 0 ? 0 : 101);
        }
        if (operation == SET_DENIED || operation == REMOVE_DENIED) {
            uint32_t empty = htole32(2);
            int ret = operation == SET_DENIED
                ? setxattr(path, NAME, &empty, sizeof(empty), 0)
                : removexattr(path, NAME);
            _exit(ret == -1 && errno == EPERM ? 0 : 102);
        }
        if (operation == READ_ACL) {
            struct acl got;
            if (getxattr(path, NAME, &got, sizeof(got)) != sizeof(got)) _exit(103);
            char names[512];
            ssize_t length = listxattr(path, names, sizeof(names));
            int listed = 0;
            if (length < 0) _exit(105);
            for (ssize_t offset = 0; offset < length; offset += strlen(names + offset) + 1)
                listed += strcmp(names + offset, NAME) == 0;
            _exit(listed == 1 ? 0 : 106);
        }
        int fd = open(path, flags);
        int saved_errno = errno;
        if (fd >= 0) close(fd);
        _exit((fd >= 0) == expected && (expected || saved_errno == EACCES) ? 0 : 104);
    }
    int status;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    require(waited == pid, "waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "uid %u gid %u extra %u flags %d operation %d child status %d\n",
                uid, gid, extra, flags, operation, status);
        exit(1);
    }
}

static void check_mode(mode_t expected, const char *what)
{
    struct stat st;
    require(stat(file, &st) == 0 && (st.st_mode & 07777) == expected, what);
}

int main(int argc, char **argv)
{
    require(geteuid() == 0, "cross-principal checks require root");
    alarm(120);
    const char *base = argc > 1 ? argv[1] : getenv("TMPDIR");
    if (!base) base = "/tmp";
    require(snprintf(dir, sizeof(dir), "%s/posix-acl-XXXXXX", base) < (int)sizeof(dir), "directory path");
    require(mkdtemp(dir) != NULL, "mkdtemp");
    atexit(cleanup);
    require(chmod(dir, 0777) == 0, "chmod directory");
    require(snprintf(file, sizeof(file), "%s/file", dir) < (int)sizeof(file), "file path");
    int fd = open(file, O_CREAT | O_EXCL | O_RDWR, 0600);
    require(fd >= 0, "create file");
    require(close(fd) == 0, "close file");
    require(chown(file, 1000, 12349) == 0, "chown file");

    struct acl acl = make_acl(), got;
    require(setxattr(file, NAME, &acl, sizeof(acl), XATTR_REPLACE) == 0, "set ACL with REPLACE");
    require(getxattr(file, NAME, NULL, 0) == sizeof(got), "ACL length");
    errno = 0;
    require(getxattr(file, NAME, &got, sizeof(got) - 1) == -1 && errno == ERANGE, "short ACL buffer");
    require(getxattr(file, NAME, &got, sizeof(got)) == sizeof(got) &&
            memcmp(&acl, &got, sizeof(acl)) == 0, "ACL roundtrip");
    char names[512];
    ssize_t length = listxattr(file, names, sizeof(names));
    require(length > 0, "list ACL");
    int listed = 0;
    for (ssize_t offset = 0; offset < length; offset += strlen(names + offset) + 1)
        listed += strcmp(names + offset, NAME) == 0;
    require(listed == 1, "ACL listed by exact full name");
    check_mode(0660, "ACL mode");
    require(setxattr(file, NAME, &acl, sizeof(acl), XATTR_CREATE) == 0, "set ACL with CREATE");
    struct acl invalid = acl;
    invalid.entries[4].perm = htole16(8);
    errno = 0;
    require(setxattr(file, NAME, &invalid, sizeof(invalid), 0) == -1 && errno == EINVAL, "invalid ACL permissions");
    invalid = acl;
    invalid.entries[4].tag = htole16(2);
    errno = 0;
    require(setxattr(file, NAME, &invalid, sizeof(invalid), 0) == -1 && errno == EINVAL, "invalid ACL order");
    invalid = acl;
    invalid.version = htole32(3);
    errno = 0;
    require(setxattr(file, NAME, &invalid, sizeof(invalid), 0) == -1 && errno == EOPNOTSUPP, "invalid ACL version");
    require(getxattr(file, NAME, &got, sizeof(got)) == sizeof(got) &&
            memcmp(&acl, &got, sizeof(acl)) == 0, "invalid ACL preserves policy");
    check_mode(0660, "invalid ACL preserves mode");
    errno = 0;
    require(syscall(SYS_setxattr, file, NAME, (void *)(uintptr_t)1, sizeof(acl), 0) == -1 && errno == EFAULT,
            "unreadable ACL buffer");
    require(getxattr(file, NAME, &got, sizeof(got)) == sizeof(got) &&
            memcmp(&acl, &got, sizeof(acl)) == 0, "unreadable ACL buffer preserves policy");
    check_mode(0660, "unreadable ACL buffer preserves mode");
    if (argc > 2 && strcmp(argv[2], "--ext2") == 0) {
        char filler[128] = {0};
        require(setxattr(file, "user.acl-space", filler, sizeof(filler), 0) == 0, "reserve xattr space");
        struct { uint32_t version; struct entry e[504]; } large = { .version = htole32(2) };
        entry(&large.e[0], 1, 6, UNDEF);
        for (int i = 0; i < 500; ++i) entry(&large.e[i + 1], 2, 4, 20000 + i);
        entry(&large.e[501], 4, 0, UNDEF);
        entry(&large.e[502], 16, 4, UNDEF);
        entry(&large.e[503], 32, 0, UNDEF);
        errno = 0;
        require(setxattr(file, NAME, &large, sizeof(large), 0) == -1 && errno == ENOSPC,
                "full xattr block rejects ACL update");
        require(getxattr(file, NAME, &got, sizeof(got)) == sizeof(got) &&
                memcmp(&acl, &got, sizeof(acl)) == 0, "full xattr block preserves policy");
        check_mode(0660, "full xattr block preserves mode");
        require(removexattr(file, "user.acl-space") == 0, "remove reserved xattr space");
    }

    child_check(file, 12345, 12347, 0, O_RDONLY, 1, ACCESS);
    child_check(file, 12345, 12347, 0, O_WRONLY, 0, ACCESS);
    child_check(file, 12348, 12346, 0, O_WRONLY, 1, ACCESS);
    child_check(file, 12348, 12346, 0, O_RDONLY, 0, ACCESS);
    child_check(file, 12348, 12347, 12346, O_WRONLY, 1, ACCESS);
    child_check(file, 12348, 12347, 0, O_WRONLY, 0, ACCESS);
    child_check(file, 12348, 12346, 0, 0, 0, SET_DENIED);
    child_check(file, 12348, 12346, 0, 0, 0, REMOVE_DENIED);
    child_check(file, 12348, 12347, 0, 0, 0, READ_ACL);

    require(chmod(file, 0440) == 0, "chmod ACL file");
    require(getxattr(file, NAME, &got, sizeof(got)) == sizeof(got) &&
            le16toh(got.entries[0].perm) == 4 && le16toh(got.entries[4].perm) == 4 &&
            le16toh(got.entries[5].perm) == 0, "chmod ACL mask");
    child_check(file, 12348, 12346, 0, O_WRONLY, 0, ACCESS);
    child_check(file, 1000, 1000, 0, 0, 0, OWNER_SET);
    check_mode(0660, "unprivileged owner sets ACL on read-only file");
    require(chmod(file, 02660) == 0, "setgid before ACL update");
    child_check(file, 1000, 1000, 0, 0, 0, OWNER_SET);
    check_mode(0660, "ACL update clears unauthorized setgid");

    entry(&acl.entries[2], 4, 4, UNDEF);
    require(setxattr(file, NAME, &acl, sizeof(acl), 0) == 0, "set separate group grants");
    child_check(file, 12348, 12349, 12346, O_RDONLY, 1, ACCESS);
    child_check(file, 12348, 12349, 12346, O_WRONLY, 1, ACCESS);
    child_check(file, 12348, 12349, 12346, O_RDWR, 0, ACCESS);
    entry(&acl.entries[1], 2, 0, 12345);
    entry(&acl.entries[5], 32, 6, UNDEF);
    require(setxattr(file, NAME, &acl, sizeof(acl), 0) == 0, "set fallback traps");
    child_check(file, 12345, 12347, 0, O_RDONLY, 0, ACCESS);
    child_check(file, 12348, 12346, 0, O_RDONLY, 0, ACCESS);
    child_check(file, 12348, 12347, 0, O_RDONLY, 1, ACCESS);

    struct acl directory_acl = make_acl();
    entry(&directory_acl.entries[0], 1, 7, UNDEF);
    entry(&directory_acl.entries[1], 2, 5, 12345);
    entry(&directory_acl.entries[4], 16, 5, UNDEF);
    require(setxattr(dir, NAME, &directory_acl, sizeof(directory_acl), 0) == 0, "set directory access ACL");
    child_check(dir, 12345, 12347, 0, O_RDONLY | O_DIRECTORY, 1, ACCESS);
    child_check(dir, 12348, 12347, 0, O_RDONLY | O_DIRECTORY, 0, ACCESS);
    require(removexattr(dir, NAME) == 0 && chmod(dir, 0777) == 0, "restore directory access");

    require(chmod(file, 02660) == 0, "setgid before ACL removal");
    require(removexattr(file, NAME) == 0, "remove ACL");
    check_mode(02660, "ACL removal preserves mode");
    require(removexattr(file, NAME) == 0, "remove absent ACL");
    errno = 0;
    require(getxattr(file, NAME, &got, sizeof(got)) == -1 && errno == ENODATA, "ACL removed");
    struct { uint32_t version; struct entry e[3]; } basic = { .version = htole32(2) };
    entry(&basic.e[0], 1, 6, UNDEF);
    entry(&basic.e[1], 4, 0, UNDEF);
    entry(&basic.e[2], 32, 0, UNDEF);
    require(setxattr(file, NAME, &basic, sizeof(basic), 0) == 0, "set mode-equivalent ACL");
    errno = 0;
    require(getxattr(file, NAME, &got, sizeof(got)) == -1 && errno == ENODATA, "mode-equivalent ACL removed");
    check_mode(02600, "mode-equivalent mode preserves authorized setgid");
    acl = make_acl();
    require(setxattr(file, NAME, &acl, sizeof(acl), 0) == 0, "set before zero-entry removal");
    uint32_t empty = htole32(2);
    require(chmod(file, 02660) == 0, "setgid before empty ACL update");
    require(setxattr(file, NAME, &empty, sizeof(empty), 0) == 0, "zero-entry ACL removes");
    check_mode(02660, "empty ACL update preserves mode");
    errno = 0;
    require(getxattr(file, NAME, &got, sizeof(got)) == -1 && errno == ENODATA, "zero-entry ACL absent");
    require(setxattr(file, NAME, NULL, 0, 0) == 0, "zero-byte ACL removes");
    return 0;
}
