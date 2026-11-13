// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char work[PATH_MAX];

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); \
    failed = 1; goto out; \
} } while (0)

static int fd_name(int fd, const char *name, const char *suffix)
{
    char proc[64], actual[PATH_MAX], expected[PATH_MAX];
    struct stat a, b;
    int length = snprintf(expected, sizeof(expected), "%s/%s%s", work, name, suffix);
    if (length < 0 || (size_t)length >= sizeof(expected)) return 0;
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t count = readlink(proc, actual, sizeof(actual));
    if (count != length || memcmp(actual, expected, length)) {
        fprintf(stderr, "fd %d: expected '%s', got '%.*s' (%zd bytes, errno=%d)\n",
                fd, expected, count > 0 ? (int)count : 0, actual, count, errno);
        return 0;
    }
    return fstat(fd, &a) == 0 && stat(proc, &b) == 0 &&
           a.st_ino == b.st_ino && a.st_dev == b.st_dev;
}

int main(int argc, char **argv)
{
    int exchange = argc == 2 && !strcmp(argv[1], "--exchange");
    if (argc != 1 && !exchange) return 1;
    const char *base = getenv("TMPDIR");
    const char *names[] = {"raw-\xff", "survivor", "source", "target", "target-keep",
                           "cross-keep", "sub/cross", "exchange", "sub/exchange"};
    int original = -1, fds[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    int failed = 0, entered = 0;
    struct stat before, after;
    char resolved[PATH_MAX];
    if (!base || !*base) base = ".";
    int length = snprintf(work, sizeof(work), "%s/deleted-paths-XXXXXX", base);
    if (length <= 0 || (size_t)length >= sizeof(work) || !mkdtemp(work)) return 1;
    CHECK(realpath(work, resolved) != NULL);
    memcpy(work, resolved, strlen(resolved) + 1);
    original = open(".", O_RDONLY | O_DIRECTORY);
    CHECK(original >= 0 && chdir(work) == 0);
    entered = 1;
    CHECK(mkdir("sub", 0700) == 0);

    fds[0] = open("raw-\xff", O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(fds[0] >= 0 && link("raw-\xff", "survivor") == 0);
    CHECK(fd_name(fds[0], "raw-\xff", ""));
    CHECK(unlink("raw-\xff") == 0);
    CHECK(fstat(fds[0], &before) == 0 && before.st_nlink == 1);
    CHECK(fd_name(fds[0], "raw-\xff", " (deleted)"));
    fds[1] = open("survivor", O_RDONLY);
    CHECK(fds[1] >= 0 && fd_name(fds[1], "survivor", ""));
    fds[2] = open("raw-\xff", O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(fds[2] >= 0 && fstat(fds[2], &after) == 0 && after.st_ino != before.st_ino);
    CHECK(fd_name(fds[2], "raw-\xff", "") && fd_name(fds[0], "raw-\xff", " (deleted)"));

    fds[3] = open("source", O_CREAT | O_RDWR | O_EXCL, 0600);
    fds[4] = open("target", O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(fds[3] >= 0 && fds[4] >= 0 && link("target", "target-keep") == 0);
    CHECK(rename("source", "target") == 0);
    CHECK(fd_name(fds[3], "target", "") && fd_name(fds[4], "target", " (deleted)"));
    CHECK(fstat(fds[4], &after) == 0 && after.st_nlink == 1);

    fds[5] = open("sub/cross", O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(fds[5] >= 0 && link("sub/cross", "cross-keep") == 0);
    CHECK(rename("target", "sub/cross") == 0);
    CHECK(fd_name(fds[3], "sub/cross", "") && fd_name(fds[5], "sub/cross", " (deleted)"));
    CHECK(fstat(fds[5], &after) == 0 && after.st_nlink == 1);

    fds[6] = open("exchange", O_CREAT | O_RDWR | O_EXCL, 0600);
    fds[7] = open("sub/exchange", O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(fds[6] >= 0 && fds[7] >= 0);
    const char *first = "exchange", *second = "sub/exchange";
    if (exchange) {
        CHECK(renameat2(AT_FDCWD, "exchange", AT_FDCWD, "sub/exchange", RENAME_EXCHANGE) == 0);
        first = "sub/exchange";
        second = "exchange";
    }
    CHECK(fd_name(fds[6], first, "") && fd_name(fds[7], second, ""));
    errno = 0;
    CHECK(renameat2(AT_FDCWD, "exchange", AT_FDCWD, "sub/exchange", RENAME_NOREPLACE) == -1 && errno == EEXIST);
    CHECK(fd_name(fds[6], first, "") && fd_name(fds[7], second, ""));
    CHECK(close(fds[7]) == 0);
    fds[7] = -1;
    CHECK(mkdir("removed-dir", 0700) == 0);
    fds[7] = open("removed-dir", O_RDONLY | O_DIRECTORY);
    CHECK(fds[7] >= 0 && rmdir("removed-dir") == 0);
    CHECK(fd_name(fds[7], "removed-dir", " (deleted)"));
    CHECK(close(fds[6]) == 0);
    fds[6] = -1;
    CHECK(close(fds[7]) == 0);
    fds[7] = -1;
    CHECK(mkdir("dir-source", 0700) == 0 && mkdir("dir-target", 0700) == 0 &&
          mkdir("sub/dir-target", 0700) == 0);
    fds[6] = open("dir-source", O_RDONLY | O_DIRECTORY);
    fds[7] = open("dir-target", O_RDONLY | O_DIRECTORY);
    CHECK(fds[6] >= 0 && fds[7] >= 0 && rename("dir-source", "dir-target") == 0);
    CHECK(fd_name(fds[6], "dir-target", "") && fd_name(fds[7], "dir-target", " (deleted)"));
    CHECK(fstat(fds[6], &after) == 0 && after.st_nlink == 2);
    CHECK(fstat(fds[7], &after) == 0 && after.st_nlink == 0);
    CHECK(close(fds[7]) == 0);
    fds[7] = open("sub/dir-target", O_RDONLY | O_DIRECTORY);
    CHECK(fds[7] >= 0 && rename("dir-target", "sub/dir-target") == 0);
    CHECK(fd_name(fds[6], "sub/dir-target", "") && fd_name(fds[7], "sub/dir-target", " (deleted)"));
    CHECK(fstat(fds[6], &after) == 0 && after.st_nlink == 2);
    CHECK(fstat(fds[7], &after) == 0 && after.st_nlink == 0);
out:
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
        if (fds[i] >= 0 && close(fds[i])) failed = 1;
    if (entered) {
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
            if (unlink(names[i]) && errno != ENOENT) failed = 1;
        if (rmdir("removed-dir") && errno != ENOENT) failed = 1;
        if (rmdir("dir-source") && errno != ENOENT) failed = 1;
        if (rmdir("dir-target") && errno != ENOENT) failed = 1;
        if (rmdir("sub/dir-target") && errno != ENOENT) failed = 1;
        if (rmdir("sub") && errno != ENOENT) failed = 1;
        if (fchdir(original)) failed = 1;
    }
    if (original >= 0 && close(original)) failed = 1;
    if (rmdir(work)) failed = 1;
    return failed;
}
