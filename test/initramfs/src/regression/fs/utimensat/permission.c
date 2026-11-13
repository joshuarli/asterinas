// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int ok = 1;

static void expect(int result, int expected_errno, const char *what)
{
    int actual = result == -1 ? errno : 0;
    if (expected_errno == EACCES ? (actual != EACCES && actual != EPERM) : actual != expected_errno) {
        fprintf(stderr, "%s: errno %d, expected %d\n", what, actual, expected_errno);
        ok = 0;
    }
    errno = 0;
}

int main(void)
{
    struct timespec now[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    struct timespec now_omit[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
    struct timespec omit[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    struct timespec explicit_time[2] = {{1, 0}, {1, 0}};
    char owned[] = "/tmp/utimensat-permission-XXXXXX";

    if (geteuid() == 0) {
        fprintf(stderr, "run as an unprivileged user\n");
        return 1;
    }
    expect(utimensat(AT_FDCWD, "/", NULL, 0), EACCES, "unwritable NULL");
    expect(utimensat(AT_FDCWD, "/", now, 0), EACCES, "unwritable NOW");
    expect(utimensat(AT_FDCWD, "/", explicit_time, 0), EPERM, "unwritable explicit");
    expect(utimensat(AT_FDCWD, "/", omit, 0), 0, "unwritable OMIT");
    expect(utimensat(AT_FDCWD, "/dev/null", NULL, 0), 0, "writable non-owner NULL");
    expect(utimensat(AT_FDCWD, "/dev/null", now_omit, 0), EPERM, "writable non-owner NOW+OMIT");
    expect(utimensat(AT_FDCWD, "/dev/null", explicit_time, 0), EPERM, "writable non-owner explicit");
    int fd = mkstemp(owned);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);
    expect(utimensat(AT_FDCWD, owned, explicit_time, 0), 0, "owner explicit");
    unlink(owned);
    puts(ok ? "WITNESS_PERMISSION_PASS" : "WITNESS_PERMISSION_FAIL");
    return !ok;
}
