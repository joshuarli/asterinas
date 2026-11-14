// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static void check(int ok, const char *what)
{
    if (!ok) { perror(what); exit(1); }
}

static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(path);
}

int main(int argc, char **argv)
{
    const char *base = argc > 1 ? argv[1] : "/tmp";
    char root[PATH_MAX], lower[PATH_MAX], upper[PATH_MAX], work[PATH_MAX];
    char merged[PATH_MAX], bind[PATH_MAX], file[PATH_MAX], bound[PATH_MAX], opts[4 * PATH_MAX];
    check(snprintf(root, sizeof(root), "%s/lifetime-XXXXXX", base) < (int)sizeof(root), "root");
    check(mkdtemp(root) != NULL, "mkdtemp");
#define PATH_TO(dst, suffix) check(snprintf(dst, sizeof(dst), "%s/" suffix, root) < (int)sizeof(dst), "path")
    PATH_TO(lower, "lower"); PATH_TO(upper, "upper"); PATH_TO(work, "work");
    PATH_TO(merged, "merged"); PATH_TO(bind, "bind");
#undef PATH_TO
    check(mkdir(lower, 0755) == 0 && mkdir(upper, 0755) == 0 && mkdir(work, 0755) == 0 &&
          mkdir(merged, 0755) == 0 && mkdir(bind, 0755) == 0, "mkdir");
    check(snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work) < (int)sizeof(opts), "options");
    check(mount("overlay", merged, "overlay", 0, opts) == 0, "mount overlay");
    check(snprintf(file, sizeof(file), "%s/file", merged) < (int)sizeof(file), "file path");
    int fd = open(file, O_CREAT | O_RDWR, 0600);
    check(fd >= 0 && write(fd, "abc", 3) == 3 && unlink(file) == 0, "create and unlink");
    check(mount(merged, bind, NULL, MS_BIND, NULL) == 0, "bind mount");
    if (argc > 2 && strcmp(argv[2], "busy") == 0) {
        errno = 0;
        check(umount(merged) == -1 && errno == EBUSY, "busy unmount");
    }
    check(umount2(merged, MNT_DETACH) == 0, "detach original");
    char data[3];
    check(pread(fd, data, sizeof(data), 0) == 3 && memcmp(data, "abc", 3) == 0, "read unlinked after detach");
    check(close(fd) == 0, "close");
    check(snprintf(bound, sizeof(bound), "%s/file", bind) < (int)sizeof(bound), "bound path");
    fd = open(bound, O_CREAT | O_RDWR, 0600);
    check(fd >= 0 && write(fd, "xyz", 3) == 3 && lseek(fd, 0, SEEK_SET) == 0 &&
          read(fd, data, sizeof(data)) == 3 && memcmp(data, "xyz", 3) == 0, "read through bind");
    check(close(fd) == 0 && unlink(bound) == 0, "remove bind file");
    fd = open(bound, O_CREAT | O_RDWR, 0600);
    check(fd >= 0 && write(fd, "end", 3) == 3 && unlink(bound) == 0, "create final unlinked file");
    check(umount2(bind, MNT_DETACH) == 0, "detach final mount");
    check(pread(fd, data, sizeof(data), 0) == 3 && memcmp(data, "end", 3) == 0, "read after final detach");
    check(close(fd) == 0, "close final handle");
    check(nftw(work, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0, "remove work tree");
    check(rmdir(merged) == 0 && rmdir(bind) == 0 && rmdir(lower) == 0 &&
          rmdir(upper) == 0 && rmdir(root) == 0, "remove directories");
    puts("LIFETIME_PASS");
    return 0;
}
