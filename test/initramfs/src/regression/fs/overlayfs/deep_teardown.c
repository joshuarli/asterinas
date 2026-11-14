// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEPTH 4096

static void need(int ok, const char *operation)
{
    if (!ok) { perror(operation); exit(1); }
}

static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(path);
}

static void run(const char *base, int keep_file)
{
    char root[PATH_MAX], lower[PATH_MAX], upper[PATH_MAX], work[PATH_MAX];
    char merged[PATH_MAX], options[4 * PATH_MAX];
    need(snprintf(root, sizeof(root), "%s/deep-overlay-XXXXXX", base) < (int)sizeof(root), "root path");
    need(mkdtemp(root) != NULL, "mkdtemp");
#define CHILD(dst, suffix) need(snprintf(dst, sizeof(dst), "%s/" suffix, root) < (int)sizeof(dst), "child path")
    CHILD(lower, "lower"); CHILD(upper, "upper"); CHILD(work, "work"); CHILD(merged, "merged");
#undef CHILD
    need(mkdir(lower, 0755) == 0 && mkdir(upper, 0755) == 0 &&
         mkdir(work, 0755) == 0 && mkdir(merged, 0755) == 0, "mkdir roots");
    need(snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work) < (int)sizeof(options), "options");
    need(mount("overlay", merged, "overlay", 0, options) == 0, "mount overlay");
    int directory = open(merged, O_RDONLY | O_DIRECTORY);
    need(directory >= 0, "open root");
    for (int depth = 0; depth < DEPTH; depth++) {
        need(mkdirat(directory, "d", 0700) == 0, "mkdir deep child");
        int child = openat(directory, "d", O_RDONLY | O_DIRECTORY);
        need(child >= 0 && close(directory) == 0, "open deep child");
        directory = child;
    }
    int file = -1;
    if (keep_file) {
        file = openat(directory, "file", O_CREAT | O_RDWR, 0600);
        need(file >= 0 && write(file, "kept", 4) == 4 &&
             unlinkat(directory, "file", 0) == 0, "create unlinked deep file");
    }
    need(close(directory) == 0, "close directory");
    printf("deep teardown start keep_file=%d\n", keep_file);
    fflush(stdout);
    need(umount2(merged, MNT_DETACH) == 0, "detach deep overlay");
    if (keep_file) {
        char value[4];
        need(pread(file, value, sizeof(value), 0) == 4 && !memcmp(value, "kept", 4), "read detached deep file");
        need(close(file) == 0, "close detached deep file");
    }
    directory = open(upper, O_RDONLY | O_DIRECTORY);
    need(directory >= 0, "open backing root");
    for (int depth = 0; depth < DEPTH; depth++) {
        int child = openat(directory, "d", O_RDONLY | O_DIRECTORY);
        need(child >= 0 && close(directory) == 0, "open backing child");
        directory = child;
    }
    for (int depth = 0; depth < DEPTH; depth++) {
        int parent = openat(directory, "..", O_RDONLY | O_DIRECTORY);
        need(parent >= 0 && close(directory) == 0, "open backing parent");
        need(unlinkat(parent, "d", AT_REMOVEDIR) == 0, "remove backing child");
        directory = parent;
    }
    need(close(directory) == 0, "close backing root");
    need(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0, "remove deep fixture");
    printf("deep teardown passed keep_file=%d\n", keep_file);
}

int main(int argc, char **argv)
{
    alarm(60);
    const char *base = argc > 1 ? argv[1] : "/tmp";
    run(base, 0);
    run(base, 1);
    return 0;
}
