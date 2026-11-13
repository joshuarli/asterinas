// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/statfs.h>
#include <unistd.h>

static int expect_seek(int fd, off_t offset, int whence, off_t expected, int error)
{
    off_t before = lseek(fd, 0, SEEK_CUR);
    errno = 0;
    off_t actual = lseek(fd, offset, whence);
    int actual_error = errno;
    if (actual != expected || (actual == -1 && actual_error != error)) {
        fprintf(stderr, "seek(%lld,%d): got %lld errno %d; expected %lld errno %d\n",
            (long long)offset, whence, (long long)actual, actual_error,
            (long long)expected, error);
        return 1;
    }
    off_t after = lseek(fd, 0, SEEK_CUR);
    if (after != (actual == -1 ? before : actual)) {
        fprintf(stderr, "seek changed the file offset incorrectly\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    const char *root = getenv("TMPDIR");
    char path[512];
    if (!root || !*root) root = "/tmp";
    if (snprintf(path, sizeof(path), "%s/seek-extents-XXXXXX", root) >= (int)sizeof(path))
        return 1;
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("create extent fixture");
        return 1;
    }
    if (unlink(path)) {
        perror("unlink extent fixture");
        close(fd);
        return 1;
    }
    struct statfs fs;
    int failed = 0;
    off_t large = (off_t)1 << 40;
    if (fstatfs(fd, &fs) || ftruncate(fd, large)) {
        perror("prepare sparse fixture");
        close(fd);
        return 1;
    }
    off_t block = fs.f_bsize;
    off_t far = 2 * 1024 * 1024 * block;
    failed |= expect_seek(fd, 0, SEEK_DATA, -1, ENXIO);
    failed |= expect_seek(fd, 0, SEEK_HOLE, 0, 0);
    failed |= expect_seek(fd, large - 1, SEEK_HOLE, large - 1, 0);
    failed |= expect_seek(fd, large, SEEK_HOLE, -1, ENXIO);
    failed |= expect_seek(fd, large, SEEK_DATA, -1, ENXIO);
    failed |= expect_seek(fd, large + 1, SEEK_DATA, -1, ENXIO);
    failed |= expect_seek(fd, -1, SEEK_DATA, -1, ENXIO);
    failed |= expect_seek(fd, -1, SEEK_HOLE, -1, ENXIO);
    if (pwrite(fd, "x", 1, block + 17) != 1 ||
        pwrite(fd, "y", 1, 3 * block + 29) != 1 ||
        pwrite(fd, "z", 1, far + 31) != 1) {
        perror("write sparse data");
        close(fd);
        return 1;
    }
    failed |= expect_seek(fd, 0, SEEK_DATA, block, 0);
    failed |= expect_seek(fd, block + 17, SEEK_DATA, block + 17, 0);
    failed |= expect_seek(fd, block, SEEK_HOLE, 2 * block, 0);
    failed |= expect_seek(fd, 2 * block, SEEK_DATA, 3 * block, 0);
    failed |= expect_seek(fd, 3 * block + 29, SEEK_HOLE, 4 * block, 0);
    failed |= expect_seek(fd, 4 * block, SEEK_DATA, far, 0);
    failed |= expect_seek(fd, far + 31, SEEK_DATA, far + 31, 0);
    failed |= expect_seek(fd, far, SEEK_HOLE, far + block, 0);
    failed |= expect_seek(fd, far + block, SEEK_DATA, -1, ENXIO);
    if (ftruncate(fd, block + 18)) {
        perror("truncate sparse data");
        close(fd);
        return 1;
    }
    failed |= expect_seek(fd, block, SEEK_HOLE, block + 18, 0);
    failed |= expect_seek(fd, block + 18, SEEK_HOLE, -1, ENXIO);
    if (ftruncate(fd, 0)) {
        perror("empty sparse data");
        close(fd);
        return 1;
    }
    failed |= expect_seek(fd, 0, SEEK_DATA, -1, ENXIO);
    failed |= expect_seek(fd, 0, SEEK_HOLE, -1, ENXIO);
    if (close(fd)) return 1;
    if (!failed) puts("seek extents: sparse runs, indirect blocks, eof and offsets passed");
    return failed;
}
