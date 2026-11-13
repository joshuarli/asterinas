// SPDX-License-Identifier: MPL-2.0
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if ((x) == -1) { perror(#x); exit(1); } } while (0)

int main(void)
{
    char data[8192] = {42};
    CHECK(mkdir("/work/ext2-persist", 0700));
    CHECK(mkdir("/work/ext2-persist/dir", 0700));
    int fd = open("/work/ext2-persist/dir/file", O_CREAT | O_WRONLY | O_EXCL, 0600);
    CHECK(fd);
    if (write(fd, data, sizeof(data)) != sizeof(data)) { perror("write"); return 1; }
    CHECK(fsync(fd));
    CHECK(rename("/work/ext2-persist/dir/file", "/work/ext2-persist/dir/renamed"));
    CHECK(unlink("/work/ext2-persist/dir/renamed"));
    CHECK(close(fd));
    CHECK(rmdir("/work/ext2-persist/dir"));
    CHECK(rmdir("/work/ext2-persist"));
    return 0;
}
