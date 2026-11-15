// SPDX-License-Identifier: MPL-2.0

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int check_file(const char *path, mode_t mode, int profiling)
{
    struct stat st;
    char buf[4096];
    int fd = open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0777) != mode) {
        perror(path);
        return 1;
    }
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0 || (profiling && (n != 2 || memcmp(buf, "0\n", 2)))) {
        fprintf(stderr, "%s: unexpected contents\n", path);
        close(fd);
        return 1;
    }
    if (profiling && (pread(fd, buf, sizeof(buf), 1) != 1 || buf[0] != '\n')) {
        fprintf(stderr, "%s: unexpected offset read\n", path);
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

int main(void)
{
    int failed = check_file("/proc/modules", 0444, 0);
    failed |= check_file("/sys/kernel/profiling", 0644, 1);
    return failed;
}
