// SPDX-License-Identifier: MPL-2.0

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat st;
    char buf[8];
    int fd = open("/sys/kernel/profiling", O_RDONLY);
    if (fd < 0 || fstat(fd, &st)) {
        perror("profiling");
        return 1;
    }
    if (st.st_size != sysconf(_SC_PAGESIZE)) {
        fprintf(stderr, "profiling size: %lld, expected %ld\n",
                (long long)st.st_size, sysconf(_SC_PAGESIZE));
        return 1;
    }
    if (read(fd, buf, sizeof(buf)) != 2 || memcmp(buf, "0\n", 2) ||
        read(fd, buf, sizeof(buf)) != 0 ||
        pread(fd, buf, sizeof(buf), 1) != 1 || buf[0] != '\n' ||
        pread(fd, buf, sizeof(buf), st.st_size - 1) != 0) {
        fprintf(stderr, "unexpected profiling read or EOF\n");
        return 1;
    }
    close(fd);
    return 0;
}
