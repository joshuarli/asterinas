// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    static const char *names[] = {"MemTotal", "MemFree", "MemAvailable", "Buffers",
                                  "Cached", "Shmem", "SReclaimable", "SwapTotal", "SwapFree"};
    unsigned long values[sizeof(names) / sizeof(names[0])] = {0};
    int seen[sizeof(names) / sizeof(names[0])] = {0};
    const size_t size = 1024 * 1024;
    int fd = -1, result = 1;
    char *mapping = MAP_FAILED;
    char *anonymous = MAP_FAILED;
    FILE *file = NULL;
    char line[256], name[64], unit[16], extra;
    unsigned long value;

    fd = memfd_create("meminfo-counters", 0);
    if (fd < 0) {
        perror("memfd_create");
        goto out;
    }
    if (ftruncate(fd, size) != 0) {
        perror("ftruncate memfd");
        goto out;
    }
    mapping = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap memfd");
        goto out;
    }
    anonymous = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (anonymous == MAP_FAILED) {
        perror("mmap shared anonymous");
        goto out;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        fprintf(stderr, "invalid host page size\n");
        goto out;
    }
    for (size_t offset = 0; offset < size; offset += (size_t)page_size) {
        ((volatile char *)mapping)[offset] = 1;
        ((volatile char *)anonymous)[offset] = 1;
    }
    file = fopen("/proc/meminfo", "r");
    if (!file) {
        perror("open meminfo");
        goto out;
    }
    while (fgets(line, sizeof(line), file)) {
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            size_t len = strlen(names[i]);
            if (strncmp(line, names[i], len) != 0 || line[len] != ':')
                continue;
            if (seen[i] || sscanf(line, "%63[^:]: %lu %15s %c", name, &value, unit, &extra) != 3 ||
                strcmp(unit, "kB") != 0) {
                fprintf(stderr, "malformed or repeated %s\n", names[i]);
                goto out;
            }
            seen[i] = 1;
            values[i] = value;
        }
    }
    if (ferror(file)) {
        perror("read meminfo");
        goto out;
    }
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!seen[i]) {
            fprintf(stderr, "missing or invalid %s\n", names[i]);
            goto out;
        }
    }
    if (values[4] < 2 * size / 1024 || values[5] < 2 * size / 1024) {
        fprintf(stderr, "resident shared pages missing from Cached or Shmem\n");
        goto out;
    }
    printf("Cached=%lu KiB Shmem=%lu KiB with %zu owned resident shared bytes\n", values[4], values[5], 2 * size);
    result = 0;
out:
    if (file && fclose(file)) { perror("close meminfo"); result = 1; }
    if (mapping != MAP_FAILED && munmap(mapping, size)) { perror("munmap memfd"); result = 1; }
    if (anonymous != MAP_FAILED && munmap(anonymous, size)) { perror("munmap shared anonymous"); result = 1; }
    if (fd >= 0 && close(fd)) { perror("close memfd"); result = 1; }
    return result;
}
