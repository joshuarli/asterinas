// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct statm {
    unsigned long long size, resident, shared, text, lib, data, dt;
};

static void read_file(const char *path, char *buf, size_t capacity)
{
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    ssize_t n = read(fd, buf, capacity - 1);
    assert(n > 0 && (size_t)n < capacity - 1);
    buf[n] = '\0';
    assert(close(fd) == 0);
}

static struct statm read_statm(const char *path)
{
    char buf[512], *cursor, *end;
    unsigned long long fields[7];
    read_file(path, buf, sizeof(buf));
    cursor = buf;
    for (int i = 0; i < 7; i++) {
        while (isspace((unsigned char)*cursor)) cursor++;
        assert(isdigit((unsigned char)*cursor));
        errno = 0;
        fields[i] = strtoull(cursor, &end, 10);
        assert(errno == 0 && end != cursor);
        cursor = end;
    }
    while (isspace((unsigned char)*cursor)) cursor++;
    assert(*cursor == '\0');
    struct statm result = { fields[0], fields[1], fields[2], fields[3],
                            fields[4], fields[5], fields[6] };
    assert(result.size > 0 && result.resident <= result.size);
    assert(result.shared <= result.resident && result.text > 0 && result.text <= result.size);
    assert(result.lib == 0 && result.dt == 0 && result.data <= result.size);
    return result;
}

static unsigned long long read_vmsize(void)
{
    char buf[16384];
    read_file("/proc/self/status", buf, sizeof(buf));
    char *line = strstr(buf, "\nVmSize:");
    assert(line != NULL);
    char *end;
    unsigned long long kb = strtoull(line + sizeof("\nVmSize:") - 1, &end, 10);
    assert(end != line && strncmp(end, " kB", 3) == 0);
    return kb;
}

int main(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0 && page_size % 1024 == 0);
    char path[128];
    assert(snprintf(path, sizeof(path), "/proc/%ld/task/%ld/statm",
                    (long)getpid(), (long)getpid()) > 0);
    struct statm before = read_statm("/proc/self/statm");
    struct statm alias = read_statm(path);
    assert(before.size == alias.size && before.text == alias.text && before.data == alias.data);
    assert(before.size * (unsigned long long)page_size / 1024 == read_vmsize());

    size_t bytes = 8 * 1024 * 1024;
    size_t pages = bytes / (size_t)page_size;
    volatile char *memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);
    for (size_t i = 0; i < bytes; i += (size_t)page_size) memory[i] = 1;
    struct statm mapped = read_statm("/proc/self/statm");
    assert(mapped.size == before.size + pages);
    assert(mapped.data == before.data + pages);
    assert(mapped.resident > before.resident + pages / 2);
    assert(mapped.size * (unsigned long long)page_size / 1024 == read_vmsize());
    assert(munmap((void *)memory, bytes) == 0);
    struct statm unmapped = read_statm("/proc/self/statm");
    assert(unmapped.size == before.size && unmapped.data == before.data);
    assert(unmapped.resident + pages / 2 < mapped.resident);

    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        char byte;
        close(pipefd[1]);
        if (read(pipefd[0], &byte, 1) != 1) _exit(1);
        _exit(0);
    }
    assert(close(pipefd[0]) == 0);
    assert(snprintf(path, sizeof(path), "/proc/%ld/statm", (long)child) > 0);
    read_statm(path);
    assert(write(pipefd[1], "x", 1) == 1);
    assert(close(pipefd[1]) == 0);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    errno = 0;
    int fd = open(path, O_RDONLY);
    assert(fd == -1 && errno == ENOENT);
    return 0;
}
