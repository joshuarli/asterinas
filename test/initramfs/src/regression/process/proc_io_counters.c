// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define DATA_BYTES (1024 * 1024)

struct vmstats {
    unsigned long long pgpgin, pgpgout, pswpin, pswpout;
};

struct diskstats {
    unsigned long long reads, reads_merged, sectors_read, read_ms;
    unsigned long long writes, writes_merged, sectors_written, write_ms;
    unsigned long long in_flight, io_ms, weighted_ms;
    char name[256];
};

static int read_vmstats(struct vmstats *stats)
{
    FILE *file = fopen("/proc/vmstat", "r");
    char name[256];
    unsigned long long value;
    unsigned found = 0;
    int result = -1;

    if (!file) {
        perror("open /proc/vmstat");
        return -1;
    }
    while (fscanf(file, "%255s %llu", name, &value) == 2) {
        if (!strcmp(name, "pgpgin")) { stats->pgpgin = value; found |= 1; }
        if (!strcmp(name, "pgpgout")) { stats->pgpgout = value; found |= 2; }
        if (!strcmp(name, "pswpin")) { stats->pswpin = value; found |= 4; }
        if (!strcmp(name, "pswpout")) { stats->pswpout = value; found |= 8; }
    }
    if (found == 15 && !ferror(file))
        result = 0;
    else
        fprintf(stderr, "missing or unreadable vmstat counters\n");
    if (fclose(file)) { perror("close vmstat"); result = -1; }
    return result;
}

static int read_diskstats(dev_t dev, struct diskstats *stats)
{
    FILE *file = fopen("/proc/diskstats", "r");
    char *line = NULL;
    size_t size = 0;
    int result = -1;

    if (!file) { perror("open /proc/diskstats"); return -1; }
    while (getline(&line, &size, file) >= 0) {
        unsigned maj, min;
        struct diskstats entry;
        int fields = sscanf(line, "%u %u %255s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
            &maj, &min, entry.name, &entry.reads, &entry.reads_merged,
            &entry.sectors_read, &entry.read_ms, &entry.writes,
            &entry.writes_merged, &entry.sectors_written, &entry.write_ms,
            &entry.in_flight, &entry.io_ms, &entry.weighted_ms);
        if (fields >= 3 && maj == major(dev) && min == minor(dev)) {
            if (fields == 14 && entry.name[0]) { *stats = entry; result = 0; }
            break;
        }
    }
    if (result) fprintf(stderr, "missing or malformed diskstats for %u:%u\n", major(dev), minor(dev));
    free(line);
    if (fclose(file)) { perror("close diskstats"); result = -1; }
    return result;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : getenv("TMPDIR");
    struct stat st;
    struct vmstats before, after;
    struct diskstats disk_before, disk_after;
    char *path = NULL;
    char data[4096];
    int fd = -1, result = 1;
    size_t written = 0;

    if (!dir || !*dir) dir = ".";
    if (argc > 2) {
        fprintf(stderr, "usage: %s scratch-directory (or set TMPDIR)\n", argv[0]);
        return 1;
    }
    if (stat(dir, &st)) { perror("stat scratch directory"); return 1; }
    if (asprintf(&path, "%s/proc-io-counters-XXXXXX", dir) < 0) return 1;
    fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); goto out; }
    if (read_vmstats(&before) || read_diskstats(st.st_dev, &disk_before)) goto out;
    memset(data, 0x5a, sizeof(data));
    while (written < DATA_BYTES) {
        ssize_t n = write(fd, data, sizeof(data));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { perror("write"); goto out; }
        written += (size_t)n;
    }
    if (fsync(fd)) { perror("fsync"); goto out; }
    if (read_vmstats(&after) || read_diskstats(st.st_dev, &disk_after)) goto out;
    if (after.pgpgin < before.pgpgin || after.pgpgout < before.pgpgout ||
        after.pswpin < before.pswpin || after.pswpout < before.pswpout ||
        disk_after.reads < disk_before.reads || disk_after.reads_merged < disk_before.reads_merged ||
        disk_after.sectors_read < disk_before.sectors_read || disk_after.read_ms < disk_before.read_ms ||
        disk_after.writes < disk_before.writes || disk_after.writes_merged < disk_before.writes_merged ||
        disk_after.sectors_written < disk_before.sectors_written || disk_after.write_ms < disk_before.write_ms ||
        disk_after.io_ms < disk_before.io_ms || disk_after.weighted_ms < disk_before.weighted_ms ||
        strcmp(disk_before.name, disk_after.name) ||
        after.pgpgout - before.pgpgout < DATA_BYTES / 1024 ||
        disk_after.sectors_written - disk_before.sectors_written < DATA_BYTES / 512 ||
        disk_after.writes == disk_before.writes) {
        fprintf(stderr, "I/O counters did not advance as expected for %s\n", disk_before.name);
        goto out;
    }
    printf("%s: pgpgout +%llu KiB, writes +%llu, sectors written +%llu\n",
        disk_before.name, after.pgpgout - before.pgpgout,
        disk_after.writes - disk_before.writes,
        disk_after.sectors_written - disk_before.sectors_written);
    result = 0;
out:
    if (fd >= 0 && close(fd)) { perror("close scratch file"); result = 1; }
    if (fd >= 0 && unlink(path)) { perror("unlink scratch file"); result = 1; }
    free(path);
    return result;
}
