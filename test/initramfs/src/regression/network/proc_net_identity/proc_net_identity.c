// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include "../sock_diag.h"

#define COUNT 160

static void fail(const char *message)
{
    perror(message);
    exit(1);
}

static unsigned long long inode(int fd)
{
    struct stat st;
    if (fstat(fd, &st)) fail("fstat");
    return st.st_ino;
}

static char *read_chunks(const char *path, size_t chunk)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) fail(path);
    size_t used = 0, cap = 4096;
    char *buf = malloc(cap);
    if (!buf) fail("malloc");
    for (;;) {
        if (used + chunk + 1 > cap) {
            while (used + chunk + 1 > cap) cap *= 2;
            char *next = realloc(buf, cap);
            if (!next) fail("realloc");
            buf = next;
        }
        ssize_t n = read(fd, buf + used, chunk);
        if (n < 0) fail("read");
        used += (size_t)n;
        if (!n) break;
    }
    close(fd);
    buf[used] = 0;
    return buf;
}

static int occurrences(const char *text, int column, unsigned long long wanted, const char *name)
{
    char *copy = strdup(text), *line_save, *line;
    if (!copy) fail("strdup");
    int matches = 0;
    for (line = strtok_r(copy, "\n", &line_save); line; line = strtok_r(NULL, "\n", &line_save)) {
        char *field_save, *field = strtok_r(line, " \t", &field_save);
        for (int i = 0; field && i < column; i++) field = strtok_r(NULL, " \t", &field_save);
        if (field && strtoull(field, NULL, 10) == wanted) {
            if (name) {
                field = strtok_r(NULL, " \t", &field_save);
                if (!field || strcmp(field, name)) continue;
            }
            matches++;
        }
    }
    free(copy);
    return matches;
}

static void require_entry(const char *table, int col, unsigned long long ino, const char *name, int expected)
{
    char *text = read_chunks(table, 37);
    int found = occurrences(text, col, ino, name);
    free(text);
    if (found != expected) {
        fprintf(stderr, "%s inode=%llu count=%d expected=%d\n", table, ino, found, expected);
        exit(1);
    }
}

static int udp4(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (fd < 0 || bind(fd, (void *)&addr, sizeof(addr))) fail("udp bind");
    return fd;
}

static void udp_many(void)
{
    int fds[COUNT];
    unsigned long long ids[COUNT];
    for (int i = 0; i < COUNT; i++) { fds[i] = udp4(0); ids[i] = inode(fds[i]); }
    char *small = read_chunks("/proc/net/udp", 13);
    char *large = read_chunks("/proc/net/udp", 65536);
    if (strcmp(small, large)) { fprintf(stderr, "offset reads differ\n"); exit(1); }
    for (int i = 0; i < COUNT; i++) {
        int found = occurrences(small, 9, ids[i], NULL);
        if (found != 1) { fprintf(stderr, "udp %d count=%d\n", i, found); exit(1); }
    }
    static struct entry entries[512];
    int err, count = diag_dump(AF_INET, IPPROTO_UDP, ~0U, 0, entries, 512, &err);
    if (err || count < COUNT) { fprintf(stderr, "udp diag count=%d err=%d\n", count, err); exit(1); }
    for (int i = 0; i < COUNT; i++) {
        int found = 0;
        for (int j = 0; j < count; j++) {
            if (entries[j].m.idiag_inode == ids[i]) {
                if (entries[j].m.idiag_uid != getuid()) { fprintf(stderr, "udp diag uid mismatch\n"); exit(1); }
                found++;
            }
        }
        if (found != 1) { fprintf(stderr, "udp diag %d count=%d\n", i, found); exit(1); }
    }
    free(small); free(large);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (getsockname(fds[0], (void *)&addr, &len)) fail("getsockname");
    close(fds[0]);
    require_entry("/proc/net/udp", 9, ids[0], NULL, 0);
    int replacement = udp4(ntohs(addr.sin_port));
    unsigned long long replacement_id = inode(replacement);
    if (replacement_id == ids[0]) { fprintf(stderr, "inode reused during rebind\n"); exit(1); }
    require_entry("/proc/net/udp", 9, replacement_id, NULL, 1);
    close(replacement);
    for (int i = 1; i < COUNT; i++) close(fds[i]);
}

static void unix_and_netlink(void)
{
    int pathfd = socket(AF_UNIX, SOCK_STREAM, 0), absfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (pathfd < 0 || absfd < 0) fail("unix socket");
    struct sockaddr_un path = { .sun_family = AF_UNIX }, abstract = { .sun_family = AF_UNIX };
    snprintf(path.sun_path, sizeof(path.sun_path), "/tmp/proc-net-%ld", (long)getpid());
    snprintf(abstract.sun_path + 1, sizeof(abstract.sun_path) - 1, "proc-net-%ld", (long)getpid());
    char name[sizeof(abstract.sun_path)];
    snprintf(name, sizeof(name), "@%s", abstract.sun_path + 1);
    if (bind(pathfd, (void *)&path, sizeof(path)) ||
        bind(absfd, (void *)&abstract, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(abstract.sun_path + 1))) fail("unix bind");
    unsigned long long pathid = inode(pathfd), absid = inode(absfd);
    require_entry("/proc/net/unix", 6, pathid, path.sun_path, 1);
    require_entry("/proc/net/unix", 6, absid, name, 1);
    close(pathfd); close(absfd);
    require_entry("/proc/net/unix", 6, pathid, NULL, 0);
    require_entry("/proc/net/unix", 6, absid, NULL, 0);
    if (unlink(path.sun_path)) fail("unlink");
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl < 0) fail("netlink socket");
    unsigned long long nlid = inode(nl);
    require_entry("/proc/net/netlink", 9, nlid, NULL, 0);
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    if (bind(nl, (void *)&addr, sizeof(addr))) fail("netlink bind");
    require_entry("/proc/net/netlink", 9, nlid, NULL, 1);
    close(nl);
    require_entry("/proc/net/netlink", 9, nlid, NULL, 0);
}

static void ipv6(void)
{
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)) { puts("ipv6 unsupported"); return; }
    if (fd < 0) fail("ipv6 socket");
    struct sockaddr_in6 addr = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
    if (bind(fd, (void *)&addr, sizeof(addr)) || listen(fd, 1)) fail("ipv6 listen");
    require_entry("/proc/net/tcp6", 9, inode(fd), NULL, 1);
    puts("ipv6 tcp listener found");
    close(fd);
}

static void require_datagram_state(int fd, unsigned int expected)
{
    unsigned long long wanted = inode(fd), found;
    char *text = read_chunks("/proc/net/unix", 37), *save;
    for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        unsigned int kind, state;
        if (sscanf(line, "%*s %*s %*s %*s %x %x %llu", &kind, &state, &found) == 3 && found == wanted) {
            free(text);
            if (kind != SOCK_DGRAM || state != expected) {
                fprintf(stderr, "unix datagram state=%u expected=%u kind=%u\n", state, expected, kind);
                exit(1);
            }
            return;
        }
    }
    free(text);
    fail("unix datagram missing");
}

static void datagram_states(void)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0), pair[2];
    if (fd < 0 || socketpair(AF_UNIX, SOCK_DGRAM, 0, pair)) fail("unix datagram");
    require_datagram_state(fd, 1);
    require_datagram_state(pair[0], 3);
    require_datagram_state(pair[1], 3);
    close(pair[0]); close(pair[1]); close(fd);
}

static atomic_bool stop_churn;
static atomic_uint churn_cycles;

static void *churn(void *unused)
{
    (void)unused;
    while (!atomic_load(&stop_churn)) {
        int fd = udp4(0);
        close(fd);
        atomic_fetch_add(&churn_cycles, 1);
    }
    return NULL;
}

static void concurrent_reads(void)
{
    pthread_t thread;
    atomic_store(&stop_churn, false);
    atomic_store(&churn_cycles, 0);
    if (pthread_create(&thread, NULL, churn, NULL)) fail("pthread_create");
    while (atomic_load(&churn_cycles) == 0) sched_yield();
    for (int index = 0; index < 20; index++) {
        char *text = read_chunks("/proc/net/udp", 37);
        free(text);
        struct entry entries[8];
        int error;
        int count = diag_dump(AF_INET, IPPROTO_UDP, 0, 0, entries, 8, &error);
        if (error || count != 0) fail("filtered UDP dump during churn");
    }
    atomic_store(&stop_churn, true);
    if (pthread_join(thread, NULL)) fail("pthread_join");
    printf("concurrent socket enumeration passed with %u close/rebind cycles\n", atomic_load(&churn_cycles));
}

int main(void)
{
    alarm(15);
    udp_many();
    unix_and_netlink();
    ipv6();
    datagram_states();
    concurrent_reads();
    puts("proc_net_identity PASS");
    return 0;
}
