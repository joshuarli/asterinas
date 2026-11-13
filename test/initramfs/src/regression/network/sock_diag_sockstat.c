// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); return 1; } } while (0)

struct stat_set { long used, tcp_inuse, tcp_orphan, tcp_tw, tcp_alloc, udp_inuse, raw_inuse, frag_inuse, tcp6_inuse, udp6_inuse; };

static long field(const char *text, const char *section, const char *key)
{
    size_t n = strlen(section);
    for (const char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (strncmp(line, section, n) != 0 || line[n] != ':') continue;
        const char *end = strchr(line, '\n');
        const char *p = line;
        size_t kl = strlen(key);
        while (p < (end ? end : line + strlen(line))) {
            if ((p == line || p[-1] == ' ') && strncmp(p, key, kl) == 0 && p[kl] == ' ') return strtol(p + kl + 1, NULL, 10);
            p++;
        }
    }
    return -1;
}

static int slurp(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, size - 1, f);
    buf[n] = 0;
    fclose(f);
    return 0;
}

static int read_stats(struct stat_set *s)
{
    static char v4[4096], v6[4096];
    if (slurp("/proc/net/sockstat", v4, sizeof(v4)) || slurp("/proc/net/sockstat6", v6, sizeof(v6))) return -1;
    if (strncmp(v4, "sockets: used ", 14) != 0) return -1;
    s->used = field(v4, "sockets", "used");
    s->tcp_inuse = field(v4, "TCP", "inuse");
    s->tcp_orphan = field(v4, "TCP", "orphan");
    s->tcp_tw = field(v4, "TCP", "tw");
    s->tcp_alloc = field(v4, "TCP", "alloc");
    s->udp_inuse = field(v4, "UDP", "inuse");
    s->raw_inuse = field(v4, "RAW", "inuse");
    s->frag_inuse = field(v4, "FRAG", "inuse");
    s->tcp6_inuse = field(v6, "TCP6", "inuse");
    s->udp6_inuse = field(v6, "UDP6", "inuse");
    return 0;
}

int main(void)
{
    struct stat_set base, now;
    CHECK(read_stats(&base) == 0);
    CHECK(base.used >= 0 && base.tcp_inuse >= 0 && base.tcp_orphan >= 0 && base.tcp_tw >= 0 && base.tcp_alloc >= 0);
    CHECK(base.udp_inuse >= 0 && base.raw_inuse >= 0 && base.frag_inuse >= 0 && base.tcp6_inuse >= 0 && base.udp6_inuse >= 0);

    int listener = socket(AF_INET, SOCK_STREAM, 0), client = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof(a);
    CHECK(bind(listener, (void *)&a, len) == 0 && listen(listener, 4) == 0 && getsockname(listener, (void *)&a, &len) == 0);
    CHECK(connect(client, (void *)&a, len) == 0);
    int server = accept(listener, NULL, NULL);
    CHECK(server >= 0);
    CHECK(read_stats(&now) == 0);
    CHECK(now.tcp_inuse - base.tcp_inuse == 3);
    CHECK(now.tcp_alloc - base.tcp_alloc == 3);
    CHECK(now.used - base.used >= 3);

    int unbound = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(unbound >= 0);
    CHECK(read_stats(&now) == 0);
    CHECK(now.udp_inuse == base.udp_inuse && now.used - base.used >= 4);
    struct sockaddr_in u = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    CHECK(bind(unbound, (void *)&u, sizeof(u)) == 0);
    CHECK(read_stats(&now) == 0);
    CHECK(now.udp_inuse - base.udp_inuse == 1);
    close(unbound);
    CHECK(read_stats(&now) == 0);
    CHECK(now.udp_inuse == base.udp_inuse);

    int six = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 loop = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
    CHECK(bind(six, (void *)&loop, sizeof(loop)) == 0 && listen(six, 4) == 0);
    CHECK(read_stats(&now) == 0);
    CHECK(now.tcp6_inuse - base.tcp6_inuse == 1);
    CHECK(now.tcp_inuse - base.tcp_inuse == 3);
    close(six);

    close(client);
    close(server);
    int seen = 0;
    for (int tries = 0; tries < 200 && !seen; tries++) {
        CHECK(read_stats(&now) == 0);
        if (now.tcp_tw - base.tcp_tw == 1) seen = 1; else usleep(10000);
    }
    CHECK(seen);
    CHECK(now.tcp_inuse - base.tcp_inuse == 1);
    CHECK(now.tcp_alloc - base.tcp_alloc == 1);
    close(listener);
    CHECK(read_stats(&now) == 0);
    CHECK(now.tcp_inuse == base.tcp_inuse && now.tcp_alloc == base.tcp_alloc);
    puts("ok");
    return 0;
}
