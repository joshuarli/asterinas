// SPDX-License-Identifier: MPL-2.0

#include "sock_diag.h"
#include <sys/stat.h>

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); return 1; } } while (0)

static struct entry *find(struct entry *e, int n, unsigned short sport, unsigned short dport)
{
    for (int i = 0; i < n; i++)
        if (e[i].m.id.idiag_sport == sport && e[i].m.id.idiag_dport == dport) return &e[i];
    return NULL;
}

int main(void)
{
    int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0), idle = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) }, connected;
    socklen_t len = sizeof(addr);
    CHECK(a >= 0 && b >= 0 && idle >= 0);
    CHECK(bind(a, (void *)&addr, len) == 0 && getsockname(a, (void *)&addr, &len) == 0);
    CHECK(connect(b, (void *)&addr, len) == 0);
    len = sizeof(connected);
    CHECK(getsockname(b, (void *)&connected, &len) == 0);
    struct stat sa, sb;
    CHECK(fstat(a, &sa) == 0 && fstat(b, &sb) == 0);

    static struct entry e[256];
    int err, n;
    n = diag_dump(AF_INET, IPPROTO_UDP, ~0U, 0, e, 256, &err);
    CHECK(n >= 2 && err == 0);
    struct entry *ea = find(e, n, addr.sin_port, 0), *eb = find(e, n, connected.sin_port, addr.sin_port);
    CHECK(ea && eb);
    CHECK(ea->m.idiag_family == AF_INET && ea->m.idiag_state == 7);
    CHECK(eb->m.idiag_family == AF_INET && eb->m.idiag_state == 1);
    CHECK(ea->m.idiag_inode == sa.st_ino && eb->m.idiag_inode == sb.st_ino);
    CHECK(ea->m.idiag_uid == getuid() && eb->m.idiag_uid == getuid());
    CHECK(ea->m.id.idiag_src[0] == addr.sin_addr.s_addr && eb->m.id.idiag_dst[0] == addr.sin_addr.s_addr);
    CHECK(eb->m.id.idiag_src[0] == addr.sin_addr.s_addr);
    CHECK(ea->m.idiag_rqueue == 0 && ea->m.idiag_wqueue == 0 && eb->m.idiag_rqueue == 0);
    CHECK(ea->m.id.idiag_cookie[0] != 0 || ea->m.id.idiag_cookie[1] != 0);
    CHECK(ea->m.id.idiag_cookie[0] != eb->m.id.idiag_cookie[0] || ea->m.id.idiag_cookie[1] != eb->m.id.idiag_cookie[1]);

    n = diag_dump(AF_INET, IPPROTO_UDP, 1 << 7, 0, e, 256, &err);
    CHECK(err == 0 && find(e, n, addr.sin_port, 0) && !find(e, n, connected.sin_port, addr.sin_port));
    n = diag_dump(AF_INET, IPPROTO_UDP, 1 << 1, 0, e, 256, &err);
    CHECK(err == 0 && !find(e, n, addr.sin_port, 0) && find(e, n, connected.sin_port, addr.sin_port));
    n = diag_dump(AF_INET, IPPROTO_UDP, 0, 0, e, 256, &err);
    CHECK(err == 0 && n == 0);
    n = diag_dump(AF_INET6, IPPROTO_UDP, ~0U, 0, e, 256, &err);
    CHECK(err == 0 && n >= 0);
    CHECK(!find(e, n, addr.sin_port, 0));

    CHECK(send(b, "0123456789", 10, 0) == 10);
    for (int tries = 0; tries < 100; tries++) {
        n = diag_dump(AF_INET, IPPROTO_UDP, ~0U, 0, e, 256, &err);
        ea = find(e, n, addr.sin_port, 0);
        if (ea && ea->m.idiag_rqueue) break;
        usleep(10000);
    }
    CHECK(ea && ea->m.idiag_rqueue >= 10);
    char buf[64];
    CHECK(recv(a, buf, sizeof(buf), 0) == 10);
    n = diag_dump(AF_INET, IPPROTO_UDP, ~0U, 0, e, 256, &err);
    ea = find(e, n, addr.sin_port, 0);
    CHECK(ea && ea->m.idiag_rqueue == 0);

    close(b);
    n = diag_dump(AF_INET, IPPROTO_UDP, ~0U, 0, e, 256, &err);
    CHECK(!find(e, n, connected.sin_port, addr.sin_port));
    close(a);
    n = diag_dump(AF_INET, IPPROTO_UDP, ~0U, 0, e, 256, &err);
    CHECK(!find(e, n, addr.sin_port, 0));
    puts("ok");
    return 0;
}
