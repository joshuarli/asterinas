// SPDX-License-Identifier: MPL-2.0

#include "sock_diag.h"

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); return 1; } } while (0)

static struct entry *find(struct entry *e, int n, unsigned short sport, unsigned short dport)
{
    for (int i = 0; i < n; i++)
        if (e[i].m.id.idiag_sport == sport && e[i].m.id.idiag_dport == dport) return &e[i];
    return NULL;
}

int main(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0), client = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof(a);
    CHECK(bind(listener, (void *)&a, len) == 0 && listen(listener, 4) == 0 && getsockname(listener, (void *)&a, &len) == 0);
    CHECK(connect(client, (void *)&a, len) == 0);
    int server = accept(listener, NULL, NULL);
    CHECK(server >= 0);
    struct sockaddr_in c;
    len = sizeof(c);
    CHECK(getsockname(client, (void *)&c, &len) == 0);
    char data[100] = {0};
    CHECK(send(client, data, sizeof(data), 0) == 100);
    int u = socket(AF_INET, SOCK_DGRAM, 0), v = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ua = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    len = sizeof(ua);
    CHECK(bind(u, (void *)&ua, len) == 0 && getsockname(u, (void *)&ua, &len) == 0);
    CHECK(connect(v, (void *)&ua, len) == 0 && send(v, data, 10, 0) == 10);

    static struct entry e[256];
    int err, n, alen;
    for (int tries = 0; tries < 200; tries++) {
        n = diag_dump(AF_INET, IPPROTO_TCP, ~0U, 0, e, 256, &err);
        struct entry *r = find(e, n, a.sin_port, c.sin_port);
        if (r && r->m.idiag_rqueue == 100) break;
        usleep(10000);
    }
    n = diag_dump(AF_INET, IPPROTO_TCP, ~0U, 0, e, 256, &err);
    struct entry *plain = find(e, n, a.sin_port, c.sin_port);
    CHECK(plain && !find_attr(plain, 7, NULL) && !find_attr(plain, 1, NULL));
    n = diag_dump(AF_INET, IPPROTO_TCP, ~0U, 0x41, e, 256, &err);
    struct entry *rx = find(e, n, a.sin_port, c.sin_port), *tx = find(e, n, c.sin_port, a.sin_port), *ls = find(e, n, a.sin_port, 0);
    CHECK(rx && tx && ls);
    unsigned *sk = (unsigned *)find_attr(rx, 7, &alen);
    CHECK(sk && alen == 36);
    CHECK(sk[0] >= 100 && sk[1] > 0 && sk[3] > 0);
    unsigned *mi = (unsigned *)find_attr(rx, 1, &alen);
    CHECK(mi && alen == 16);
    sk = (unsigned *)find_attr(tx, 7, &alen);
    CHECK(sk && alen == 36 && sk[0] == 0 && sk[1] > 0 && sk[3] > 0);
    sk = (unsigned *)find_attr(ls, 7, &alen);
    CHECK(sk && alen == 36 && sk[0] == 0 && sk[1] > 0 && sk[3] > 0);

    for (int tries = 0; tries < 200; tries++) {
        n = diag_dump(AF_INET, IPPROTO_UDP, ~0U, 0x40, e, 256, &err);
        struct entry *r = find(e, n, ua.sin_port, 0);
        if (r && r->m.idiag_rqueue) break;
        usleep(10000);
    }
    struct entry *ur = find(e, n, ua.sin_port, 0);
    CHECK(ur);
    sk = (unsigned *)find_attr(ur, 7, &alen);
    CHECK(sk && alen == 36 && sk[0] >= 10 && sk[1] > 0 && sk[3] > 0);
    puts("ok");
    return 0;
}
