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
    int l6 = socket(AF_INET6, SOCK_STREAM, 0), a6 = socket(AF_INET6, SOCK_STREAM, 0), l4 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in6 loop = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT }, any = { .sin6_family = AF_INET6 };
    struct sockaddr_in s4 = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof(loop);
    CHECK(bind(l6, (void *)&loop, sizeof(loop)) == 0 && listen(l6, 4) == 0 && getsockname(l6, (void *)&loop, &len) == 0);
    len = sizeof(any);
    int have_any = bind(a6, (void *)&any, sizeof(any)) == 0 && listen(a6, 4) == 0 && getsockname(a6, (void *)&any, &len) == 0;
    len = sizeof(s4);
    CHECK(bind(l4, (void *)&s4, sizeof(s4)) == 0 && listen(l4, 4) == 0 && getsockname(l4, (void *)&s4, &len) == 0);
    int c6 = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(connect(c6, (void *)&loop, sizeof(loop)) == 0);
    struct sockaddr_in6 client;
    len = sizeof(client);
    CHECK(getsockname(c6, (void *)&client, &len) == 0);
    int acc = accept(l6, NULL, NULL);
    CHECK(acc >= 0);

    static struct entry e[256];
    int err, n = diag_dump(AF_INET6, IPPROTO_TCP, ~0U, 0, e, 256, &err), alen;
    CHECK(n >= 3 && err == 0);
    struct entry *el = find(e, n, loop.sin6_port, 0), *ea = NULL;
    struct entry *ec = find(e, n, client.sin6_port, loop.sin6_port), *es = find(e, n, loop.sin6_port, client.sin6_port);
    CHECK(el && ec && es);
    unsigned char *v = find_attr(el, 11, &alen);
    CHECK(v && alen == 1 && *v == 1);
    if (have_any) {
        ea = find(e, n, any.sin6_port, 0);
        v = find_attr(ea, 11, &alen);
        CHECK(v && alen == 1 && *v == 0);
    }
    CHECK(!find_attr(ec, 11, NULL) && !find_attr(es, 11, NULL));
    n = diag_dump(AF_INET, IPPROTO_TCP, ~0U, 0, e, 256, &err);
    struct entry *e4 = find(e, n, s4.sin_port, 0);
    CHECK(e4 && !find_attr(e4, 11, NULL));
    puts("ok");
    return 0;
}
