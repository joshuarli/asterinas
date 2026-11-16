// SPDX-License-Identifier: MPL-2.0
#include "sock_diag.h"
#include <stdint.h>
#include <sys/wait.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL uid=%u line=%d: %s errno=%d\n", getuid(), __LINE__, #c, errno); return 1; } } while (0)

static uint32_t u32(const unsigned char *p, int offset) { uint32_t v; memcpy(&v, p + offset, sizeof(v)); return v; }
static uint64_t u64(const unsigned char *p, int offset) { uint64_t v; memcpy(&v, p + offset, sizeof(v)); return v; }

static int run(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0), client = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) }, c;
    socklen_t len = sizeof(a);
    CHECK(listener >= 0 && client >= 0);
    CHECK(bind(listener, (void *)&a, len) == 0 && listen(listener, 4) == 0 && getsockname(listener, (void *)&a, &len) == 0);
    CHECK(connect(client, (void *)&a, len) == 0);
    int server = accept(listener, NULL, NULL);
    CHECK(server >= 0);
    CHECK(setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) == 0);
    len = sizeof(c);
    CHECK(getsockname(client, (void *)&c, &len) == 0);
    char data[100] = {0};
    CHECK(send(client, data, sizeof(data), 0) == 100);
    static struct entry entries[256];
    int err = 0, n = 0, alen = 0;
    struct entry *tx = NULL, *rx = NULL;
    unsigned char *info = NULL;
    for (int tries = 0; tries < 300; tries++) {
        n = diag_dump(AF_INET, IPPROTO_TCP, ~0U, (1 << (INET_DIAG_INFO - 1)) | (1 << (INET_DIAG_CONG - 1)), entries, 256, &err);
        CHECK(n >= 0 && err == 0);
        tx = NULL; rx = NULL;
        for (int i = 0; i < n; i++) {
            if (entries[i].m.id.idiag_sport == c.sin_port && entries[i].m.id.idiag_dport == a.sin_port) tx = &entries[i];
            if (entries[i].m.id.idiag_sport == a.sin_port && entries[i].m.id.idiag_dport == c.sin_port) rx = &entries[i];
        }
        info = tx ? find_attr(tx, INET_DIAG_INFO, &alen) : NULL;
        if (info && alen >= 208 && u64(info, 200) >= 100 && tx->m.idiag_timer == 2 && rx && rx->m.idiag_rqueue == 100) break;
        usleep(10000);
    }
    CHECK(tx && rx && info && alen >= 208);
    int clen;
    unsigned char *cong = find_attr(tx, INET_DIAG_CONG, &clen);
    CHECK(cong && clen > 1 && cong[clen - 1] == 0 && strlen((char *)cong) > 0);
    CHECK(u64(info, 200) == 100 && u32(info, 8) && u32(info, 16) && u32(info, 68) && u32(info, 80));
    CHECK(u64(info, 104) && u64(info, 112) == UINT64_MAX);
    CHECK(tx->m.idiag_timer == 2 && tx->m.idiag_expires > 0);
    int rxlen;
    unsigned char *ri = find_attr(rx, INET_DIAG_INFO, &rxlen);
    CHECK(ri && rxlen >= 136 && u64(ri, 128) == 100 && u32(ri, 20) == 536);
    printf("TELEMETRY_OK uid=%u cong=%s sent=%llu received=%llu timer=%u expires=%u\n", getuid(), cong, (unsigned long long)u64(info, 200), (unsigned long long)u64(ri, 128), tx->m.idiag_timer, tx->m.idiag_expires);
    close(server); close(client); close(listener);
    return 0;
}

int main(void)
{
    if (run()) return 1;
    fflush(stdout);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) { if (setgid(1000) || setuid(1000)) _exit(1); int rc = run(); fflush(stdout); _exit(rc); }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("ok");
    return 0;
}
