// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL uid=%u line=%d: %s errno=%d\n", getuid(), __LINE__, #c, errno); return 1; } } while (0)
struct item { struct unix_diag_msg msg; unsigned char attrs[1024]; int len; };
static struct item items[1024];
static int query(unsigned states, unsigned inode, int dump)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    struct { struct nlmsghdr h; struct unix_diag_req r; } req = {0};
    req.h.nlmsg_len = sizeof(req); req.h.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.h.nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0);
    req.r.sdiag_family = AF_UNIX; req.r.udiag_states = states; req.r.udiag_ino = inode;
    req.r.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_VFS | UDIAG_SHOW_PEER | UDIAG_SHOW_ICONS | UDIAG_SHOW_RQLEN | UDIAG_SHOW_MEMINFO | UDIAG_SHOW_UID;
    req.r.udiag_cookie[0] = req.r.udiag_cookie[1] = ~0U;
    if (fd < 0 || send(fd, &req, sizeof(req), 0) != sizeof(req)) return -1;
    int count = 0, done = 0;
    while (!done) {
        char buf[65536]; int n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) { close(fd); return -1; }
        for (struct nlmsghdr *h = (void *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE) { if (h->nlmsg_len >= NLMSG_LENGTH(sizeof(int)) && *(int *)NLMSG_DATA(h)) { printf("DIAG_DONE_ERROR %d\n", *(int *)NLMSG_DATA(h)); close(fd); return -1; } done = 1; break; }
            if (h->nlmsg_type == NLMSG_ERROR) { printf("DIAG_ERROR %d\n", ((struct nlmsgerr *)NLMSG_DATA(h))->error); close(fd); return -1; }
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct unix_diag_msg)) || count == 1024) { close(fd); return -1; }
            struct item *e = &items[count++];
            memcpy(&e->msg, NLMSG_DATA(h), sizeof(e->msg));
            e->len = h->nlmsg_len - NLMSG_LENGTH(sizeof(e->msg));
            if (e->len > (int)sizeof(e->attrs)) { close(fd); return -1; }
            memcpy(e->attrs, (char *)NLMSG_DATA(h) + sizeof(e->msg), e->len);
            if (!dump) done = 1;
        }
    }
    close(fd); return count;
}
static struct item *find(unsigned inode, int count)
{
    for (int i = 0; i < count; i++) if (items[i].msg.udiag_ino == inode) return &items[i];
    return NULL;
}
static unsigned char *attr(struct item *e, int type, int *size)
{
    for (int off = 0; off + 4 <= e->len;) {
        uint16_t len, kind; memcpy(&len, e->attrs + off, 2); memcpy(&kind, e->attrs + off + 2, 2);
        if (len < 4 || off + len > e->len) return NULL;
        if ((kind & 0x3fff) == type) { *size = len - 4; return e->attrs + off + 4; }
        off += (len + 3) & ~3;
    }
    return NULL;
}
static uint32_t number(const unsigned char *p) { uint32_t n; memcpy(&n, p, 4); return n; }
static int run(void)
{
    int listener = socket(AF_UNIX, SOCK_STREAM, 0), client = socket(AF_UNIX, SOCK_STREAM, 0), spare = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0 && client >= 0 && spare >= 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof(a.sun_path), "/tmp/lap62-%u-%u", getuid(), getpid());
    unlink(a.sun_path);
    CHECK(bind(listener, (void *)&a, sizeof(a)) == 0 && listen(listener, 4) == 0);
    CHECK(connect(client, (void *)&a, sizeof(a)) == 0);
    int server = accept(listener, NULL, NULL); CHECK(server >= 0);
    struct stat st[4]; int fds[] = {listener, client, server, spare};
    for (int i = 0; i < 4; i++) CHECK(fstat(fds[i], &st[i]) == 0);
    int dgram = socket(AF_UNIX, SOCK_DGRAM, 0), pair[2];
    CHECK(dgram >= 0 && socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
    struct sockaddr_un da = { .sun_family = AF_UNIX };
    snprintf(da.sun_path, sizeof(da.sun_path), "/tmp/lap62-d-%u-%u", getuid(), getpid());
    unlink(da.sun_path);
    CHECK(bind(dgram, (void *)&da, sizeof(da)) == 0);
    struct stat ds[3], pathstat; int dfds[] = { dgram, pair[0], pair[1] };
    for (int i = 0; i < 3; i++) CHECK(fstat(dfds[i], &ds[i]) == 0);
    CHECK(stat(da.sun_path, &pathstat) == 0);
    CHECK(send(pair[0], "abc", 3, 0) == 3);
    CHECK(shutdown(client, SHUT_WR) == 0);
    int n = query(~0U, 0, 1); CHECK(n >= 0);
    for (int i = 0; i < 4; i++) {
        struct item *e = find(st[i].st_ino, n); CHECK(e && e->msg.udiag_family == AF_UNIX && e->msg.udiag_type == SOCK_STREAM);
        CHECK(e->msg.udiag_state == (i == 0 ? 10 : i == 3 ? 7 : 1));
        int len = 0; unsigned char *p = attr(e, UNIX_DIAG_RQLEN, &len); CHECK(p && len == 8 && number(p) == 0);
        if (i == 0) CHECK(number(p + 4) == 4);
        p = attr(e, UNIX_DIAG_SHUTDOWN, &len); CHECK(p && len == 1 && (i != 1 || (p[0] & 2)));
        p = attr(e, UNIX_DIAG_PEER, &len);
        if (i == 1 || i == 2) CHECK(p && len == 4 && number(p) == st[i == 1 ? 2 : 1].st_ino);
        else CHECK(!p);
        p = attr(e, UNIX_DIAG_NAME, &len);
        if (i == 0 || i == 2) CHECK(p && len >= (int)strlen(a.sun_path) && !memcmp(p, a.sun_path, strlen(a.sun_path)));
        else CHECK(!p);
    }
    for (int i = 0; i < 3; i++) {
        struct item *e = find(ds[i].st_ino, n); CHECK(e && e->msg.udiag_type == SOCK_DGRAM);
        CHECK(e->msg.udiag_state == (i == 0 ? 7 : 1));
        int len = 0; unsigned char *p = attr(e, UNIX_DIAG_PEER, &len);
        if (i) CHECK(p && len == 4 && number(p) == ds[i == 1 ? 2 : 1].st_ino); else CHECK(!p);
        p = attr(e, UNIX_DIAG_RQLEN, &len); CHECK(p && len == 8 && number(p) == (i == 2 ? 3 : 0));
        p = attr(e, UNIX_DIAG_UID, &len); CHECK(p && len == 4 && number(p) == getuid());
        p = attr(e, UNIX_DIAG_VFS, &len);
        if (!i) CHECK(p && len == 8 && number(p) == (uint32_t)pathstat.st_ino); else CHECK(!p);
        p = attr(e, UNIX_DIAG_MEMINFO, &len); CHECK(p && len == 36 && number(p + 4) && number(p + 12));
    }
    close(pair[0]); close(pair[1]); close(dgram); unlink(da.sun_path);
    n = query(1U << 10, 0, 1); CHECK(n >= 0 && find(st[0].st_ino, n) && !find(st[1].st_ino, n) && !find(st[3].st_ino, n));
    n = query(0, st[1].st_ino, 0); CHECK(n == 1 && items[0].msg.udiag_ino == st[1].st_ino);
    printf("UNIX_DIAG_OK uid=%u\n", getuid());
    close(server); close(client); close(listener); close(spare); unlink(a.sun_path); return 0;
}
int main(void)
{
    if (run()) return 1;
    fflush(stdout); pid_t child = fork(); CHECK(child >= 0);
    if (!child) { if (setgid(1000) || setuid(1000)) _exit(1); int rc = run(); fflush(stdout); _exit(rc); }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("ok"); return 0;
}
