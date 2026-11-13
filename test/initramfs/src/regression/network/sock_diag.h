// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct entry {
    struct inet_diag_msg m;
    unsigned char attrs[1024];
    int attr_len;
};

static int diag_dump(int family, int proto, unsigned states, unsigned ext, struct entry *out, int max, int *err)
{
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    struct { struct nlmsghdr h; struct inet_diag_req_v2 r; } req;
    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len = sizeof(req);
    req.h.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.r.sdiag_family = family;
    req.r.sdiag_protocol = proto;
    req.r.idiag_ext = ext;
    req.r.idiag_states = states;
    req.r.id.idiag_cookie[0] = req.r.id.idiag_cookie[1] = ~0U;
    int count = 0, done = 0;
    *err = 0;
    if (nl < 0 || send(nl, &req, sizeof(req), 0) != sizeof(req)) { *err = errno; return -1; }
    while (!done) {
        static char buf[65536];
        int n = recv(nl, buf, sizeof(buf), 0);
        if (n <= 0) { *err = errno; close(nl); return -1; }
        for (struct nlmsghdr *h = (void *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                if (h->nlmsg_len >= NLMSG_LENGTH(sizeof(int))) *err = -*(int *)NLMSG_DATA(h);
                done = 1; break;
            }
            if (h->nlmsg_type == NLMSG_ERROR) { *err = -((struct nlmsgerr *)NLMSG_DATA(h))->error; done = 1; break; }
            if (count < max) {
                memcpy(&out[count].m, NLMSG_DATA(h), sizeof(struct inet_diag_msg));
                out[count].attr_len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct inet_diag_msg));
                if (out[count].attr_len > (int)sizeof(out[count].attrs)) out[count].attr_len = sizeof(out[count].attrs);
                memcpy(out[count].attrs, (char *)NLMSG_DATA(h) + sizeof(struct inet_diag_msg), out[count].attr_len);
                count++;
            }
        }
    }
    close(nl);
    return count;
}

__attribute__((unused)) static unsigned char *find_attr(struct entry *e, int type, int *len)
{
    int off = 0;
    while (off + 4 <= e->attr_len) {
        unsigned short l = *(unsigned short *)(e->attrs + off), t = *(unsigned short *)(e->attrs + off + 2) & 0x3fff;
        if (l < 4 || off + l > e->attr_len) break;
        if (t == type) { if (len) *len = l - 4; return e->attrs + off + 4; }
        off += (l + 3) & ~3;
    }
    return NULL;
}

__attribute__((unused)) static void print_entry(const char *tag, struct entry *e)
{
    printf("%s fam=%d state=%d sport=%u dport=%u rq=%u wq=%u uid=%u ino=%u ifindex=%u attrs=[", tag, e->m.idiag_family, e->m.idiag_state,
           ntohs(e->m.id.idiag_sport), ntohs(e->m.id.idiag_dport), e->m.idiag_rqueue, e->m.idiag_wqueue, e->m.idiag_uid, e->m.idiag_inode, e->m.id.idiag_if);
    int off = 0;
    while (off + 4 <= e->attr_len) {
        unsigned short l = *(unsigned short *)(e->attrs + off), t = *(unsigned short *)(e->attrs + off + 2) & 0x3fff;
        if (l < 4 || off + l > e->attr_len) break;
        printf("%d(%d)", t, l - 4);
        if (l == 5) printf("=%d", e->attrs[off + 4]);
        printf(" ");
        off += (l + 3) & ~3;
    }
    printf("]\n");
}
