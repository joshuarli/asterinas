// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int64_t milliseconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int query(int type, const char *name, uint16_t id, int expected, size_t padding, unsigned int request_flags)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char attrs[60000];
    } req = {0};
    char buf[8192];
    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    socklen_t addrlen = sizeof(local);
    struct pollfd pfd;
    int fd = -1, result = -1, found = 0, ack = 0;
    ssize_t len;
    int64_t deadline = milliseconds() + 1000;

    fd = socket(AF_NETLINK, type, NETLINK_GENERIC);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
        getsockname(fd, (struct sockaddr *)&local, &addrlen))
        goto out;
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | request_flags;
    req.n.nlmsg_seq = 123;
    req.g.cmd = CTRL_CMD_GETFAMILY;
    if (name || id) {
        struct nlattr *a = (struct nlattr *)((char *)&req + req.n.nlmsg_len);
        size_t payload = name ? strlen(name) + 1 : sizeof(id);
        a->nla_type = name ? CTRL_ATTR_FAMILY_NAME : CTRL_ATTR_FAMILY_ID;
        a->nla_len = (uint16_t)(sizeof(*a) + payload);
        memcpy((char *)a + sizeof(*a), name ? (const void *)name : (const void *)&id, payload);
        req.n.nlmsg_len += NLA_ALIGN(a->nla_len);
    }
    if (padding) {
        struct nlattr *a = (struct nlattr *)((char *)&req + req.n.nlmsg_len);
        if (padding > 40000) goto out;
        a->nla_type = CTRL_ATTR_MAX + 1;
        a->nla_len = (uint16_t)(sizeof(*a) + padding);
        req.n.nlmsg_len += NLA_ALIGN(a->nla_len);
    }
    if (sendto(fd, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) != (ssize_t)req.n.nlmsg_len)
        goto out;
    pfd.fd = fd;
    pfd.events = POLLIN;
    while (!ack) {
        struct sockaddr_nl from;
        socklen_t fromlen = sizeof(from);
        int rem;
        int64_t left_ms = deadline - milliseconds();
        if (left_ms <= 0 || poll(&pfd, 1, (int)left_ms) != 1 || !(pfd.revents & POLLIN))
            goto out;
        len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (len < 0 || from.nl_pid != 0)
            goto out;
        rem = (int)len;
        for (struct nlmsghdr *n = (struct nlmsghdr *)buf; NLMSG_OK(n, rem); n = NLMSG_NEXT(n, rem)) {
            if (n->nlmsg_seq != 123 || n->nlmsg_pid != local.nl_pid)
                goto out;
            if (n->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(n);
                if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*e)) || e->error != -expected || e->msg.nlmsg_seq != 123)
                    goto out;
                ack = 1;
            } else if (n->nlmsg_type == GENL_ID_CTRL && n->nlmsg_len >= NLMSG_LENGTH(GENL_HDRLEN)) {
                struct genlmsghdr *g = NLMSG_DATA(n);
                int left = (int)n->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
                char *p = (char *)g + GENL_HDRLEN;
                int got_name = 0, got_id = 0, got_version = 0, got_hdr = 0, got_max = 0, got_ops = 0;
                if (g->cmd != CTRL_CMD_NEWFAMILY)
                    goto out;
                while (left >= (int)sizeof(struct nlattr)) {
                    struct nlattr *a = (struct nlattr *)p;
                    int step = NLA_ALIGN(a->nla_len);
                    if (a->nla_len < sizeof(*a) || step > left)
                        goto out;
                    if (a->nla_type == CTRL_ATTR_FAMILY_NAME && a->nla_len == sizeof(*a) + 7 && !memcmp(p + sizeof(*a), "nlctrl", 7)) got_name = 1;
                    if (a->nla_type == CTRL_ATTR_FAMILY_ID && a->nla_len == sizeof(*a) + 2) { uint16_t v; memcpy(&v, p + sizeof(*a), 2); got_id = v == 16; }
                    if (a->nla_type == CTRL_ATTR_VERSION && a->nla_len == sizeof(*a) + 4) { uint32_t v; memcpy(&v, p + sizeof(*a), 4); got_version = v == 2; }
                    if (a->nla_type == CTRL_ATTR_HDRSIZE && a->nla_len == sizeof(*a) + 4) { uint32_t v; memcpy(&v, p + sizeof(*a), 4); got_hdr = v == 0; }
                    if (a->nla_type == CTRL_ATTR_MAXATTR && a->nla_len == sizeof(*a) + 4) { uint32_t v; memcpy(&v, p + sizeof(*a), 4); got_max = v == 0; }
                    if (a->nla_type == CTRL_ATTR_OPS && a->nla_len > sizeof(*a)) got_ops = 1;
                    p += step; left -= step;
                }
                if (left || !got_name || !got_id || !got_version || !got_hdr || !got_max || !got_ops || expected)
                    goto out;
                found++;
            } else goto out;
        }
        if (rem) goto out;
    }
    if (found == !expected && poll(&pfd, 1, 0) == 0) result = 0;
out:
    if (fd >= 0) close(fd);
    if (result) fprintf(stderr, "generic query type=%d name=%s id=%u expected=%d failed: %s\n", type, name ? name : "-", id, expected, strerror(errno));
    return result;
}

static int dump(int type, int dump_flags)
{
    struct { struct nlmsghdr n; struct genlmsghdr g; } req = {0};
    struct sockaddr_nl local = { .nl_family = AF_NETLINK }, kernel = { .nl_family = AF_NETLINK };
    socklen_t alen = sizeof(local);
    char buf[65536];
    int fd = -1, result = -1, found = 0, done = 0;
    int64_t deadline = milliseconds() + 3000;
    struct pollfd pfd;

    fd = socket(AF_NETLINK, type, NETLINK_GENERIC);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
        getsockname(fd, (struct sockaddr *)&local, &alen)) goto out;
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST | dump_flags | NLM_F_ACK;
    req.n.nlmsg_seq = 456;
    req.g.cmd = CTRL_CMD_GETFAMILY;
    if (sendto(fd, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) != (ssize_t)req.n.nlmsg_len) goto out;
    pfd.fd = fd; pfd.events = POLLIN;
    while (!done) {
        struct sockaddr_nl from;
        socklen_t fromlen = sizeof(from);
        int64_t left_ms = deadline - milliseconds();
        int rem;
        if (left_ms <= 0 || poll(&pfd, 1, (int)left_ms) != 1 || !(pfd.revents & POLLIN)) goto out;
        ssize_t len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (len < 0 || from.nl_pid) goto out;
        rem = (int)len;
        for (struct nlmsghdr *n = (struct nlmsghdr *)buf; NLMSG_OK(n, rem); n = NLMSG_NEXT(n, rem)) {
            if (n->nlmsg_seq != 456 || n->nlmsg_pid != local.nl_pid || !(n->nlmsg_flags & NLM_F_MULTI)) goto out;
            if (n->nlmsg_type == NLMSG_DONE) {
                int32_t status;
                if (n->nlmsg_len < NLMSG_LENGTH(sizeof(status))) goto out;
                memcpy(&status, NLMSG_DATA(n), sizeof(status));
                if (status) goto out;
                done = 1;
            } else if (n->nlmsg_type == GENL_ID_CTRL && n->nlmsg_len >= NLMSG_LENGTH(GENL_HDRLEN)) {
                struct genlmsghdr *g = NLMSG_DATA(n);
                int left = (int)n->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
                char *p = (char *)g + GENL_HDRLEN;
                int is_ctrl = 0, id = 0;
                if (g->cmd != CTRL_CMD_NEWFAMILY) goto out;
                while (left >= (int)sizeof(struct nlattr)) {
                    struct nlattr *a = (struct nlattr *)p;
                    int step = NLA_ALIGN(a->nla_len);
                    if (a->nla_len < sizeof(*a) || step > left) goto out;
                    if (a->nla_type == CTRL_ATTR_FAMILY_NAME && a->nla_len == sizeof(*a) + 7 && !memcmp(p + sizeof(*a), "nlctrl", 7)) is_ctrl = 1;
                    if (a->nla_type == CTRL_ATTR_FAMILY_ID && a->nla_len == sizeof(*a) + 2) { uint16_t v; memcpy(&v, p + sizeof(*a), 2); id = v; }
                    p += step; left -= step;
                }
                if (left || (is_ctrl && id != 16)) goto out;
                found += is_ctrl;
            } else goto out;
        }
        if (rem) goto out;
    }
    if (found == 1 && poll(&pfd, 1, 0) == 0) result = 0;
out:
    if (fd >= 0) close(fd);
    if (result) fprintf(stderr, "generic dump type=%d flags=%#x failed\n", type, dump_flags);
    return result;
}

static int malformed(int type, int short_header)
{
    struct { struct nlmsghdr n; struct genlmsghdr g; struct nlattr a; char name[4]; } req = {0};
    struct sockaddr_nl local = { .nl_family = AF_NETLINK }, kernel = { .nl_family = AF_NETLINK }, from;
    socklen_t alen = sizeof(local), fromlen = sizeof(from);
    struct pollfd pfd;
    char buf[256];
    int fd = -1, result = -1;
    ssize_t len;

    fd = socket(AF_NETLINK, type, NETLINK_GENERIC);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
        getsockname(fd, (struct sockaddr *)&local, &alen)) goto out;
    req.n.nlmsg_len = short_header ? NLMSG_HDRLEN : sizeof(req);
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_seq = 789;
    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.a.nla_len = sizeof(req.a) + sizeof(req.name);
    req.a.nla_type = CTRL_ATTR_FAMILY_NAME;
    memcpy(req.name, "abcd", sizeof(req.name));
    if (sendto(fd, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) != (ssize_t)req.n.nlmsg_len) goto out;
    pfd.fd = fd; pfd.events = POLLIN;
    if (poll(&pfd, 1, 1000) != 1 || !(pfd.revents & POLLIN)) goto out;
    len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if (len < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) || from.nl_pid) goto out;
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct nlmsgerr *e = NLMSG_DATA(n);
    if (!NLMSG_OK(n, len) || n->nlmsg_type != NLMSG_ERROR || n->nlmsg_seq != 789 ||
        n->nlmsg_pid != local.nl_pid || e->error != -EINVAL || e->msg.nlmsg_seq != 789) goto out;
    result = 0;
out:
    if (fd >= 0) close(fd);
    if (result) fprintf(stderr, "generic malformed type=%d case=%d failed\n", type, short_header);
    return result;
}

static int control_messages(int type)
{
    struct nlmsghdr request[2] = {0};
    struct sockaddr_nl local = { .nl_family = AF_NETLINK }, kernel = { .nl_family = AF_NETLINK };
    socklen_t alen = sizeof(local);
    char buf[256];
    struct pollfd pfd;
    int fd = -1, result = -1, seen = 0;
    int64_t deadline = milliseconds() + 1000;
    fd = socket(AF_NETLINK, type, NETLINK_GENERIC);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
        getsockname(fd, (struct sockaddr *)&local, &alen)) goto out;
    for (int i = 0; i < 2; i++) {
        request[i].nlmsg_len = NLMSG_HDRLEN;
        request[i].nlmsg_type = i ? GENL_ID_CTRL : NLMSG_NOOP;
        request[i].nlmsg_flags = NLM_F_ACK | (i ? 0 : NLM_F_REQUEST);
        request[i].nlmsg_seq = 900 + i;
    }
    if (sendto(fd, request, sizeof(request), 0, (struct sockaddr *)&kernel, sizeof(kernel)) != sizeof(request)) goto out;
    pfd.fd = fd; pfd.events = POLLIN;
    while (seen != 3) {
        int64_t left = deadline - milliseconds();
        struct sockaddr_nl from;
        socklen_t flen = sizeof(from);
        if (left <= 0 || poll(&pfd, 1, (int)left) != 1 || !(pfd.revents & POLLIN)) goto out;
        ssize_t len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
        if (len < 0 || from.nl_pid) goto out;
        int remaining = (int)len;
        for (struct nlmsghdr *n = (struct nlmsghdr *)buf; NLMSG_OK(n, remaining); n = NLMSG_NEXT(n, remaining)) {
            if (n->nlmsg_type != NLMSG_ERROR || n->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)) ||
                n->nlmsg_pid != local.nl_pid || n->nlmsg_seq < 900 || n->nlmsg_seq > 901) goto out;
            int i = n->nlmsg_seq - 900;
            struct nlmsgerr *e = NLMSG_DATA(n);
            if ((seen & (1 << i)) || e->error || memcmp(&e->msg, &request[i], sizeof(request[i]))) goto out;
            seen |= 1 << i;
        }
        if (remaining) goto out;
    }
    if (!poll(&pfd, 1, 0)) result = 0;
out:
    if (fd >= 0) close(fd);
    if (result) fprintf(stderr, "generic control messages type=%d failed\n", type);
    return result;
}

static int ports(int type)
{
    struct sockaddr_nl a = { .nl_family = AF_NETLINK }, b;
    socklen_t length = sizeof(a);
    int first = -1, second = -1, reused = -1, route = -1, result = -1;
    first = socket(AF_NETLINK, type, NETLINK_GENERIC);
    second = socket(AF_NETLINK, type, NETLINK_GENERIC);
    if (first < 0 || second < 0 || bind(first, (struct sockaddr *)&a, sizeof(a)) ||
        getsockname(first, (struct sockaddr *)&a, &length)) goto out;
    errno = 0;
    if (bind(second, (struct sockaddr *)&a, sizeof(a)) != -1 || errno != EADDRINUSE) goto out;
    b = a; b.nl_pid = 0;
    if (bind(second, (struct sockaddr *)&b, sizeof(b)) || getsockname(second, (struct sockaddr *)&b, &length) ||
        !a.nl_pid || !b.nl_pid || a.nl_pid == b.nl_pid) goto out;
    if (close(first)) goto out;
    first = -1;
    reused = socket(AF_NETLINK, type, NETLINK_GENERIC);
    route = socket(AF_NETLINK, type, NETLINK_ROUTE);
    if (reused < 0 || route < 0 || bind(reused, (struct sockaddr *)&a, sizeof(a)) ||
        bind(route, (struct sockaddr *)&a, sizeof(a))) goto out;
    result = 0;
out:
    if (first >= 0) close(first);
    if (second >= 0) close(second);
    if (reused >= 0) close(reused);
    if (route >= 0) close(route);
    if (result) fprintf(stderr, "generic ports type=%d failed: %s\n", type, strerror(errno));
    return result;
}

int main(void)
{
    for (int type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
        if (query(type, "nlctrl", 0, 0, 0, 0) || query(type, NULL, 16, 0, 0, 0) ||
            query(type, "xsh-no-such", 0, ENOENT, 0, 0) || query(type, NULL, 65535, ENOENT, 0, 0) ||
            query(type, NULL, 0, EINVAL, 0, 0) || dump(type, NLM_F_DUMP) || query(type, "nlctrl", 0, 0, 0, NLM_F_ROOT) ||
            query(type, "nlctrl", 0, 0, 0, NLM_F_MATCH) || query(type, NULL, 0, EINVAL, 0, NLM_F_ROOT) ||
            query(type, "nlctrl", 0, 0, 40000, 0) || control_messages(type) || ports(type) || malformed(type, 0) ||
            malformed(type, 1)) return 1;
    }
    return 0;
}
