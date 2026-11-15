// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <linux/netlink.h>
#include <linux/netlink_diag.h>
#include <linux/sock_diag.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void check(int condition, const char *message)
{
    if (!condition) { fprintf(stderr, "%s: %s\n", message, strerror(errno)); exit(1); }
}

static void query(int fd, unsigned int inode, unsigned int port, int dump)
{
    struct {
        struct nlmsghdr hdr;
        struct netlink_diag_req req;
    } request = { .hdr = { .nlmsg_len = sizeof(request), .nlmsg_type = SOCK_DIAG_BY_FAMILY,
                           .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = 123 },
                  .req = { .sdiag_family = AF_NETLINK, .sdiag_protocol = NETLINK_ROUTE,
                           .ndiag_ino = inode, .ndiag_cookie = { ~0U, ~0U } } };
    if (dump) request.hdr.nlmsg_flags |= NLM_F_DUMP;
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    check(sendto(fd, &request, sizeof(request), 0, (void *)&kernel, sizeof(kernel)) == sizeof(request), "sendto");
    int found = 0, done = 0;
    while (!done) {
        char buf[16384];
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        check(len > 0, "recv");
        for (struct nlmsghdr *h = (void *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
            check(h->nlmsg_type != NLMSG_ERROR, "diagnostic error");
            if (h->nlmsg_type == NLMSG_DONE) { done = 1; continue; }
            check(h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct netlink_diag_msg)), "short response");
            struct netlink_diag_msg *m = NLMSG_DATA(h);
            if (m->ndiag_ino == inode) {
                check(m->ndiag_family == AF_NETLINK && m->ndiag_type == SOCK_RAW &&
                      m->ndiag_protocol == NETLINK_ROUTE && m->ndiag_portid == port, "wrong socket details");
                found = 1;
            }
            if (!dump) done = 1;
        }
    }
    check(found, "socket missing");
}

int main(void)
{
    int route = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int diag = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    check(route >= 0 && diag >= 0, "socket");
    char protocol[32];
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", route);
    ssize_t protocol_len = getxattr(path, "system.sockprotoname", protocol, sizeof(protocol));
    check(protocol_len == 8 && memcmp(protocol, "NETLINK\0", 8) == 0, "socket protocol attribute");
    struct stat st;
    check(fstat(route, &st) == 0, "fstat");
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    check(bind(route, (void *)&addr, sizeof(addr)) == 0, "bind");
    socklen_t size = sizeof(addr);
    check(getsockname(route, (void *)&addr, &size) == 0, "getsockname");
    query(diag, st.st_ino, addr.nl_pid, 1);
    close(diag); close(route);
    puts("netlink diagnostic witness passed");
    return 0;
}
