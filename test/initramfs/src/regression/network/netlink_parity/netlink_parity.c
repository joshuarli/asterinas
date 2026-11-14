// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(void)
{
    int failed = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW, 9999);
    if (fd != -1 || errno != EPROTONOSUPPORT) {
        fprintf(stderr, "unsupported protocol: fd=%d errno=%d\n", fd, errno);
        if (fd >= 0) close(fd);
        failed = 1;
    }
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) { perror("socket"); return 1; }
    struct timeval timeout = { .tv_sec = 1 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) { perror("setsockopt"); return 1; }
    struct { struct nlmsghdr h; struct ifinfomsg i; } req = {
        .h = { .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)), .nlmsg_type = RTM_GETLINK,
               .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK, .nlmsg_seq = 42 },
        .i = { .ifi_index = 1 },
    };
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    if (sendto(fd, &req, req.h.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) { perror("sendto"); return 1; }
    int data = 0, ack = 0;
    while (!ack) {
        char buf[8192];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) { perror("recv"); return 1; }
        for (struct nlmsghdr *h = (void *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq != 42) return 1;
            if (h->nlmsg_type == RTM_NEWLINK) data++;
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return 1;
                struct nlmsgerr *err = NLMSG_DATA(h);
                if (err->error) return 1;
                ack++;
            }
        }
    }
    close(fd);
    if (data != 1) return 1;
    puts("netlink protocol and acknowledgement passed");
    return failed;
}
