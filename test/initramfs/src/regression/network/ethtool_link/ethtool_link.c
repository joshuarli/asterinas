// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s errno=%d\n", __LINE__, #x, errno); failures++; } } while (0)

int main(int argc, char **argv)
{
    int admin = argc > 1 ? atoi(argv[1]) : geteuid() == 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    struct ifreq req = {0}, original;
    struct { struct ethtool_value value; unsigned guard; } payload = {{ETHTOOL_GLINK, 0x12345678}, 0x87654321};
    strcpy(req.ifr_name, "lo");
    req.ifr_data = (void *)&payload.value;
    original = req;
    CHECK(ioctl(fd, SIOCETHTOOL, &req) == 0);
    CHECK(payload.value.cmd == ETHTOOL_GLINK && payload.value.data == 1 && payload.guard == 0x87654321);
    CHECK(memcmp(&req, &original, sizeof(req)) == 0);
    payload.value.cmd = 0xffffffff; payload.value.data = 0x12345678;
    errno = 0; CHECK(ioctl(fd, SIOCETHTOOL, &req) == -1 && errno == (admin ? EOPNOTSUPP : EPERM));
    CHECK(payload.value.data == 0x12345678 && payload.guard == 0x87654321);
    payload.value.cmd = ETHTOOL_SSET;
    errno = 0; CHECK(ioctl(fd, SIOCETHTOOL, &req) == -1 && errno == (admin ? EOPNOTSUPP : EPERM));
    payload.value.cmd = ETHTOOL_GSET;
    errno = 0; CHECK(ioctl(fd, SIOCETHTOOL, &req) == -1 && errno == EOPNOTSUPP);
    strcpy(req.ifr_name, "missing0"); payload.value.cmd = ETHTOOL_GLINK;
    errno = 0; CHECK(ioctl(fd, SIOCETHTOOL, &req) == -1 && errno == ENODEV);
    CHECK(payload.value.data == 0x12345678);
    req.ifr_data = NULL;
    errno = 0; CHECK(ioctl(fd, SIOCETHTOOL, &req) == -1 && errno == EFAULT);
    strcpy(req.ifr_name, "lo"); req.ifr_data = (void *)1;
    errno = 0; CHECK(ioctl(fd, SIOCETHTOOL, &req) == -1 && errno == EFAULT);
    long page = sysconf(_SC_PAGESIZE);
    char *p = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    if (p != MAP_FAILED) {
        CHECK(mprotect(p + page, page, PROT_NONE) == 0);
        unsigned *cmd = (unsigned *)(p + page - 4); *cmd = ETHTOOL_GLINK; req.ifr_data = (void *)cmd;
        errno = 0; CHECK(ioctl(fd, SIOCETHTOOL, &req) == -1 && errno == EFAULT);
        CHECK(*cmd == ETHTOOL_GLINK);
        munmap(p, page * 2);
    }
    close(fd);
    printf("ethtool_link %s\n", failures ? "FAIL" : "PASS");
    return failures != 0;
}
