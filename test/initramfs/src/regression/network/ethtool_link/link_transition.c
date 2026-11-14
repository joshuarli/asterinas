// SPDX-License-Identifier: MPL-2.0
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0), failed = 0;
    struct ifreq req = {0};
    strcpy(req.ifr_name, "lo");
    if (fd < 0 || ioctl(fd, SIOCGIFFLAGS, &req) < 0) return 1;
    short original = req.ifr_flags;
    req.ifr_flags = original & ~IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &req) < 0) return 1;
    struct ethtool_value value = {ETHTOOL_GLINK, 0x12345678};
    req.ifr_data = (void *)&value;
    if (ioctl(fd, SIOCETHTOOL, &req) < 0 || value.data != 0) failed = 1;
    req.ifr_flags = original;
    if (ioctl(fd, SIOCSIFFLAGS, &req) < 0) return 1;
    value.cmd = ETHTOOL_GLINK; req.ifr_data = (void *)&value;
    if (ioctl(fd, SIOCETHTOOL, &req) < 0 || value.data != !!(original & IFF_UP)) failed = 1;
    close(fd);
    printf("link_transition %s\n", failed ? "FAIL" : "PASS");
    return failed;
}
