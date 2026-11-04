// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/test.h"
#include "rtnl_common.h"

FN_SETUP(configure_ethernet_and_gateway)
{
	int control = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	struct ifreq request = {};
	strncpy(request.ifr_name, "eth0", IFNAMSIZ - 1);
	CHECK(ioctl(control, SIOCGIFFLAGS, &request));
	request.ifr_flags |= IFF_UP;
	CHECK(ioctl(control, SIOCSIFFLAGS, &request));
	CHECK(close(control));
	unsigned int index = CHECK_WITH(if_nametoindex("eth0"), _ret != 0);
	struct in_addr local, gateway;
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.100", &local), _ret == 1);
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.1", &gateway), _ret == 1);
	int fd = CHECK(rtnl_open(0));
	struct rtnl_reply reply;
	struct { struct ifaddrmsg body; uint8_t attributes[64]; } address = {
		.body = { .ifa_family = AF_INET, .ifa_prefixlen = 24, .ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = index }
	};
	size_t len = sizeof(address.body);
	len = rtnl_put(&address, len, IFA_LOCAL, &local, sizeof(local));
	len = rtnl_put(&address, len, IFA_ADDRESS, &local, sizeof(local));
	CHECK(rtnl_send(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			71, &address, len));
	CHECK(rtnl_receive(fd, &reply, 71));
	CHECK_WITH(reply.saw_error && !reply.error, _ret != 0);
	struct { struct rtmsg body; uint8_t attributes[64]; } route = {
		.body = { .rtm_family = AF_INET, .rtm_table = RT_TABLE_MAIN, .rtm_protocol = RTPROT_STATIC,
			.rtm_scope = RT_SCOPE_UNIVERSE, .rtm_type = RTN_UNICAST }
	};
	len = sizeof(route.body);
	len = rtnl_put(&route, len, RTA_GATEWAY, &gateway, sizeof(gateway));
	len = rtnl_put(&route, len, RTA_OIF, &index, sizeof(index));
	CHECK(rtnl_send(fd, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			72, &route, len));
	CHECK(rtnl_receive(fd, &reply, 72));
	CHECK_WITH(reply.saw_error && !reply.error, _ret != 0);
	CHECK(close(fd));
}
END_SETUP()

static uint16_t checksum(const void *data, size_t length)
{
 const unsigned char *bytes = data; uint32_t sum = 0;
 while (length >= 2) { sum += ((uint16_t)bytes[0] << 8) | bytes[1]; bytes += 2; length -= 2; }
 if (length) sum += (uint16_t)bytes[0] << 8;
 while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
 return htons((uint16_t)~sum);
}

FN_TEST(raw_ipv4_echo_crosses_ethernet)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP)); if (fd < 0) { __TEST_SUMMARY(); return; }
 int ttl = 37, tos = 16;
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)));
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
 struct sockaddr_in peer = { .sin_family = AF_INET };
 TEST_RES(inet_pton(AF_INET, "192.0.2.1", &peer.sin_addr), _ret == 1);
 struct { struct icmphdr header; char data[8]; } request = {
  .header = { .type = ICMP_ECHO, .un.echo = { .id = htons(4983), .sequence = htons(9) } }, .data = "wire-raw" };
 request.header.checksum = checksum(&request, sizeof(request));
 TEST_RES(sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&peer, sizeof(peer)), _ret == sizeof(request));
 int found = 0;
 for (int i = 0; i < 8 && !found; i++) {
  struct pollfd ready = { .fd = fd, .events = POLLIN }; if (poll(&ready, 1, 1000) != 1) break;
  unsigned char bytes[256]; struct sockaddr_in source = {}; socklen_t len = sizeof(source);
  ssize_t n = recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr *)&source, &len);
  if (n != 36 || bytes[0] != 0x45 || bytes[9] != IPPROTO_ICMP || checksum(bytes, 20) || checksum(bytes + 20, 16)) continue;
  struct icmphdr icmp; memcpy(&icmp, bytes + 20, sizeof(icmp));
  found = source.sin_addr.s_addr == peer.sin_addr.s_addr && icmp.type == ICMP_ECHOREPLY &&
   icmp.un.echo.id == htons(4983) && icmp.un.echo.sequence == htons(9) && !memcmp(bytes + 28, request.data, 8);
 }
 TEST_RES(found, _ret == 1); TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(raw_loopback_source_cannot_escape_and_connected_cannot_rebind)
{
 struct sockaddr_in loop = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 struct sockaddr_in peer = { .sin_family = AF_INET }; inet_pton(AF_INET, "192.0.2.1", &peer.sin_addr);
 struct icmphdr request = { .type = ICMP_ECHO };
 int bound = TEST_SUCC(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
 if (bound < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(bind(bound, (struct sockaddr *)&loop, sizeof(loop)));
 TEST_ERRNO(sendto(bound, &request, sizeof(request), 0, (struct sockaddr *)&peer, sizeof(peer)), EINVAL);
 TEST_ERRNO(connect(bound, (struct sockaddr *)&peer, sizeof(peer)), EINVAL);
 TEST_SUCC(close(bound));
 int connected = TEST_SUCC(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
 if (connected < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(connect(connected, (struct sockaddr *)&loop, sizeof(loop)));
 TEST_ERRNO(bind(connected, (struct sockaddr *)&loop, sizeof(loop)), EINVAL);
 TEST_ERRNO(sendto(connected, &request, sizeof(request), 0, (struct sockaddr *)&peer, sizeof(peer)), EINVAL);
 TEST_SUCC(close(connected));
}
END_TEST()

FN_TEST(ping_socket_rejects_directed_broadcast_bind)
{
 const char *path = "/proc/sys/net/ipv4/ping_group_range";
 int config = TEST_SUCC(open(path, O_RDONLY));
 if (config < 0) { __TEST_SUMMARY(); return; }
 char original[64] = {}; ssize_t n = read(config, original, sizeof(original));
 TEST_RES(n, _ret > 0); TEST_SUCC(close(config));
 config = TEST_SUCC(open(path, O_WRONLY)); TEST_RES(write(config, "0 0\n", 4), _ret == 4); TEST_SUCC(close(config));
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));
 if (fd >= 0) {
  struct sockaddr_in address = { .sin_family = AF_INET }; inet_pton(AF_INET, "192.0.2.255", &address.sin_addr);
  TEST_ERRNO(bind(fd, (struct sockaddr *)&address, sizeof(address)), EADDRNOTAVAIL);
  inet_pton(AF_INET, "192.0.2.100", &address.sin_addr); TEST_SUCC(bind(fd, (struct sockaddr *)&address, sizeof(address)));
  TEST_SUCC(close(fd));
 }
 config = TEST_SUCC(open(path, O_WRONLY)); TEST_RES(write(config, original, n), _ret == n); TEST_SUCC(close(config));
}
END_TEST()
