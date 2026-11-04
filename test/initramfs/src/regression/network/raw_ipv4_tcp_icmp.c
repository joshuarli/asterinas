// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
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

FN_TEST(raw_icmp_receives_quoted_tcp_syn)
{
 int raw = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP)); if (raw < 0) return;
 int tcp = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons(39145) };
 TEST_RES(inet_pton(AF_INET, "192.0.2.1", &peer.sin_addr), _ret == 1);
 TEST_ERRNO(connect(tcp, (struct sockaddr *)&peer, sizeof(peer)), EINPROGRESS);
 struct sockaddr_in local = {}; socklen_t len = sizeof(local); TEST_SUCC(getsockname(tcp, (struct sockaddr *)&local, &len));
 struct pollfd ready = { .fd = raw, .events = POLLIN }; TEST_RES(poll(&ready, 1, 5000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char bytes[512]; struct sockaddr_in source = {}; len = sizeof(source);
 ssize_t n = recvfrom(raw, bytes, sizeof(bytes), 0, (struct sockaddr *)&source, &len); int valid = 0;
 if (n >= 56 && bytes[0] == 0x45 && bytes[9] == IPPROTO_ICMP && !checksum(bytes, 20) &&
     bytes[20] == ICMP_TIME_EXCEEDED && bytes[21] == ICMP_EXC_TTL && !checksum(bytes + 20, n - 20)) {
  unsigned char *quoted = bytes + 28; size_t h = (quoted[0] & 15) * 4;
  if (h >= 20 && n >= (ssize_t)(28 + h + 8) && quoted[9] == IPPROTO_TCP) {
   uint16_t source_port, dest_port; memcpy(&source_port, quoted + h, 2); memcpy(&dest_port, quoted + h + 2, 2);
   valid = source.sin_addr.s_addr == peer.sin_addr.s_addr && source_port == local.sin_port && dest_port == peer.sin_port;
  }
 }
 TEST_RES(valid, _ret == 1); TEST_SUCC(close(tcp)); TEST_SUCC(close(raw));
}
END_TEST()
