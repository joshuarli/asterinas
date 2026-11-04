// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
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

FN_TEST(path_mtu_controls_oversized_datagram_admission)
{
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(39125) };
	TEST_RES(inet_pton(AF_INET, "192.0.2.1", &destination.sin_addr), _ret == 1);
	static char payload[1473];
	int modes[] = { IP_PMTUDISC_DO, IP_PMTUDISC_PROBE, IP_PMTUDISC_DONT };
	for (int i = 0; i < 3; i++) {
		int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
		TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &modes[i], sizeof(modes[i])));
		TEST_RES(sendto(fd, payload, 1472, 0, (struct sockaddr *)&destination,
			       sizeof(destination)), _ret == 1472);
		if (modes[i] == IP_PMTUDISC_DONT)
			TEST_RES(sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&destination,
				       sizeof(destination)), _ret == sizeof(payload));
		else
			TEST_ERRNO(sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&destination,
					 sizeof(destination)), EMSGSIZE);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(fragmentable_udp_emits_complete_ipv4_fragments)
{
	unsigned int index = TEST_RES(if_nametoindex("eth0"), _ret != 0);
	int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL)));
	struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = index };
	TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int mode = IP_PMTUDISC_DONT;
	TEST_SUCC(setsockopt(sender, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(39129) };
	TEST_RES(inet_pton(AF_INET, "192.0.2.1", &destination.sin_addr), _ret == 1);
	static unsigned char payload[2000];
	memset(payload, 0x7b, sizeof(payload));
	TEST_RES(sendto(sender, payload, sizeof(payload), 0, (struct sockaddr *)&destination,
		       sizeof(destination)), _ret == sizeof(payload));
	int first = 0, second = 0;
	uint16_t identity = 0;
	for (int i = 0; i < 16 && !(first && second); i++) {
		struct pollfd ready = { .fd = watcher, .events = POLLIN };
		if (poll(&ready, 1, 500) != 1) break;
		unsigned char frame[2048];
		ssize_t length = recv(watcher, frame, sizeof(frame), 0);
		if (length < 34 || frame[12] != 8 || frame[13] != 0 || frame[23] != IPPROTO_UDP ||
		    memcmp(frame + 30, &destination.sin_addr, 4)) continue;
		uint16_t flags = ((uint16_t)frame[20] << 8) | frame[21];
		uint16_t id = ((uint16_t)frame[18] << 8) | frame[19];
		if ((flags & 0x7fff) == 0x2000 && length == 1514 &&
		    frame[36] == (39129 >> 8) && frame[37] == (39129 & 255) &&
		    !memcmp(frame + 42, payload, 1472)) { identity = id; first = 1; }
		if ((flags & 0x7fff) == 185 && length == 562 && first && id == identity &&
		    !memcmp(frame + 34, payload + 1472, 528)) second = 1;
	}
	TEST_RES(first, _ret == 1);
	TEST_RES(second, _ret == 1);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(watcher));
}
END_TEST()
