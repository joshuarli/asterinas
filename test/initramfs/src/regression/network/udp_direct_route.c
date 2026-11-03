// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
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

FN_TEST(dont_route_uses_the_direct_route_next_hop)
{
	unsigned int index = TEST_RES(if_nametoindex("eth0"), _ret != 0);
	struct in_addr target;
	TEST_RES(inet_pton(AF_INET, "198.51.100.42", &target), _ret == 1);
	int netlink = TEST_SUCC(rtnl_open(0));
	struct rtnl_reply reply;
	struct { struct rtmsg body; uint8_t attributes[64]; } route = {
		.body = { .rtm_family = AF_INET, .rtm_dst_len = 32, .rtm_table = RT_TABLE_MAIN,
			.rtm_protocol = RTPROT_STATIC, .rtm_scope = RT_SCOPE_LINK, .rtm_type = RTN_UNICAST }
	};
	size_t len = sizeof(route.body);
	len = rtnl_put(&route, len, RTA_DST, &target, sizeof(target));
	len = rtnl_put(&route, len, RTA_OIF, &index, sizeof(index));
	TEST_SUCC(rtnl_send(netlink, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			73, &route, len));
	TEST_SUCC(rtnl_receive(netlink, &reply, 73));
	TEST_RES(reply.saw_error && !reply.error, _ret != 0);
	int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL)));
	struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = index };
	TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(39126), .sin_addr = target };
	TEST_RES(sendto(sender, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&destination, sizeof(destination)), _ret == 1);
	int found = 0;
	for (int i = 0; i < 8 && !found; i++) {
		struct pollfd ready = { .fd = watcher, .events = POLLIN };
		if (poll(&ready, 1, 500) != 1) break;
		unsigned char packet[256];
		ssize_t n = recv(watcher, packet, sizeof(packet), 0);
		if (n >= 42 && packet[12] == 0x08 && packet[13] == 0x06 &&
		    packet[20] == 0 && packet[21] == 1 && !memcmp(packet + 38, &target, 4)) found = 1;
	}
	TEST_RES(found, _ret == 1);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(watcher));
	TEST_SUCC(close(netlink));
}
END_TEST()

FN_TEST(dont_route_selects_a_route_on_the_bound_device)
{
	unsigned int interfaces[] = { if_nametoindex("lo"), if_nametoindex("eth0") };
	struct in_addr target;
	TEST_RES(inet_pton(AF_INET, "198.51.100.43", &target), _ret == 1);
	int netlink = TEST_SUCC(rtnl_open(0));
	for (unsigned int i = 0; i < 2; i++) {
		struct { struct rtmsg body; uint8_t attributes[64]; } route = {
			.body = { .rtm_family = AF_INET, .rtm_dst_len = 32, .rtm_table = RT_TABLE_MAIN,
				.rtm_protocol = RTPROT_STATIC, .rtm_scope = RT_SCOPE_LINK, .rtm_type = RTN_UNICAST }
		};
		unsigned int metric = i + 1;
		size_t len = sizeof(route.body);
		len = rtnl_put(&route, len, RTA_DST, &target, sizeof(target));
		len = rtnl_put(&route, len, RTA_OIF, &interfaces[i], sizeof(interfaces[i]));
		len = rtnl_put(&route, len, RTA_PRIORITY, &metric, sizeof(metric));
		struct rtnl_reply reply;
		TEST_SUCC(rtnl_send(netlink, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
				80 + i, &route, len));
		TEST_SUCC(rtnl_receive(netlink, &reply, 80 + i));
		TEST_RES(reply.saw_error && !reply.error, _ret != 0);
	}
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_SUCC(setsockopt(sender, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5));
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(39127), .sin_addr = target };
	TEST_RES(sendto(sender, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&destination, sizeof(destination)), _ret == 1);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(netlink));
}
END_TEST()

FN_TEST(reconnect_preserves_automatically_selected_local_address)
{
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons(39128),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(connect(sender, (struct sockaddr *)&remote, sizeof(remote)));
	struct sockaddr_in first = {}, second = {};
	socklen_t len = sizeof(first);
	TEST_SUCC(getsockname(sender, (struct sockaddr *)&first, &len));
	TEST_RES(inet_pton(AF_INET, "192.0.2.1", &remote.sin_addr), _ret == 1);
	TEST_ERRNO(connect(sender, (struct sockaddr *)&remote, sizeof(remote)), EINVAL);
	len = sizeof(second);
	TEST_SUCC(getsockname(sender, (struct sockaddr *)&second, &len));
	TEST_RES(second.sin_addr.s_addr, _ret == first.sin_addr.s_addr);
	TEST_RES(second.sin_port, _ret == first.sin_port);
	TEST_SUCC(close(sender));
}
END_TEST()
