// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
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

FN_TEST(mode_feedback)
{
 FILE *f = fopen("/usr/lib/asterinas/case/mode", "r"); int mode = 0;
 TEST_RES(f, _ret != NULL); TEST_RES(fscanf(f, "%d", &mode), _ret == 1); fclose(f);
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
 struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(39143) };
 TEST_RES(inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr), _ret == 1);
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 int enabled = 1; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 TEST_SUCC(connect(fd, (struct sockaddr *)&dst, sizeof(dst)));
 char payload[900] = {}; TEST_RES(send(fd, payload, sizeof(payload), 0), _ret == sizeof(payload));
 struct pollfd ready = { .fd = fd, .events = POLLIN }; TEST_RES(poll(&ready, 1, 5000), _ret == 1 && (ready.revents & POLLERR));
 int error = 0, mtu = 0; socklen_t len = sizeof(error);
 TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)); TEST_RES(error, _ret == EMSGSIZE);
 len = sizeof(mtu); TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len)); TEST_RES(mtu, _ret == 1500);
 int second = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0)); TEST_SUCC(connect(second, (struct sockaddr *)&dst, sizeof(dst)));
 len = sizeof(mtu); TEST_SUCC(getsockopt(second, IPPROTO_IP, IP_MTU, &mtu, &len)); TEST_RES(mtu, _ret == 1500);
 TEST_SUCC(close(second)); TEST_SUCC(close(fd));
}
END_TEST()
