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

FN_TEST(raw_want_fragments_at_learned_path_mtu)
{
 int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL)));
 struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = if_nametoindex("eth0") };
 TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
 int udp = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)); int mode = IP_PMTUDISC_DO;
 TEST_SUCC(setsockopt(udp, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons(39146) };
 TEST_RES(inet_pton(AF_INET, "192.0.2.1", &peer.sin_addr), _ret == 1); TEST_SUCC(connect(udp, (struct sockaddr *)&peer, sizeof(peer)));
 char probe[900] = {}; TEST_RES(send(udp, probe, sizeof(probe), 0), _ret == sizeof(probe));
 struct pollfd ready = { .fd = udp, .events = POLLIN }; TEST_RES(poll(&ready, 1, 5000), _ret == 1 && (ready.revents & POLLERR));
 int error = 0, mtu = 0; socklen_t len = sizeof(error); TEST_SUCC(getsockopt(udp, SOL_SOCKET, SO_ERROR, &error, &len)); TEST_RES(error, _ret == EMSGSIZE);
 len = sizeof(mtu); TEST_SUCC(getsockopt(udp, IPPROTO_IP, IP_MTU, &mtu, &len)); TEST_RES(mtu, _ret == 600);
 int raw = TEST_SUCC(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
 unsigned char payload[700]; memset(payload, 0x53, sizeof(payload)); payload[0] = ICMP_ECHO; payload[1] = 0; payload[2] = payload[3] = 0;
 uint16_t sum = checksum(payload, sizeof(payload)); memcpy(payload + 2, &sum, sizeof(sum)); peer.sin_port = 0;
 TEST_RES(sendto(raw, payload, sizeof(payload), 0, (struct sockaddr *)&peer, sizeof(peer)), _ret == sizeof(payload));
 int first = 0, last = 0; uint16_t id = 0;
 for (int i = 0; i < 24 && !(first && last); i++) {
  struct pollfd event = { .fd = watcher, .events = POLLIN }; if (poll(&event, 1, 500) != 1) break;
  unsigned char frame[1600]; ssize_t n = recv(watcher, frame, sizeof(frame), 0);
  if (n < 34 || frame[12] != 8 || frame[13] != 0 || frame[23] != IPPROTO_ICMP) continue;
  unsigned flags = ((unsigned)frame[20] << 8) | frame[21]; uint16_t current = ((uint16_t)frame[18] << 8) | frame[19];
  if (n == 610 && flags == 0x2000 && !memcmp(frame + 34, payload, 576)) { first = 1; id = current; }
  if (n == 158 && flags == 72 && current == id && !memcmp(frame + 34, payload + 576, 124)) last = 1;
 }
 TEST_RES(first, _ret == 1); TEST_RES(last, _ret == 1);
 TEST_SUCC(close(raw)); TEST_SUCC(close(udp)); TEST_SUCC(close(watcher));
}
END_TEST()
