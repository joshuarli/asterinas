// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/udp.h>
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

FN_TEST(feedback_on_another_interface_updates_the_output_path)
{
 unsigned int loopback = TEST_RES(if_nametoindex("lo"), _ret != 0);
 struct in_addr local; TEST_RES(inet_pton(AF_INET, "192.0.2.100", &local), _ret == 1);
 int config = TEST_SUCC(rtnl_open(0)); struct rtnl_reply reply;
 struct { struct ifaddrmsg body; uint8_t attributes[64]; } address = {
  .body = { .ifa_family = AF_INET, .ifa_prefixlen = 32, .ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = loopback }
 };
 size_t length = sizeof(address.body);
 length = rtnl_put(&address, length, IFA_LOCAL, &local, sizeof(local));
 length = rtnl_put(&address, length, IFA_ADDRESS, &local, sizeof(local));
 TEST_SUCC(rtnl_send(config, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 73, &address, length));
 TEST_SUCC(rtnl_receive(config, &reply, 73)); TEST_RES(reply.saw_error && !reply.error, _ret != 0); TEST_SUCC(close(config));
 int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL)));
 struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = if_nametoindex("eth0") };
 TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)); int mode = IP_PMTUDISC_DO;
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(39144) };
 TEST_RES(inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr), _ret == 1);
 TEST_SUCC(connect(fd, (struct sockaddr *)&dst, sizeof(dst)));
 int mtu = 0; socklen_t len = sizeof(mtu); TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len)); TEST_RES(mtu, _ret == 1500);
 char payload[900]; memset(payload, 0x5a, sizeof(payload)); TEST_RES(send(fd, payload, sizeof(payload), 0), _ret == sizeof(payload));
 unsigned char frame[1600]; ssize_t size = 0; int observed = 0;
 for (int i = 0; i < 20 && !observed; i++) {
  struct pollfd ready = { .fd = watcher, .events = POLLIN }; if (poll(&ready, 1, 500) != 1) break;
  size = recv(watcher, frame, sizeof(frame), 0);
  if (size == 942 && frame[12] == 8 && frame[13] == 0 && frame[23] == IPPROTO_UDP &&
      frame[36] == (39144 >> 8) && frame[37] == (39144 & 255) && !memcmp(frame + 42, payload, 900)) observed = 1;
 }
 TEST_RES(observed, _ret == 1);
 unsigned char packet[20 + 8 + 928] = {}; struct iphdr *outer = (struct iphdr *)packet;
 outer->version = 4; outer->ihl = 5; outer->tot_len = htons(sizeof(packet)); outer->ttl = 64;
 outer->protocol = IPPROTO_ICMP; outer->saddr = dst.sin_addr.s_addr; outer->daddr = local.s_addr;
 outer->check = checksum(outer, 20); packet[20] = ICMP_DEST_UNREACH; packet[21] = ICMP_FRAG_NEEDED;
 packet[26] = 600 >> 8; packet[27] = 600 & 255; memcpy(packet + 28, frame + 14, 928);
 uint16_t sum = checksum(packet + 20, sizeof(packet) - 20); memcpy(packet + 22, &sum, sizeof(sum));
 int raw = TEST_SUCC(socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)));
 struct sockaddr_ll target = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP), .sll_ifindex = loopback, .sll_halen = ETH_ALEN };
 TEST_RES(sendto(raw, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target)), _ret == sizeof(packet));
 struct pollfd ready = { .fd = fd, .events = POLLIN }; TEST_RES(poll(&ready, 1, 5000), _ret == 1 && (ready.revents & POLLERR));
 int error = 0; len = sizeof(error); TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)); TEST_RES(error, _ret == EMSGSIZE);
 len = sizeof(mtu); TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len)); TEST_RES(mtu, _ret == 600);
 TEST_ERRNO(send(fd, payload, 700, 0), EMSGSIZE);
 TEST_SUCC(close(raw)); TEST_SUCC(close(fd)); TEST_SUCC(close(watcher));
}
END_TEST()
