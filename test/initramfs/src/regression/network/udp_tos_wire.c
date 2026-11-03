// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"
#include "rtnl_common.h"

FN_SETUP(configure_ethernet)
{
	int control = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	struct ifreq request = {};
	strncpy(request.ifr_name, "eth0", IFNAMSIZ - 1);
	CHECK(ioctl(control, SIOCGIFFLAGS, &request));
	request.ifr_flags |= IFF_UP;
	CHECK(ioctl(control, SIOCSIFFLAGS, &request));
	CHECK(close(control));
	unsigned int index = CHECK_WITH(if_nametoindex("eth0"), _ret != 0);
	struct in_addr local;
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.100", &local), _ret == 1);
	struct { struct ifaddrmsg body; uint8_t attributes[64]; } address = {
		.body = { .ifa_family = AF_INET, .ifa_prefixlen = 24, .ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = index }
	};
	struct rtnl_reply reply;
	size_t len = sizeof(address.body);
	int fd = CHECK(rtnl_open(0));
	len = rtnl_put(&address, len, IFA_LOCAL, &local, sizeof(local));
	len = rtnl_put(&address, len, IFA_ADDRESS, &local, sizeof(local));
	CHECK(rtnl_send(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			71, &address, len));
	CHECK(rtnl_receive(fd, &reply, 71));
	CHECK_WITH(reply.saw_error && !reply.error, _ret != 0);
	CHECK(close(fd));
}
END_SETUP()

FN_TEST(ipv4_udp_emits_the_selected_tos)
{
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL)));
	struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = (int)if_nametoindex("eth0") };
	TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(39123) };
	TEST_RES(inet_pton(AF_INET, "192.0.2.1", &destination.sin_addr), _ret == 1);
	int tos = 0xb9;
	TEST_SUCC(setsockopt(sender, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
	TEST_RES(sendto(sender, "wire", 4, 0, (struct sockaddr *)&destination,
			 sizeof(destination)), _ret == 4);
	int found = 0;
	for (int i = 0; i < 16 && !found; i++) {
		struct pollfd ready = { .fd = watcher, .events = POLLIN };
		if (poll(&ready, 1, 1000) != 1) break;
		unsigned char frame[2048];
		ssize_t length = recv(watcher, frame, sizeof(frame), 0);
		if (length < ETH_HLEN + (ssize_t)sizeof(struct iphdr) + (ssize_t)sizeof(struct udphdr) + 4) continue;
		struct iphdr ip;
		memcpy(&ip, frame + ETH_HLEN, sizeof(ip));
		if (ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_UDP) continue;
		struct udphdr udp;
		memcpy(&udp, frame + ETH_HLEN + sizeof(ip), sizeof(udp));
		if (udp.dest != destination.sin_port || memcmp(frame + ETH_HLEN + sizeof(ip) + sizeof(udp), "wire", 4)) continue;
		found = ip.tos == tos;
	}
	TEST_RES(found, _ret == 1);
	TEST_SUCC(close(watcher));
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(ipv4_udp_reports_the_received_wire_tos)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int enabled = 1;
	TEST_SUCC(setsockopt(receiver, IPPROTO_IP, IP_RECVTOS, &enabled, sizeof(enabled)));
	struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(39124) };
	TEST_RES(inet_pton(AF_INET, "192.0.2.100", &local.sin_addr), _ret == 1);
	TEST_SUCC(bind(receiver, (struct sockaddr *)&local, sizeof(local)));
	struct pollfd ready = { .fd = receiver, .events = POLLIN };
	if (TEST_RES(poll(&ready, 1, 5000), _ret == 1 && (ready.revents & POLLIN)) == 1) {
		char payload[8];
		union { struct cmsghdr align; char bytes[128]; } control = {};
		struct iovec iov = { .iov_base = payload, .iov_len = sizeof(payload) };
		struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
			.msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
		TEST_RES(recvmsg(receiver, &message, 0), _ret == 4 && !memcmp(payload, "peer", 4));
		struct cmsghdr *header = CMSG_FIRSTHDR(&message);
		TEST_RES(header, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_TOS && _ret->cmsg_len >= CMSG_LEN(1));
		if (header && header->cmsg_len >= CMSG_LEN(1))
			TEST_RES(*(unsigned char *)CMSG_DATA(header), _ret == 0xb9);
	}
	TEST_SUCC(close(receiver));
}
END_TEST()
