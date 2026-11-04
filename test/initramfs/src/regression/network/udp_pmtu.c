// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

static int emitted_df(int sender, int watcher, const struct sockaddr_in *destination, int mode)
{
	if (setsockopt(sender, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode))) return -1;
	if (sendto(sender, "pmtu", 4, 0, (const struct sockaddr *)destination, sizeof(*destination)) != 4) return -1;
	for (int i = 0; i < 16; i++) {
		struct pollfd event = { .fd = watcher, .events = POLLIN };
		if (poll(&event, 1, 2000) != 1) return -1;
		unsigned char frame[2048];
		ssize_t length = recv(watcher, frame, sizeof(frame), 0);
		if (length < ETH_HLEN + (ssize_t)sizeof(struct iphdr) + (ssize_t)sizeof(struct udphdr) + 4) continue;
		struct iphdr ip;
		memcpy(&ip, frame + ETH_HLEN, sizeof(ip));
		size_t offset = ETH_HLEN + ip.ihl * 4;
		if (ip.version != 4 || ip.protocol != IPPROTO_UDP || offset + sizeof(struct udphdr) + 4 > (size_t)length) continue;
		struct udphdr udp;
		memcpy(&udp, frame + offset, sizeof(udp));
		if (udp.dest != destination->sin_port || memcmp(frame + offset + sizeof(udp), "pmtu", 4)) continue;
		return (ntohs(ip.frag_off) & IP_DF) != 0;
	}
	return -1;
}

FN_TEST(path_mtu_modes_control_the_ipv4_df_flag)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_IP)));
	int initial = -1;
	socklen_t option_length = sizeof(initial);
	TEST_SUCC(getsockopt(sender, IPPROTO_IP, IP_MTU_DISCOVER, &initial, &option_length));
	TEST_RES(initial, _ret == IP_PMTUDISC_WANT);
	struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = (int)if_nametoindex("lo") };
	TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&destination, sizeof(destination)));
	socklen_t length = sizeof(destination);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&destination, &length));
	TEST_RES(emitted_df(sender, watcher, &destination, IP_PMTUDISC_DONT), _ret == 0);
	TEST_RES(emitted_df(sender, watcher, &destination, IP_PMTUDISC_DO), _ret == 1);
	TEST_RES(emitted_df(sender, watcher, &destination, IP_PMTUDISC_PROBE), _ret == 1);
	int selected = -1;
	TEST_SUCC(getsockopt(sender, IPPROTO_IP, IP_MTU_DISCOVER, &selected, &option_length));
	TEST_RES(selected, _ret == IP_PMTUDISC_PROBE);
	int mode = -1;
	TEST_ERRNO(setsockopt(sender, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)), EINVAL);
	TEST_SUCC(close(watcher));
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()

FN_TEST(maximum_ipv4_udp_payload_arrives_on_loopback)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in destination = { .sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&destination, sizeof(destination)));
	socklen_t length = sizeof(destination);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&destination, &length));
	static char sent[65507], received[65507];
	sent[0] = 'a';
	sent[sizeof(sent) - 1] = 'z';
	TEST_RES(sendto(sender, sent, sizeof(sent), 0, (struct sockaddr *)&destination,
			 sizeof(destination)), _ret == sizeof(sent));
	struct pollfd ready = { .fd = receiver, .events = POLLIN };
	if (TEST_RES(poll(&ready, 1, 2000), _ret == 1) == 1)
		TEST_RES(recv(receiver, received, sizeof(received), 0),
			_ret == sizeof(received) && !memcmp(sent, received, sizeof(sent)));
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()
