// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

static uint16_t checksum(const void *data, size_t length)
{
	const unsigned char *bytes = data;
	uint32_t sum = 0;
	while (length >= 2) {
		sum += ((uint16_t)bytes[0] << 8) | bytes[1];
		bytes += 2;
		length -= 2;
	}
	if (length) sum += (uint16_t)bytes[0] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return htons((uint16_t)~sum);
}

FN_TEST(icmp_echo_request_receives_a_reply)
{
	int sender = TEST_SUCC(socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)));
	int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK, htons(ETH_P_IP)));
	unsigned int loopback = TEST_RES(if_nametoindex("lo"), _ret != 0);
	struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = (int)loopback, .sll_halen = ETH_ALEN };
	TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
	struct { struct iphdr ip; struct icmphdr icmp; char data[8]; } packet = {
		.ip = { .version = 4, .ihl = 5, .tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 8),
			.ttl = 64, .protocol = IPPROTO_ICMP, .saddr = htonl(INADDR_LOOPBACK), .daddr = htonl(INADDR_LOOPBACK) },
		.icmp = { .type = ICMP_ECHO, .un.echo = { .id = htons(4982), .sequence = htons(7) } },
		.data = "request",
	};
	packet.icmp.checksum = checksum(&packet.icmp, sizeof(packet.icmp) + sizeof(packet.data));
	packet.ip.check = checksum(&packet.ip, sizeof(packet.ip));
	TEST_RES(sendto(sender, &packet, sizeof(packet), 0, (struct sockaddr *)&link, sizeof(link)), _ret == sizeof(packet));
	int found = 0;
	for (int i = 0; i < 8 && !found; i++) {
		struct pollfd ready = { .fd = watcher, .events = POLLIN };
		if (poll(&ready, 1, 500) != 1) break;
		unsigned char data[256];
		ssize_t n = recv(watcher, data, sizeof(data), 0);
		if (n < (ssize_t)sizeof(packet)) continue;
		struct iphdr *ip = (struct iphdr *)data;
		if (ip->version != 4 || ip->protocol != IPPROTO_ICMP || ip->ihl != 5) continue;
		struct icmphdr *icmp = (struct icmphdr *)(data + sizeof(*ip));
		fprintf(stderr, "observed ICMP type=%u code=%u len=%zd checksum=%u\n",
			icmp->type, icmp->code, n, checksum(icmp, sizeof(*icmp) + 8));
		found = icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons(4982)
			&& icmp->un.echo.sequence == htons(7) && !memcmp(data + sizeof(*ip) + sizeof(*icmp), "request", 8)
			&& checksum(icmp, sizeof(*icmp) + 8) == 0;
	}
	TEST_RES(found, _ret == 1);
	TEST_SUCC(close(watcher));
	TEST_SUCC(close(sender));
}
END_TEST()
