// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

FN_SETUP(configure_ping_group)
{
#ifndef __asterinas__
	int fd = CHECK(open("/proc/sys/net/ipv4/ping_group_range", O_WRONLY));
	CHECK_WITH(write(fd, "0 0\n", 4), _ret == 4);
	CHECK(close(fd));
#endif
}
END_SETUP()

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

static int echo_roundtrip(int type)
{
	int fd = socket(AF_INET, type | SOCK_NONBLOCK, IPPROTO_ICMP);
	if (fd < 0) {
		int error = errno;
		FILE *range = fopen("/proc/sys/net/ipv4/ping_group_range", "r");
		char value[80] = {};
		if (range && fgets(value, sizeof(value), range))
			fprintf(stderr, "ping_group_range=%s", value);
		if (range) fclose(range);
		errno = error;
		return 0;
	}
	struct sockaddr_in peer = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	struct { struct icmphdr header; char data[8]; } request = {
		.header = { .type = ICMP_ECHO, .un.echo = { .id = htons(1234), .sequence = htons(7) } },
		.data = "asteric",
	};
	request.header.checksum = checksum(&request, sizeof(request));
	if (sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&peer, sizeof(peer)) != sizeof(request)) {
		close(fd);
		return 0;
	}
	int found = 0;
	for (int i = 0; i < 4 && !found; i++) {
		struct pollfd event = { .fd = fd, .events = POLLIN };
		if (poll(&event, 1, 2000) != 1) break;
		unsigned char data[512];
		ssize_t length = recv(fd, data, sizeof(data), 0);
		size_t offset = type == SOCK_RAW && length > 0 ? (data[0] & 15) * 4 : 0;
		if (length >= (ssize_t)(offset + sizeof(request))) {
			struct icmphdr reply;
			memcpy(&reply, data + offset, sizeof(reply));
			found = reply.type == ICMP_ECHOREPLY && reply.un.echo.sequence == htons(7)
				&& memcmp(data + offset + sizeof(reply), request.data, sizeof(request.data)) == 0;
		}
	}
	close(fd);
	return found;
}

FN_TEST(icmp_datagram_echo_on_loopback)
{
	TEST_RES(echo_roundtrip(SOCK_DGRAM), _ret == 1);
}
END_TEST()

FN_TEST(icmp_raw_echo_on_loopback)
{
	TEST_RES(echo_roundtrip(SOCK_RAW), _ret == 1);
}
END_TEST()
