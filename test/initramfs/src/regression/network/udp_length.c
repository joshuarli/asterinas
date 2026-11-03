// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

FN_TEST(ipv4_udp_rejects_payloads_larger_than_the_protocol_limit)
{
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in destination = { .sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(39000) };
	static char payload[65508];
	TEST_RES(sendto(sender, payload, sizeof(payload) - 1, 0,
			(struct sockaddr *)&destination, sizeof(destination)), _ret == 65507);
	TEST_ERRNO(sendto(sender, payload, sizeof(payload), 0,
			  (struct sockaddr *)&destination, sizeof(destination)), EMSGSIZE);
	TEST_SUCC(close(sender));
}
END_TEST()
