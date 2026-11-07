// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

FN_TEST(ipv6_loopback_datagram_round_trip)
{
	int receiver = TEST_SUCC(socket(AF_INET6, SOCK_DGRAM, 0));
	int sender = TEST_SUCC(socket(AF_INET6, SOCK_DGRAM, 0));
	struct sockaddr_in6 address = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&address, sizeof(address)));
	socklen_t length = sizeof(address);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&address, &length));
	TEST_RES(sendto(sender, "ipv6", 4, 0, (struct sockaddr *)&address, sizeof(address)), _ret == 4);
	char received[8] = {};
	struct sockaddr_in6 source = {};
	length = sizeof(source);
	TEST_RES(recvfrom(receiver, received, sizeof(received), 0, (struct sockaddr *)&source, &length),
		 _ret == 4 && !memcmp(received, "ipv6", 4));
	TEST_RES(source.sin6_family, _ret == AF_INET6);
	TEST_RES(IN6_IS_ADDR_LOOPBACK(&source.sin6_addr), _ret != 0);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()

FN_TEST(ipv6_wildcard_receives_ipv4_as_mapped_address)
{
	int receiver = TEST_SUCC(socket(AF_INET6, SOCK_DGRAM, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int only = -1;
	socklen_t length = sizeof(only);
	TEST_SUCC(getsockopt(receiver, IPPROTO_IPV6, IPV6_V6ONLY, &only, &length));
	TEST_RES(only, _ret == 0);
	struct sockaddr_in6 local = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&local, sizeof(local)));
	length = sizeof(local);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&local, &length));
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = local.sin6_port };
	TEST_RES(sendto(sender, "v4", 2, 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == 2);
	struct pollfd ready = { .fd = receiver, .events = POLLIN };
	if (TEST_RES(poll(&ready, 1, 1000), _ret == 1) == 1) {
		char payload[8];
		struct sockaddr_in6 source = {};
		length = sizeof(source);
		TEST_RES(recvfrom(receiver, payload, sizeof(payload), 0, (struct sockaddr *)&source, &length),
			_ret == 2 && !memcmp(payload, "v4", 2));
		TEST_RES(source.sin6_family, _ret == AF_INET6);
		TEST_RES(IN6_IS_ADDR_V4MAPPED(&source.sin6_addr), _ret != 0);
	}
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()
