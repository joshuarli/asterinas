// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

FN_TEST(connected_udp_filters_and_reserves_its_local_address)
{
	int peer = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in local = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(peer, (struct sockaddr *)&local, sizeof(local)));
	socklen_t len = sizeof(local);
	TEST_SUCC(getsockname(peer, (struct sockaddr *)&local, &len));
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	TEST_SUCC(connect(receiver, (struct sockaddr *)&local, sizeof(local)));
	struct sockaddr_in target = {};
	len = sizeof(target);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&target, &len));
	TEST_RES(target.sin_addr.s_addr, _ret == htonl(INADDR_LOOPBACK));
	target.sin_addr.s_addr = htonl(INADDR_LOOPBACK + 2);
	TEST_RES(sendto(peer, "x", 1, 0, (struct sockaddr *)&target, sizeof(target)), _ret == 1);
	struct pollfd ready = { .fd = receiver, .events = POLLIN };
	TEST_RES(poll(&ready, 1, 200), _ret == 0);
	int other = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_SUCC(bind(other, (struct sockaddr *)&target, sizeof(target)));
	TEST_SUCC(close(other));
	TEST_SUCC(close(receiver));
	TEST_SUCC(close(peer));
}
END_TEST()

FN_TEST(device_bound_udp_takes_priority_over_wildcard)
{
	int restricted = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int wildcard = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int reuse = 1;
	TEST_SUCC(setsockopt(restricted, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
	TEST_SUCC(setsockopt(wildcard, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
	TEST_SUCC(setsockopt(restricted, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3));
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY) };
	TEST_SUCC(bind(restricted, (struct sockaddr *)&address, sizeof(address)));
	socklen_t len = sizeof(address);
	TEST_SUCC(getsockname(restricted, (struct sockaddr *)&address, &len));
	TEST_SUCC(bind(wildcard, (struct sockaddr *)&address, sizeof(address)));
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_RES(sendto(sender, "x", 1, 0, (struct sockaddr *)&address, sizeof(address)), _ret == 1);
	struct pollfd ready[] = { { .fd = restricted, .events = POLLIN }, { .fd = wildcard, .events = POLLIN } };
	TEST_RES(poll(ready, 2, 1000), _ret == 1);
	TEST_RES(ready[0].revents & POLLIN, _ret != 0);
	TEST_RES(ready[1].revents & POLLIN, _ret == 0);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(wildcard));
	TEST_SUCC(close(restricted));
}
END_TEST()
