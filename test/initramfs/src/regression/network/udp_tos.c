// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

FN_TEST(ipv4_udp_delivers_type_of_service)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int enabled = 1;
	TEST_SUCC(setsockopt(receiver, IPPROTO_IP, IP_RECVTOS, &enabled, sizeof(enabled)));
	struct sockaddr_in destination = { .sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&destination, sizeof(destination)));
	socklen_t length = sizeof(destination);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&destination, &length));
	int values[] = { 16, 3, 0xb9 };
	for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		int tos = values[i];
		TEST_SUCC(setsockopt(sender, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
		TEST_RES(sendto(sender, "tos", 3, 0, (struct sockaddr *)&destination,
				 sizeof(destination)), _ret == 3);
		char payload[8];
		union { struct cmsghdr align; char bytes[128]; } control = {};
		struct iovec iov = { .iov_base = payload, .iov_len = sizeof(payload) };
		struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
			.msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
		TEST_RES(recvmsg(receiver, &message, 0), _ret == 3 && !memcmp(payload, "tos", 3));
		struct cmsghdr *header = CMSG_FIRSTHDR(&message);
		TEST_RES(header, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_TOS);
		TEST_RES(header, _ret && _ret->cmsg_len >= CMSG_LEN(1));
		if (header && header->cmsg_len >= CMSG_LEN(1))
			TEST_RES(*(unsigned char *)CMSG_DATA(header), _ret == tos);
	}
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()
