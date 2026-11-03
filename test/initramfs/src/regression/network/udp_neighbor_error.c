// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <linux/if_addr.h>
#include <net/if.h>
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

static struct sockaddr_in peer(const char *text)
{
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(39000) };
	if (inet_pton(AF_INET, text, &address.sin_addr) != 1) _exit(2);
	return address;
}

FN_TEST(connected_udp_without_recverr_ignores_a_soft_neighbor_error)
{
	int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	struct sockaddr_in destination = peer("192.0.2.254");
	TEST_SUCC(connect(fd, (struct sockaddr *)&destination, sizeof(destination)));
	TEST_RES(send(fd, "probe", 5, 0), _ret == 5);
	struct pollfd event = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&event, 1, 8000), _ret == 0);
	int error = 0;
	socklen_t length = sizeof(error);
	TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length));
	TEST_RES(error, _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(unconnected_udp_without_recverr_remains_silent)
{
	int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	struct sockaddr_in destination = peer("192.0.2.253");
	TEST_RES(sendto(fd, "probe", 5, 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == 5);
	struct pollfd event = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&event, 1, 5000), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(unconnected_udp_recverr_reports_the_original_datagram)
{
	int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int enabled = 1;
	TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
	struct sockaddr_in destination = peer("192.0.2.252");
	TEST_RES(sendto(fd, "probe", 5, 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == 5);
	struct pollfd event = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&event, 1, 8000), _ret == 1 && (event.revents & POLLERR));
	char data[16] = {};
	union { struct cmsghdr alignment; char data[128]; } control = {};
	struct sockaddr_in actual = {};
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	struct msghdr msg = { .msg_name = &actual, .msg_namelen = sizeof(actual), .msg_iov = &iov,
		.msg_iovlen = 1, .msg_control = control.data, .msg_controllen = sizeof(control.data) };
	TEST_RES(recvmsg(fd, &msg, MSG_ERRQUEUE), _ret == 5 && !memcmp(data, "probe", 5));
	TEST_RES(actual.sin_addr.s_addr, _ret == destination.sin_addr.s_addr);
	TEST_RES(actual.sin_port, _ret == destination.sin_port);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	TEST_RES(cmsg, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
	if (cmsg && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
		struct sock_extended_err error;
		memcpy(&error, CMSG_DATA(cmsg), sizeof(error));
		fprintf(stderr, "neighbor error: errno=%u origin=%u type=%u code=%u info=%u\n",
			error.ee_errno, error.ee_origin, error.ee_type, error.ee_code, error.ee_info);
		if (cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in))) {
			struct sockaddr_in offender;
			memcpy(&offender, (const char *)CMSG_DATA(cmsg) + sizeof(error), sizeof(offender));
			char text[INET_ADDRSTRLEN] = {};
			inet_ntop(AF_INET, &offender.sin_addr, text, sizeof(text));
			fprintf(stderr, "neighbor offender: family=%d address=%s\n", offender.sin_family, text);
		}
		TEST_RES(error.ee_errno, _ret == EHOSTUNREACH);
		TEST_RES(error.ee_origin, _ret == SO_EE_ORIGIN_ICMP);
		TEST_RES(error.ee_type, _ret == 3);
		TEST_RES(error.ee_code, _ret == 1);
	}
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(neighbor_failure_does_not_reach_a_reused_port)
{
	int old = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	struct sockaddr_in local = { .sin_family = AF_INET };
	TEST_RES(inet_pton(AF_INET, "192.0.2.100", &local.sin_addr), _ret == 1);
	TEST_SUCC(bind(old, (struct sockaddr *)&local, sizeof(local)));
	socklen_t length = sizeof(local);
	TEST_SUCC(getsockname(old, (struct sockaddr *)&local, &length));
	struct sockaddr_in destination = peer("192.0.2.251");
	TEST_SUCC(connect(old, (struct sockaddr *)&destination, sizeof(destination)));
	TEST_RES(send(old, "probe", 5, 0), _ret == 5);
	TEST_SUCC(close(old));
	int replacement = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	TEST_SUCC(bind(replacement, (struct sockaddr *)&local, sizeof(local)));
	TEST_SUCC(connect(replacement, (struct sockaddr *)&destination, sizeof(destination)));
	struct pollfd event = { .fd = replacement, .events = POLLIN };
	TEST_RES(poll(&event, 1, 5000), _ret == 0);
	TEST_SUCC(close(replacement));
}
END_TEST()
