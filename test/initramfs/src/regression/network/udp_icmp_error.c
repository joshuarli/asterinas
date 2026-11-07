// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"

static struct sockaddr_in unused_loopback_port(void)
{
	int fd = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	CHECK(bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
	socklen_t len = sizeof(addr);
	CHECK(getsockname(fd, (struct sockaddr *)&addr, &len));
	CHECK(close(fd));
	return addr;
}

FN_TEST(connected_udp_reports_port_unreachable)
{
	int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	struct sockaddr_in local = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(fd, (struct sockaddr *)&local, sizeof(local)));
	struct sockaddr_in addr = unused_loopback_port();
	TEST_SUCC(connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
	TEST_RES(send(fd, "probe", 5, 0), _ret == 5);
	struct pollfd event = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&event, 1, 2000), _ret == 1 && (event.revents & POLLERR));
	int error = 0;
	socklen_t len = sizeof(error);
	TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len));
	TEST_RES(error, _ret == ECONNREFUSED);
	TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len));
	TEST_RES(error, _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(error_queue_reports_the_original_udp_probe)
{
	int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	struct sockaddr_in local = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(fd, (struct sockaddr *)&local, sizeof(local)));
	struct sockaddr_in addr = unused_loopback_port();
	int enabled = 1;
	TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
	TEST_RES(sendto(fd, "probe", 5, 0, (struct sockaddr *)&addr, sizeof(addr)), _ret == 5);
	struct pollfd event = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&event, 1, 2000), _ret == 1 && (event.revents & POLLERR));
	char data[32] = {}, control[256] = {};
	struct sockaddr_in destination = {};
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	struct msghdr msg = { .msg_name = &destination, .msg_namelen = sizeof(destination),
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control) };
	TEST_RES(recvmsg(fd, &msg, MSG_ERRQUEUE), _ret == 5 && memcmp(data, "probe", 5) == 0);
	TEST_RES(destination.sin_port, _ret == addr.sin_port);
	TEST_RES(destination.sin_addr.s_addr, _ret == addr.sin_addr.s_addr);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	TEST_RES(cmsg, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
	TEST_RES(cmsg, _ret && _ret->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in)));
	if (cmsg && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
		struct sock_extended_err *error = (struct sock_extended_err *)CMSG_DATA(cmsg);
		TEST_RES(error->ee_errno, _ret == ECONNREFUSED);
		TEST_RES(error->ee_origin, _ret == SO_EE_ORIGIN_ICMP);
		TEST_RES(error->ee_type, _ret == 3);
		TEST_RES(error->ee_code, _ret == 3);
		if (cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in))) {
			struct sockaddr_in *offender = (struct sockaddr_in *)SO_EE_OFFENDER(error);
			TEST_RES(offender->sin_family, _ret == AF_INET);
			TEST_RES(offender->sin_addr.s_addr, _ret == htonl(INADDR_LOOPBACK));
		}
	}
	TEST_ERRNO(recvmsg(fd, &msg, MSG_ERRQUEUE), EAGAIN);
	TEST_SUCC(close(fd));
}
END_TEST()
