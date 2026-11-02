// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif

static unsigned int loopback;
static int control_socket;

static int set_loopback_up(int up)
{
	struct ifreq request = { 0 };

	strncpy(request.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(control_socket, SIOCGIFFLAGS, &request))
		return -1;
	if (up)
		request.ifr_flags |= IFF_UP;
	else
		request.ifr_flags &= ~IFF_UP;
	return ioctl(control_socket, SIOCSIFFLAGS, &request);
}

static int open_packet(int type, unsigned short protocol, unsigned int ifindex)
{
	struct sockaddr_ll address = { .sll_family = AF_PACKET,
				       .sll_protocol = htons(protocol),
				       .sll_ifindex = (int)ifindex };
	int fd = socket(AF_PACKET, type, htons(protocol));

	if (fd < 0)
		return -1;
	if (ifindex && bind(fd, (struct sockaddr *)&address, sizeof(address))) {
		close(fd);
		return -1;
	}
	return fd;
}

static int integer_option(int fd, int level, int name)
{
	int value = -1;
	socklen_t length = sizeof(value);

	if (getsockopt(fd, level, name, &value, &length))
		return -1000;
	return value;
}

static int set_integer_option(int fd, int level, int name, int value)
{
	return setsockopt(fd, level, name, &value, sizeof(value));
}

FN_SETUP(environment)
{
	loopback = CHECK_WITH(if_nametoindex("lo"), _ret != 0);
	control_socket = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
}
END_SETUP()

FN_TEST(the_socket_reports_its_type_and_domain)
{
	int raw = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));
	int cooked = TEST_SUCC(open_packet(SOCK_DGRAM, ETH_P_IP, loopback));

	TEST_RES(integer_option(raw, SOL_SOCKET, SO_TYPE), _ret == SOCK_RAW);
	TEST_RES(integer_option(cooked, SOL_SOCKET, SO_TYPE), _ret == SOCK_DGRAM);
	TEST_RES(integer_option(raw, SOL_SOCKET, SO_ERROR), _ret == 0);
	TEST_SUCC(close(raw));
	TEST_SUCC(close(cooked));
}
END_TEST()

FN_TEST(reading_the_error_clears_it)
{
	unsigned char bytes[64];
	struct pollfd waiting;
	int fd = TEST_SUCC(open_packet(SOCK_RAW | SOCK_NONBLOCK, ETH_P_IP, loopback));

	TEST_SUCC(set_loopback_up(0));
	waiting = (struct pollfd){ .fd = fd, .events = POLLIN };
	TEST_RES(poll(&waiting, 1, 0), _ret == 1 && waiting.revents == POLLERR);
	TEST_RES(integer_option(fd, SOL_SOCKET, SO_ERROR), _ret == ENETDOWN);
	TEST_RES(integer_option(fd, SOL_SOCKET, SO_ERROR), _ret == 0);
	TEST_ERRNO(recv(fd, bytes, sizeof(bytes), 0), EAGAIN);
	waiting = (struct pollfd){ .fd = fd, .events = POLLIN };
	TEST_RES(poll(&waiting, 1, 0), _ret == 0);
	TEST_SUCC(set_loopback_up(1));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(the_receive_buffer_has_a_default_and_can_grow)
{
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_RES(integer_option(fd, SOL_SOCKET, SO_RCVBUF), _ret == 212992);
	TEST_SUCC(set_integer_option(fd, SOL_SOCKET, SO_RCVBUF, 400000));
	TEST_RES(integer_option(fd, SOL_SOCKET, SO_RCVBUF), _ret >= 400000);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(a_receive_timeout_ends_a_blocking_receive)
{
	unsigned char bytes[64];
	struct timeval timeout = { .tv_usec = 200000 };
	struct timespec before, after;
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_SUCC(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
	clock_gettime(CLOCK_MONOTONIC, &before);
	TEST_ERRNO(recv(fd, bytes, sizeof(bytes), 0), EAGAIN);
	clock_gettime(CLOCK_MONOTONIC, &after);
	TEST_RES((after.tv_sec - before.tv_sec) * 1000 +
			 (after.tv_nsec - before.tv_nsec) / 1000000,
		 _ret >= 150 && _ret < 1500);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(ignoring_outgoing_frames_can_be_switched)
{
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_ALL, loopback));

	TEST_RES(integer_option(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING), _ret == 0);
	TEST_SUCC(set_integer_option(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, 1));
	TEST_RES(integer_option(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING), _ret == 1);
	TEST_SUCC(set_integer_option(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, 0));
	TEST_RES(integer_option(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(statistics_start_at_zero_and_are_read_once)
{
	struct tpacket_stats statistics = { .tp_packets = 7, .tp_drops = 7 };
	socklen_t length = sizeof(statistics);
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_SUCC(getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &statistics, &length));
	TEST_RES(length, _ret == sizeof(statistics));
	TEST_RES(statistics.tp_packets, _ret == 0);
	TEST_RES(statistics.tp_drops, _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(an_unknown_packet_option_is_refused)
{
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_ERRNO(set_integer_option(fd, SOL_PACKET, 9999, 1), ENOPROTOOPT);
	TEST_ERRNO(integer_option(fd, SOL_PACKET, 9999), ENOPROTOOPT);
	TEST_SUCC(close(fd));
}
END_TEST()

#ifdef __asterinas__
FN_TEST(known_options_that_are_not_supported_are_refused)
{
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_ERRNO(set_integer_option(fd, SOL_PACKET, PACKET_AUXDATA, 1), ENOPROTOOPT);
	TEST_SUCC(close(fd));
}
END_TEST()
#endif
