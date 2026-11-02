// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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
	int fd = socket(AF_PACKET, type | SOCK_NONBLOCK, htons(protocol));

	if (fd < 0)
		return -1;
	if (ifindex && bind(fd, (struct sockaddr *)&address, sizeof(address))) {
		close(fd);
		return -1;
	}
	return fd;
}

static int receive_frame(int fd, int flags)
{
	unsigned char bytes[2048];

	return recv(fd, bytes, sizeof(bytes), flags);
}

static int events_of(int fd)
{
	struct pollfd waiting = { .fd = fd, .events = POLLIN };

	if (poll(&waiting, 1, 0) < 0)
		return -1;
	return waiting.revents;
}

FN_SETUP(environment)
{
	loopback = CHECK_WITH(if_nametoindex("lo"), _ret != 0);
	control_socket = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
}
END_SETUP()

FN_TEST(an_idle_socket_has_nothing_to_receive)
{
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_ERRNO(receive_frame(fd, 0), EAGAIN);
	TEST_RES(events_of(fd), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(a_blocking_socket_honours_a_non_blocking_receive)
{
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

	TEST_ERRNO(receive_frame(fd, MSG_DONTWAIT), EAGAIN);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(taking_the_interface_down_fails_the_next_receive_once)
{
	int bound = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));
	int everywhere = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, 0));
	int unselective = TEST_SUCC(open_packet(SOCK_DGRAM, 0, loopback));

	TEST_SUCC(set_loopback_up(0));
	TEST_RES(events_of(bound), _ret == POLLERR);
	TEST_RES(events_of(everywhere), _ret == 0);
	TEST_RES(events_of(unselective), _ret == 0);
	TEST_ERRNO(receive_frame(bound, 0), ENETDOWN);
	TEST_ERRNO(receive_frame(bound, 0), EAGAIN);
	TEST_RES(events_of(bound), _ret == 0);
	TEST_ERRNO(receive_frame(everywhere, 0), EAGAIN);
	TEST_ERRNO(receive_frame(unselective, 0), EAGAIN);
	TEST_SUCC(set_loopback_up(1));
	TEST_ERRNO(receive_frame(bound, 0), EAGAIN);
	TEST_SUCC(close(bound));
	TEST_SUCC(close(everywhere));
	TEST_SUCC(close(unselective));
}
END_TEST()

FN_TEST(a_send_after_the_interface_returns_reports_the_pending_error_once)
{
	unsigned char frame[ETH_HLEN + 20] = { 0 };
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	frame[12] = 0x08;
	frame[ETH_HLEN] = 0x45;
	frame[ETH_HLEN + 3] = 20;
	TEST_SUCC(set_loopback_up(0));
	TEST_SUCC(set_loopback_up(1));
	TEST_RES(events_of(fd), _ret == POLLERR);
	TEST_ERRNO(send(fd, frame, sizeof(frame), 0), ENETDOWN);
	TEST_RES(events_of(fd), _ret == 0);
	TEST_RES(send(fd, frame, sizeof(frame), 0), _ret == (ssize_t)sizeof(frame));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(a_second_down_does_not_fail_the_socket_again)
{
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_SUCC(set_loopback_up(0));
	TEST_ERRNO(receive_frame(fd, 0), ENETDOWN);
	TEST_SUCC(set_loopback_up(0));
	TEST_ERRNO(receive_frame(fd, 0), EAGAIN);
	TEST_SUCC(set_loopback_up(1));
	TEST_SUCC(set_loopback_up(0));
	TEST_ERRNO(receive_frame(fd, 0), ENETDOWN);
	TEST_SUCC(set_loopback_up(1));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(binding_to_a_down_interface_fails_the_next_receive)
{
	struct sockaddr_ll address = { .sll_family = AF_PACKET,
				       .sll_protocol = htons(ETH_P_IP),
				       .sll_ifindex = (int)loopback };
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_IP)));

	TEST_SUCC(set_loopback_up(0));
	TEST_SUCC(bind(fd, (struct sockaddr *)&address, sizeof(address)));
	TEST_RES(events_of(fd), _ret == POLLERR);
	TEST_ERRNO(receive_frame(fd, 0), ENETDOWN);
	TEST_ERRNO(receive_frame(fd, 0), EAGAIN);
	TEST_SUCC(bind(fd, (struct sockaddr *)&address, sizeof(address)));
	TEST_ERRNO(receive_frame(fd, 0), EAGAIN);
	TEST_SUCC(set_loopback_up(1));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(binding_to_a_down_interface_without_a_protocol_is_not_an_error)
{
	struct sockaddr_ll address = { .sll_family = AF_PACKET,
				       .sll_ifindex = (int)loopback };
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0));

	TEST_SUCC(set_loopback_up(0));
	TEST_SUCC(bind(fd, (struct sockaddr *)&address, sizeof(address)));
	TEST_ERRNO(receive_frame(fd, 0), EAGAIN);
	TEST_SUCC(set_loopback_up(1));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(selecting_the_same_interface_and_protocol_again_does_not_fail_the_socket)
{
	struct sockaddr_ll address = { .sll_family = AF_PACKET,
				       .sll_protocol = htons(ETH_P_IP),
				       .sll_ifindex = (int)loopback };
	int fd = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_SUCC(set_loopback_up(0));
	TEST_ERRNO(receive_frame(fd, 0), ENETDOWN);
	TEST_SUCC(bind(fd, (struct sockaddr *)&address, sizeof(address)));
	TEST_ERRNO(receive_frame(fd, 0), EAGAIN);
	TEST_SUCC(set_loopback_up(1));
	TEST_SUCC(close(fd));
}
END_TEST()
