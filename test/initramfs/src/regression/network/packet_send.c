// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"
#include "rtnl_common.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define FRAME_SIZE 2048
#define WAIT_MS 1500
#define LOOPBACK_MTU 65536
#define LOCAL_ADDRESS "10.9.8.7"
#define PEER_ADDRESS "10.9.8.200"

struct frame {
	unsigned char bytes[FRAME_SIZE];
	ssize_t length;
	struct sockaddr_ll from;
};

static unsigned int loopback;
static int control_socket;
static int receiver;
static uint16_t receiver_port;

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

static uint16_t checksum(const void *data, size_t length)
{
	const uint8_t *bytes = data;
	uint32_t sum = 0;

	for (; length > 1; length -= 2, bytes += 2)
		sum += bytes[0] << 8 | bytes[1];
	if (length)
		sum += bytes[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons(~sum);
}

static size_t build_udp_packet(unsigned char *out, const char *payload)
{
	struct iphdr ip = { .version = 4,
			    .ihl = 5,
			    .ttl = 64,
			    .protocol = IPPROTO_UDP,
			    .saddr = 0,
			    .daddr = 0 };
	struct udphdr udp = { .source = htons(40000),
			      .dest = htons(receiver_port) };
	size_t length = strlen(payload);

	inet_pton(AF_INET, PEER_ADDRESS, &ip.saddr);
	inet_pton(AF_INET, LOCAL_ADDRESS, &ip.daddr);
	ip.tot_len = htons(sizeof(ip) + sizeof(udp) + length);
	udp.len = htons(sizeof(udp) + length);
	ip.check = checksum(&ip, sizeof(ip));
	memcpy(out, &ip, sizeof(ip));
	memcpy(out + sizeof(ip), &udp, sizeof(udp));
	memcpy(out + sizeof(ip) + sizeof(udp), payload, length);
	return sizeof(ip) + sizeof(udp) + length;
}

static size_t build_frame(unsigned char *out, const char *payload)
{
	memset(out, 0, ETH_HLEN);
	out[12] = ETH_P_IP >> 8;
	out[13] = ETH_P_IP & 0xff;
	return ETH_HLEN + build_udp_packet(out + ETH_HLEN, payload);
}

static int receive_frame(int fd, struct frame *frame)
{
	socklen_t length = sizeof(frame->from);

	frame->length = recvfrom(fd, frame->bytes, sizeof(frame->bytes), 0,
				 (struct sockaddr *)&frame->from, &length);
	return frame->length < 0 ? -1 : 0;
}

static int wait_readable(int fd, int milliseconds)
{
	struct pollfd waiting = { .fd = fd, .events = POLLIN };

	if (poll(&waiting, 1, milliseconds) < 0)
		return -1;
	return waiting.revents;
}

static int is_test_frame(const struct frame *frame)
{
	return frame->length >= ETH_HLEN + 28 &&
	       ntohs(*(uint16_t *)(frame->bytes + ETH_HLEN + 22)) == receiver_port;
}

/* Counts the test frames that arrive on fd; kinds[] gets their packet types. */
static int collect_frames(int fd, int kinds[], int capacity)
{
	struct frame frame;
	int count = 0;

	while (wait_readable(fd, count ? 300 : WAIT_MS) > 0 &&
	       receive_frame(fd, &frame) == 0) {
		if (!is_test_frame(&frame))
			continue;
		if (count < capacity)
			kinds[count] = frame.from.sll_pkttype;
		count++;
	}
	return count;
}

static int receive_datagram(char *buffer, size_t length)
{
	if (wait_readable(receiver, WAIT_MS) <= 0)
		return -1;
	return recv(receiver, buffer, length, 0);
}

static int drain_receiver(void)
{
	char buffer[64];

	while (recv(receiver, buffer, sizeof(buffer), MSG_DONTWAIT) >= 0)
		;
	errno = 0;
	return 0;
}

static struct sockaddr_ll destination(unsigned int ifindex, unsigned short protocol)
{
	struct sockaddr_ll address = { .sll_family = AF_PACKET,
				       .sll_protocol = htons(protocol),
				       .sll_ifindex = (int)ifindex,
				       .sll_halen = ETH_ALEN };

	return address;
}

static int add_local_address(unsigned int ifindex)
{
	struct {
		struct ifaddrmsg body;
		uint8_t attributes[64];
	} request = { .body = { .ifa_family = AF_INET,
				.ifa_prefixlen = 24,
				.ifa_scope = RT_SCOPE_UNIVERSE,
				.ifa_index = ifindex } };
	struct in_addr local;
	struct rtnl_reply reply;
	size_t length = sizeof(request.body);
	int fd = rtnl_open(0);

	inet_pton(AF_INET, LOCAL_ADDRESS, &local);
	length = rtnl_put(&request, length, IFA_LOCAL, &local, sizeof(local));
	length = rtnl_put(&request, length, IFA_ADDRESS, &local, sizeof(local));
	if (fd < 0 ||
	    rtnl_send(fd, RTM_NEWADDR,
		      NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 77,
		      &request, length) ||
	    rtnl_receive(fd, &reply, 77) || !reply.saw_error || reply.error)
		return -1;
	close(fd);
	return 0;
}

FN_SETUP(environment)
{
	struct sockaddr_in address = { .sin_family = AF_INET };
	socklen_t length = sizeof(address);

	loopback = CHECK_WITH(if_nametoindex("lo"), _ret != 0);
	CHECK(add_local_address(loopback));
	inet_pton(AF_INET, LOCAL_ADDRESS, &address.sin_addr);
	control_socket = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	receiver = CHECK(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	CHECK(bind(receiver, (struct sockaddr *)&address, sizeof(address)));
	CHECK(getsockname(receiver, (struct sockaddr *)&address, &length));
	receiver_port = ntohs(address.sin_port);
}
END_SETUP()

FN_TEST(a_raw_frame_reaches_the_network_stack_of_the_interface)
{
	unsigned char frame[FRAME_SIZE];
	char buffer[32];
	size_t length = build_frame(frame, "injected");
	int sender = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));

	TEST_SUCC(drain_receiver());
	TEST_RES(send(sender, frame, length, 0), _ret == (ssize_t)length);
	TEST_RES(receive_datagram(buffer, sizeof(buffer)), _ret == 8);
	TEST_RES(memcmp(buffer, "injected", 8), _ret == 0);
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(observers_see_the_outgoing_frame_and_the_looped_one)
{
	unsigned char frame[FRAME_SIZE];
	size_t length = build_frame(frame, "seen");
	int kinds[4];
	int sender = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));
	int everything = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_ALL, loopback));
	int ip_only = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, 0));

	TEST_SUCC(drain_receiver());
	TEST_RES(sendto(sender, frame, length, 0, NULL, 0), _ret == (ssize_t)length);
	TEST_RES(collect_frames(everything, kinds, 4), _ret == 2);
	TEST_RES(kinds[0], _ret == PACKET_OUTGOING);
	TEST_RES(kinds[1], _ret == PACKET_HOST);
	TEST_RES(collect_frames(ip_only, kinds, 4), _ret == 1);
	TEST_RES(kinds[0], _ret == PACKET_HOST);
	TEST_RES(collect_frames(sender, kinds, 4), _ret == 1);
	TEST_RES(kinds[0], _ret == PACKET_HOST);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(everything));
	TEST_SUCC(close(ip_only));
}
END_TEST()

FN_TEST(the_sender_does_not_see_its_own_outgoing_frame)
{
	unsigned char frame[FRAME_SIZE];
	size_t length = build_frame(frame, "mine");
	int kinds[4];
	int sender = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_ALL, loopback));

	TEST_SUCC(drain_receiver());
	TEST_RES(send(sender, frame, length, 0), _ret == (ssize_t)length);
	TEST_RES(collect_frames(sender, kinds, 4), _ret == 1);
	TEST_RES(kinds[0], _ret == PACKET_HOST);
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(a_raw_frame_keeps_its_bytes)
{
	unsigned char frame[FRAME_SIZE];
	struct frame seen;
	size_t length = build_frame(frame, "bytes");
	int watcher = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));
	int sender = TEST_SUCC(open_packet(SOCK_RAW, 0, loopback));

	TEST_SUCC(drain_receiver());
	TEST_RES(send(sender, frame, length, 0), _ret == (ssize_t)length);
	TEST_SUCC(wait_readable(watcher, WAIT_MS));
	TEST_SUCC(receive_frame(watcher, &seen));
	TEST_RES(seen.length, _ret == (ssize_t)length);
	TEST_RES(memcmp(seen.bytes, frame, length), _ret == 0);
	TEST_SUCC(close(watcher));
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(a_cooked_socket_adds_the_link_header)
{
	unsigned char packet[FRAME_SIZE];
	struct frame seen;
	char buffer[32];
	struct sockaddr_ll address = destination(loopback, ETH_P_IP);
	size_t length = build_udp_packet(packet, "cooked");
	int watcher = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, loopback));
	int sender = TEST_SUCC(open_packet(SOCK_DGRAM, 0, 0));

	TEST_SUCC(drain_receiver());
	TEST_RES(sendto(sender, packet, length, 0, (struct sockaddr *)&address,
			sizeof(address)),
		 _ret == (ssize_t)length);
	TEST_RES(receive_datagram(buffer, sizeof(buffer)), _ret == 6);
	TEST_SUCC(wait_readable(watcher, WAIT_MS));
	TEST_SUCC(receive_frame(watcher, &seen));
	TEST_RES(seen.length, _ret == (ssize_t)(ETH_HLEN + length));
	TEST_RES(seen.bytes[12] << 8 | seen.bytes[13], _ret == ETH_P_IP);
	TEST_RES(memcmp(seen.bytes + ETH_HLEN, packet, length), _ret == 0);
	TEST_SUCC(close(watcher));
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(a_blocking_socket_sends)
{
	unsigned char frame[FRAME_SIZE];
	size_t length = build_frame(frame, "block");
	int sender = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, 0));
	struct sockaddr_ll address = destination(loopback, ETH_P_IP);

	TEST_SUCC(drain_receiver());
	TEST_RES(sendto(sender, frame, length, 0, (struct sockaddr *)&address,
			sizeof(address)),
		 _ret == (ssize_t)length);
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(sending_needs_an_interface)
{
	unsigned char frame[FRAME_SIZE];
	size_t length = build_frame(frame, "nowhere");
	struct sockaddr_ll missing = destination(9999, ETH_P_IP);
	int unbound = TEST_SUCC(open_packet(SOCK_RAW, ETH_P_IP, 0));

	TEST_ERRNO(send(unbound, frame, length, 0), ENXIO);
	TEST_ERRNO(sendto(unbound, frame, length, 0, (struct sockaddr *)&missing,
			  sizeof(missing)),
		   ENXIO);
	TEST_SUCC(close(unbound));
}
END_TEST()

FN_TEST(sending_on_a_down_interface_fails)
{
	unsigned char frame[FRAME_SIZE];
	size_t length = build_frame(frame, "down");
	int sender = TEST_SUCC(open_packet(SOCK_RAW, 0, loopback));

	TEST_SUCC(set_loopback_up(0));
	TEST_ERRNO(send(sender, frame, length, 0), ENETDOWN);
	TEST_SUCC(set_loopback_up(1));
	TEST_SUCC(drain_receiver());
	TEST_RES(send(sender, frame, length, 0), _ret == (ssize_t)length);
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(sending_checks_the_frame_length)
{
	static unsigned char big[LOOPBACK_MTU + ETH_HLEN + 1];
	struct sockaddr_ll address = destination(loopback, ETH_P_IP);
	int raw = TEST_SUCC(open_packet(SOCK_RAW, 0, loopback));
	int cooked = TEST_SUCC(open_packet(SOCK_DGRAM, 0, loopback));

	TEST_ERRNO(send(raw, big, ETH_HLEN - 1, 0), EINVAL);
	TEST_ERRNO(send(raw, big, sizeof(big), 0), EMSGSIZE);
	TEST_ERRNO(sendto(cooked, big, LOOPBACK_MTU + 1, 0,
			  (struct sockaddr *)&address, sizeof(address)),
		   EMSGSIZE);
	TEST_SUCC(close(raw));
	TEST_SUCC(close(cooked));
}
END_TEST()

FN_TEST(a_malformed_destination_is_rejected)
{
	unsigned char frame[FRAME_SIZE];
	size_t length = build_frame(frame, "bad");
	struct sockaddr_ll address = destination(loopback, ETH_P_IP);
	int sender = TEST_SUCC(open_packet(SOCK_RAW, 0, loopback));

	TEST_ERRNO(sendto(sender, frame, length, 0, (struct sockaddr *)&address,
			  sizeof(address) - 1),
		   EINVAL);
	address.sll_halen = 9;
	TEST_ERRNO(sendto(sender, frame, length, 0, (struct sockaddr *)&address,
			  sizeof(address)),
		   EINVAL);
	TEST_SUCC(close(sender));
}
END_TEST()

#ifdef __asterinas__
FN_TEST(a_cooked_socket_without_a_destination_is_rejected)
{
	unsigned char packet[FRAME_SIZE];
	size_t length = build_udp_packet(packet, "lost");
	int cooked = TEST_SUCC(open_packet(SOCK_DGRAM, 0, loopback));

	TEST_ERRNO(send(cooked, packet, length, 0), EINVAL);
	TEST_SUCC(close(cooked));
}
END_TEST()
#endif
