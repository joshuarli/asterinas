// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "../common/test.h"
#include "rtnl_common.h"

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

static int add_loopback_address(unsigned int index, struct in_addr address)
{
	struct {
		struct ifaddrmsg body;
		uint8_t attributes[64];
	} request = { .body = { .ifa_family = AF_INET, .ifa_prefixlen = 24,
		.ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = index } };
	struct rtnl_reply reply;
	size_t length = sizeof(request.body);
	int fd = rtnl_open(0);
	length = rtnl_put(&request, length, IFA_LOCAL, &address, sizeof(address));
	length = rtnl_put(&request, length, IFA_ADDRESS, &address, sizeof(address));
	if (fd < 0 || rtnl_send(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			       71, &request, length) || rtnl_receive(fd, &reply, 71) ||
	    !reply.saw_error || reply.error)
		return -1;
	close(fd);
	return 0;
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

FN_TEST(zero_length_udp_datagram_is_delivered)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in destination = { .sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&destination, sizeof(destination)));
	socklen_t length = sizeof(destination);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&destination, &length));
	TEST_RES(sendto(sender, "", 0, 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == 0);
	struct pollfd ready = { .fd = receiver, .events = POLLIN };
	TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
	char byte;
	TEST_RES(recv(receiver, &byte, sizeof(byte), 0), _ret == 0);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()

FN_TEST(dropped_datagrams_do_not_block_later_packets)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in destination = { .sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&destination, sizeof(destination)));
	socklen_t length = sizeof(destination);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&destination, &length));
	static char large[32000];
	static char dropped[2000];
	TEST_RES(sendto(sender, large, sizeof(large), 0, (struct sockaddr *)&destination,
			 sizeof(destination)), _ret == sizeof(large));
	TEST_RES(sendto(sender, large, sizeof(large), 0, (struct sockaddr *)&destination,
			 sizeof(destination)), _ret == sizeof(large));
	for (int i = 0; i < 254; i++)
		CHECK_WITH(sendto(sender, dropped, sizeof(dropped), 0,
				  (struct sockaddr *)&destination, sizeof(destination)), _ret == sizeof(dropped));
	static char received[32000];
	TEST_RES(recv(receiver, received, sizeof(received), 0), _ret == sizeof(received));
	TEST_RES(sendto(sender, "a1", 2, 0, (struct sockaddr *)&destination,
			 sizeof(destination)), _ret == 2);
	TEST_RES(sendto(sender, "b2", 2, 0, (struct sockaddr *)&destination,
			 sizeof(destination)), _ret == 2);
	int markers = 0;
	ssize_t count;
	while ((count = recv(receiver, received, sizeof(received), 0)) >= 0) {
		if (count == 2 && !memcmp(received, "a1", 2)) markers |= 1;
		if (count == 2 && !memcmp(received, "b2", 2)) markers |= 2;
	}
	TEST_RES(markers, _ret == 3);
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()

FN_TEST(received_udp_reports_the_sent_ttl)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&addr, sizeof(addr)));
	socklen_t length = sizeof(addr);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&addr, &length));
	int enabled = 1, ttl = 37;
	TEST_SUCC(setsockopt(receiver, IPPROTO_IP, IP_RECVTTL, &enabled, sizeof(enabled)));
	TEST_SUCC(setsockopt(sender, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)));
	TEST_RES(sendto(sender, "x", 1, 0, (struct sockaddr *)&addr, sizeof(addr)), _ret == 1);
	struct pollfd event = { .fd = receiver, .events = POLLIN };
	TEST_RES(poll(&event, 1, 2000), _ret == 1 && (event.revents & POLLIN));
	char data[8] = {};
	union { struct cmsghdr alignment; char data[128]; } control = {};
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control.data, .msg_controllen = sizeof(control.data) };
	TEST_RES(recvmsg(receiver, &msg, 0), _ret == 1 && data[0] == 'x');
	int observed = -1;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(observed)))
			memcpy(&observed, CMSG_DATA(cmsg), sizeof(observed));
	}
	TEST_RES(observed, _ret == 37);
	TEST_SUCC(close(receiver));
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(full_receive_queue_keeps_the_first_datagrams_ttl)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&addr, sizeof(addr)));
	socklen_t length = sizeof(addr);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&addr, &length));
	int enabled = 1, ttl = 37;
	TEST_SUCC(setsockopt(receiver, IPPROTO_IP, IP_RECVTTL, &enabled, sizeof(enabled)));
	TEST_SUCC(setsockopt(sender, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)));
	TEST_RES(sendto(sender, "a", 1, 0, (struct sockaddr *)&addr, sizeof(addr)), _ret == 1);
	ttl = 38;
	TEST_SUCC(setsockopt(sender, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)));
	int sent = 0;
	for (int i = 0; i < 256; i++)
		if (sendto(sender, "b", 1, 0, (struct sockaddr *)&addr, sizeof(addr)) == 1) sent++;
	TEST_RES(sent, _ret == 256);
	char data[8] = {};
	union { struct cmsghdr alignment; char data[128]; } control = {};
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control.data, .msg_controllen = sizeof(control.data) };
	TEST_RES(recvmsg(receiver, &msg, 0), _ret == 1 && data[0] == 'a');
	int observed = -1;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(observed)))
			memcpy(&observed, CMSG_DATA(cmsg), sizeof(observed));
	}
	TEST_RES(observed, _ret == 37);
	TEST_SUCC(close(receiver));
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(received_icmp_error_is_matched_to_the_original_udp_socket)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int raw = TEST_SUCC(socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)));
	unsigned int loopback = TEST_RES(if_nametoindex("lo"), _ret != 0);
	struct in_addr local, peer;
	TEST_RES(inet_pton(AF_INET, "10.9.8.7", &local), _ret == 1);
	TEST_RES(inet_pton(AF_INET, "10.9.8.200", &peer), _ret == 1);
	TEST_SUCC(add_loopback_address(loopback, local));
	struct sockaddr_in source = { .sin_family = AF_INET, .sin_addr = local };
	struct sockaddr_in destination = source;
	TEST_SUCC(bind(sender, (struct sockaddr *)&source, sizeof(source)));
	TEST_SUCC(bind(receiver, (struct sockaddr *)&destination, sizeof(destination)));
	socklen_t length = sizeof(source);
	TEST_SUCC(getsockname(sender, (struct sockaddr *)&source, &length));
	length = sizeof(destination);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&destination, &length));
	int enabled = 1;
	TEST_SUCC(setsockopt(sender, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
	TEST_SUCC(connect(sender, (struct sockaddr *)&destination, sizeof(destination)));
	TEST_RES(sendto(sender, "probe", 5, 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == 5);
	struct {
		struct iphdr outer;
		struct icmphdr icmp;
		struct iphdr ip;
		struct udphdr udp;
		char payload[5];
	} packet = {
		.outer = { .version = 4, .ihl = 5, .tot_len = htons(sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + sizeof(struct udphdr) + 5),
			.ttl = 64, .protocol = IPPROTO_ICMP },
		.icmp = { .type = ICMP_TIME_EXCEEDED, .code = ICMP_EXC_TTL },
		.ip = { .version = 4, .ihl = 5, .tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 5),
			.ttl = 1, .protocol = IPPROTO_UDP },
		.udp = { .len = htons(sizeof(struct udphdr) + 5) },
		.payload = "probe",
	};
	packet.outer.saddr = peer.s_addr;
	packet.outer.daddr = local.s_addr;
	packet.ip.saddr = local.s_addr;
	packet.ip.daddr = local.s_addr;
	packet.udp.source = source.sin_port;
	packet.udp.dest = destination.sin_port;
	packet.ip.check = checksum(&packet.ip, sizeof(packet.ip));
	size_t packet_len = sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + sizeof(struct udphdr) + 5;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	packet.outer.check = checksum(&packet.outer, sizeof(packet.outer));
	struct sockaddr_ll target = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = (int)loopback, .sll_halen = ETH_ALEN };
	int soft = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	struct sockaddr_in soft_source = { .sin_family = AF_INET, .sin_addr = local };
	TEST_SUCC(bind(soft, (struct sockaddr *)&soft_source, sizeof(soft_source)));
	length = sizeof(soft_source);
	TEST_SUCC(getsockname(soft, (struct sockaddr *)&soft_source, &length));
	TEST_SUCC(connect(soft, (struct sockaddr *)&destination, sizeof(destination)));
	TEST_RES(send(soft, "probe", 5, 0), _ret == 5);
	struct pollfd soft_event = { .fd = soft, .events = POLLIN };
	packet.udp.source = soft_source.sin_port;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&soft_event, 1, 100), _ret == 0);
	packet.icmp.type = ICMP_DEST_UNREACH;
	packet.icmp.code = ICMP_HOST_UNREACH;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&soft_event, 1, 100), _ret == 0);
	int soft_error = -1;
	socklen_t error_length = sizeof(soft_error);
	TEST_SUCC(getsockopt(soft, SOL_SOCKET, SO_ERROR, &soft_error, &error_length));
	TEST_RES(soft_error, _ret == 0);
	packet.icmp.code = ICMP_PORT_UNREACH;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&soft_event, 1, 2000), _ret == 1 && (soft_event.revents & POLLERR));
	TEST_SUCC(getsockopt(soft, SOL_SOCKET, SO_ERROR, &soft_error, &error_length));
	TEST_RES(soft_error, _ret == ECONNREFUSED);
	TEST_SUCC(close(soft));
	packet.udp.source = source.sin_port;
	packet.icmp.type = ICMP_TIME_EXCEEDED;
	packet.icmp.code = ICMP_EXC_TTL;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	struct pollfd event = { .fd = sender, .events = POLLIN };
	packet.icmp.type = ICMP_DEST_UNREACH;
	packet.icmp.code = 16;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&event, 1, 100), _ret == 0);
	packet.icmp.type = ICMP_TIME_EXCEEDED;
	packet.icmp.code = ICMP_EXC_FRAGTIME;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&event, 1, 100), _ret == 0);
	packet.icmp.code = ICMP_EXC_TTL;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	packet.icmp.checksum ^= 1;
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&event, 1, 100), _ret == 0);
	packet.udp.source = htons((uint16_t)(ntohs(source.sin_port) ^ 1));
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&event, 1, 100), _ret == 0);
	packet.udp.source = source.sin_port;
	packet.udp.dest = htons((uint16_t)(ntohs(destination.sin_port) ^ 1));
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&event, 1, 100), _ret == 0);
	packet.udp.dest = destination.sin_port;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&event, 1, 2000), _ret == 1 && (event.revents & POLLERR));
	char data[16] = {};
	union { struct cmsghdr alignment; char data[128]; } control = {};
	struct sockaddr_in quoted_destination = {};
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	struct msghdr msg = { .msg_name = &quoted_destination, .msg_namelen = sizeof(quoted_destination),
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.data, .msg_controllen = sizeof(control.data) };
	TEST_RES(recvmsg(sender, &msg, MSG_ERRQUEUE), _ret == 5 && memcmp(data, "probe", 5) == 0);
	TEST_RES(quoted_destination.sin_port, _ret == destination.sin_port);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	TEST_RES(cmsg, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
	if (cmsg && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
		struct sock_extended_err error;
		memcpy(&error, CMSG_DATA(cmsg), sizeof(error));
		TEST_RES(error.ee_errno, _ret == EHOSTUNREACH);
		TEST_RES(error.ee_origin, _ret == SO_EE_ORIGIN_ICMP);
		TEST_RES(error.ee_type, _ret == ICMP_TIME_EXCEEDED);
		TEST_RES(error.ee_code, _ret == ICMP_EXC_TTL);
	}
	packet.icmp.type = ICMP_PARAMETERPROB;
	packet.icmp.code = 0;
	((unsigned char *)&packet.icmp)[4] = 17;
	packet.icmp.checksum = 0;
	packet.icmp.checksum = checksum(&packet.icmp, packet_len - sizeof(packet.outer));
	TEST_RES(sendto(raw, &packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target)), _ret == (ssize_t)packet_len);
	TEST_RES(poll(&event, 1, 2000), _ret == 1 && (event.revents & POLLERR));
	msg.msg_controllen = sizeof(control.data);
	msg.msg_namelen = sizeof(quoted_destination);
	TEST_RES(recvmsg(sender, &msg, MSG_ERRQUEUE), _ret == 5);
	cmsg = CMSG_FIRSTHDR(&msg);
	TEST_RES(cmsg, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
	if (cmsg && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
		struct sock_extended_err error;
		memcpy(&error, CMSG_DATA(cmsg), sizeof(error));
		TEST_RES(error.ee_errno, _ret == EPROTO);
		TEST_RES(error.ee_info, _ret == 17);
	}
	TEST_SUCC(close(raw));
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
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
	TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &enabled, sizeof(enabled)));
	TEST_SUCC(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled)));
	TEST_RES(sendto(fd, "probe", 5, 0, (struct sockaddr *)&addr, sizeof(addr)), _ret == 5);
	struct pollfd event = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&event, 1, 2000), _ret == 1 && (event.revents & POLLERR));
	int pending = 0;
	socklen_t pending_len = sizeof(pending);
	TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending, &pending_len));
	TEST_RES(pending, _ret == ECONNREFUSED);
	TEST_RES(poll(&event, 1, 0), _ret == 1 && (event.revents & POLLERR));
	char data[32] = {};
	union { struct cmsghdr alignment; char data[256]; } control = {};
	struct sockaddr_in destination = {};
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	struct msghdr msg = { .msg_name = &destination, .msg_namelen = sizeof(destination),
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.data, .msg_controllen = sizeof(control.data) };
	TEST_RES(recvmsg(fd, &msg, MSG_ERRQUEUE), _ret == 5 && memcmp(data, "probe", 5) == 0);
	TEST_RES(destination.sin_port, _ret == addr.sin_port);
	TEST_RES(destination.sin_addr.s_addr, _ret == addr.sin_addr.s_addr);
	TEST_RES(msg.msg_flags, _ret & MSG_ERRQUEUE);
	int saw_ttl = 0, saw_timestamp = 0;
	struct cmsghdr *cmsg, *error_cmsg = NULL;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
			int ttl;
			memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
			saw_ttl = ttl > 0 && ttl <= 255;
		}
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timespec))) {
			struct timespec timestamp;
			memcpy(&timestamp, CMSG_DATA(cmsg), sizeof(timestamp));
			saw_timestamp = timestamp.tv_sec > 0;
		}
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVERR)
			error_cmsg = cmsg;
	}
	TEST_RES(saw_ttl, _ret == 1);
	TEST_RES(saw_timestamp, _ret == 1);
	cmsg = error_cmsg;
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
	TEST_RES(poll(&event, 1, 0), _ret == 0);
	TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending, &pending_len));
	TEST_RES(pending, _ret == 0);
	TEST_RES(sendto(fd, "again", 5, 0, (struct sockaddr *)&addr, sizeof(addr)), _ret == 5);
	TEST_RES(poll(&event, 1, 2000), _ret == 1 && (event.revents & POLLERR));
	msg.msg_controllen = sizeof(control.data);
	msg.msg_namelen = sizeof(destination);
	TEST_RES(recvmsg(fd, &msg, MSG_ERRQUEUE), _ret == 5 && memcmp(data, "again", 5) == 0);
	TEST_SUCC(close(fd));
}
END_TEST()
