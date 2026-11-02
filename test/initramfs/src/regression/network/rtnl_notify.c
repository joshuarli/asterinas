// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"
#include "rtnl_common.h"

#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <poll.h>
#include <stdarg.h>
#include <sys/ioctl.h>

#define DEVICE "lo"
#define LOCAL_ADDRESS "10.9.8.7"
#define SECOND_ADDRESS "10.9.8.9"
#define OTHER_ADDRESS "10.8.8.7"
#define GATEWAY "10.9.8.1"

static int control_socket;
static int requester;
static int observer;
static uint32_t requester_port;
static uint32_t sequence = 700;
static char transcript[65536];
static size_t transcript_length;

static void line(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void line(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	transcript_length += vsnprintf(transcript + transcript_length,
				       sizeof(transcript) - transcript_length,
				       format, arguments);
	va_end(arguments);
	transcript[transcript_length++] = '\n';
	transcript[transcript_length] = 0;
}

static const char *name_of(uint32_t index)
{
	static char names[4][IFNAMSIZ];
	static int next;
	char *name = names[next++ % 4];

	return if_indextoname(index, name) ? name : "?";
}

static const char *owner_of(uint32_t port)
{
	return port == 0 ? "0" : port == requester_port ? "self" : "other";
}

static const char *address_text(const void *data)
{
	static char texts[4][INET_ADDRSTRLEN];
	static int next;
	char *text = texts[next++ % 4];

	inet_ntop(AF_INET, data, text, INET_ADDRSTRLEN);
	return text;
}

static void describe_link(const struct nlmsghdr *header)
{
	struct ifinfomsg *body = NLMSG_DATA(header);
	struct rtattr *first = IFLA_RTA(body);
	size_t length = IFLA_PAYLOAD(header);
	struct rtattr *operstate = rtnl_find(first, length, IFLA_OPERSTATE);

	line("NEWLINK %s family=%d type=%d flags=0x%x change=0x%x oper=%d hdr=0x%x seq=%u pid=%s",
	     name_of(body->ifi_index), body->ifi_family, body->ifi_type,
	     body->ifi_flags, body->ifi_change,
	     operstate ? *(uint8_t *)RTA_DATA(operstate) : -1,
	     header->nlmsg_flags, header->nlmsg_seq,
	     owner_of(header->nlmsg_pid));
}

static void attribute_order(struct rtattr *first, size_t length, char *order)
{
	struct rtattr *attribute = first;

	order[0] = 0;
	for (; RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length))
		sprintf(order + strlen(order), "%d,", attribute->rta_type);
}

static void describe_address(const struct nlmsghdr *header)
{
	struct ifaddrmsg *body = NLMSG_DATA(header);
	struct rtattr *first = IFA_RTA(body);
	size_t length = IFA_PAYLOAD(header);
	struct rtattr *local = rtnl_find(first, length, IFA_LOCAL);
	struct rtattr *broadcast = rtnl_find(first, length, IFA_BROADCAST);
	struct rtattr *label = rtnl_find(first, length, IFA_LABEL);
	char order[64];

	attribute_order(first, length, order);
	line("%s %s %s/%d scope=%d flags=0x%x label=%s brd=%s attrs=%s hdr=0x%x seq=%u pid=%s",
	     header->nlmsg_type == RTM_NEWADDR ? "NEWADDR" : "DELADDR",
	     name_of(body->ifa_index), local ? address_text(RTA_DATA(local)) : "-",
	     body->ifa_prefixlen, body->ifa_scope, body->ifa_flags,
	     label ? (char *)RTA_DATA(label) : "-",
	     broadcast ? address_text(RTA_DATA(broadcast)) : "-", order,
	     header->nlmsg_flags, header->nlmsg_seq, owner_of(header->nlmsg_pid));
}

static void describe_route(const struct nlmsghdr *header)
{
	struct rtmsg *body = NLMSG_DATA(header);
	struct rtattr *first = RTM_RTA(body);
	size_t length = RTM_PAYLOAD(header);
	struct rtattr *table = rtnl_find(first, length, RTA_TABLE);
	struct rtattr *destination = rtnl_find(first, length, RTA_DST);
	struct rtattr *gateway = rtnl_find(first, length, RTA_GATEWAY);
	struct rtattr *source = rtnl_find(first, length, RTA_PREFSRC);
	struct rtattr *priority = rtnl_find(first, length, RTA_PRIORITY);
	struct rtattr *oif = rtnl_find(first, length, RTA_OIF);
	char order[64];

	attribute_order(first, length, order);
	line("%s %s/%d table=%u proto=%d scope=%d type=%d oif=%s gw=%s src=%s prio=%u attrs=%s hdr=0x%x seq=%u pid=%s",
	     header->nlmsg_type == RTM_NEWROUTE ? "NEWROUTE" : "DELROUTE",
	     destination ? address_text(RTA_DATA(destination)) : "default",
	     body->rtm_dst_len,
	     table ? *(uint32_t *)RTA_DATA(table) : body->rtm_table,
	     body->rtm_protocol, body->rtm_scope, body->rtm_type,
	     oif ? name_of(*(uint32_t *)RTA_DATA(oif)) : "-",
	     gateway ? address_text(RTA_DATA(gateway)) : "-",
	     source ? address_text(RTA_DATA(source)) : "-",
	     priority ? *(uint32_t *)RTA_DATA(priority) : 0, order,
	     header->nlmsg_flags, header->nlmsg_seq, owner_of(header->nlmsg_pid));
}

static void drain(int fd, int wait_ms)
{
	for (;;) {
		uint8_t datagram[RTNL_BUFFER_SIZE];
		struct pollfd waiting = { .fd = fd, .events = POLLIN };
		struct nlmsghdr *header = (struct nlmsghdr *)datagram;
		ssize_t received;
		int messages = 0;

		if (poll(&waiting, 1, wait_ms) != 1)
			return;
		received = recv(fd, datagram, sizeof(datagram), MSG_DONTWAIT);
		if (received < 0) {
			line("RECV errno=%d", errno);
			continue;
		}
		for (; NLMSG_OK(header, (size_t)received);
		     header = NLMSG_NEXT(header, received)) {
			if (messages++)
				line("SAME DATAGRAM");
			switch (header->nlmsg_type) {
			case RTM_NEWLINK:
				describe_link(header);
				break;
			case RTM_NEWADDR:
			case RTM_DELADDR:
				describe_address(header);
				break;
			case RTM_NEWROUTE:
			case RTM_DELROUTE:
				describe_route(header);
				break;
			case NLMSG_ERROR:
				line("ACK errno=%d seq=%u hdr=0x%x",
				     ((struct nlmsgerr *)NLMSG_DATA(header))->error,
				     header->nlmsg_seq, header->nlmsg_flags);
				break;
			default:
				line("TYPE %d", header->nlmsg_type);
			}
		}
	}
}

static char observed[65536];
static int failed_steps;

static void check_step(const char *label, const char *expected)
{
	transcript_length = 0;
	transcript[0] = 0;
	drain(requester, 150);
	memcpy(observed, transcript, transcript_length + 1);
	transcript_length = 0;
	transcript[0] = 0;
	drain(observer, 0);

	if (strcmp(observed, expected)) {
		failed_steps++;
		fprintf(stderr, "step `%s` differs\n--- observed\n%s--- expected\n%s",
			label, observed, expected);
	}
	{
		char stripped[65536] = "";
		char *cursor = observed;

		while (*cursor) {
			char *end = strchr(cursor, '\n');
			size_t size = end - cursor + 1;

			if (strncmp(cursor, "ACK ", 4))
				strncat(stripped, cursor, size);
			cursor += size;
		}
		if (strcmp(stripped, transcript)) {
			failed_steps++;
			fprintf(stderr, "step `%s`: the observer saw other notifications\n--- observer\n%s--- requester\n%s",
				label, transcript, stripped);
		}
	}
}

#define STEP(label, action, expected) \
	do {                          \
		(void)(action);       \
		check_step(label, expected); \
	} while (0)

static int request_socket;
static int request_acknowledged = 1;

static int request(uint16_t type, uint16_t flags, const void *payload, size_t length)
{
	sequence++;
	return rtnl_send(request_socket, type,
			 NLM_F_REQUEST | (request_acknowledged ? NLM_F_ACK : 0) | flags,
			 sequence, payload, length);
}

static int address_with_broadcast(uint16_t type, const char *local,
				  int prefix_length, const char *broadcast)
{
	uint8_t payload[128] = { 0 };
	struct ifaddrmsg *header = (struct ifaddrmsg *)payload;
	struct in_addr value;
	size_t length = NLMSG_ALIGN(sizeof(*header));

	inet_pton(AF_INET, local, &value);
	header->ifa_family = AF_INET;
	header->ifa_prefixlen = prefix_length;
	header->ifa_index = if_nametoindex(DEVICE);
	length = rtnl_put(payload, length, IFA_LOCAL, &value, 4);
	length = rtnl_put(payload, length, IFA_ADDRESS, &value, 4);
	if (broadcast) {
		inet_pton(AF_INET, broadcast, &value);
		length = rtnl_put(payload, length, IFA_BROADCAST, &value, 4);
	}
	return request(type, type == RTM_NEWADDR ? NLM_F_CREATE | NLM_F_EXCL : 0,
		       payload, length);
}

static int address(uint16_t type, const char *local, int prefix_length)
{
	return address_with_broadcast(type, local, prefix_length, NULL);
}

static int route(uint16_t type, const char *destination, int prefix_length,
		 const char *gateway, uint32_t priority, int protocol)
{
	uint8_t payload[256] = { 0 };
	struct rtmsg *header = (struct rtmsg *)payload;
	size_t length = NLMSG_ALIGN(sizeof(*header));
	int add = type == RTM_NEWROUTE;
	uint32_t ifindex = if_nametoindex(DEVICE);
	struct in_addr value;

	header->rtm_family = AF_INET;
	header->rtm_dst_len = prefix_length;
	header->rtm_table = RT_TABLE_MAIN;
	header->rtm_protocol = protocol;
	header->rtm_scope = add ? (gateway ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK) :
				  RT_SCOPE_NOWHERE;
	header->rtm_type = add ? RTN_UNICAST : 0;
	if (prefix_length) {
		inet_pton(AF_INET, destination, &value);
		length = rtnl_put(payload, length, RTA_DST, &value, 4);
	}
	if (gateway) {
		inet_pton(AF_INET, gateway, &value);
		length = rtnl_put(payload, length, RTA_GATEWAY, &value, 4);
	}
	length = rtnl_put(payload, length, RTA_OIF, &ifindex, 4);
	if (priority)
		length = rtnl_put(payload, length, RTA_PRIORITY, &priority, 4);
	return request(type, add ? NLM_F_CREATE | NLM_F_EXCL : 0, payload, length);
}

static int set_up(int up)
{
	struct ifreq interface = { 0 };

	strncpy(interface.ifr_name, DEVICE, IFNAMSIZ - 1);
	if (ioctl(control_socket, SIOCGIFFLAGS, &interface))
		return -1;
	interface.ifr_flags = up ? interface.ifr_flags | IFF_UP :
				    interface.ifr_flags & ~IFF_UP;
	return ioctl(control_socket, SIOCSIFFLAGS, &interface);
}

FN_SETUP(sockets)
{
	struct sockaddr_nl bound = { 0 };
	socklen_t size = sizeof(bound);

	control_socket = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	requester = CHECK(rtnl_open(RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE));
	observer = CHECK(rtnl_open(RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE));
	CHECK(getsockname(requester, (struct sockaddr *)&bound, &size));
	requester_port = bound.nl_pid;
	request_socket = requester;
}
END_SETUP()

FN_TEST(notifications)
{
	STEP("link down", (set_up(0)),
		"NEWLINK lo family=0 type=772 flags=0x8 change=0x1 oper=2 hdr=0x0 seq=0 pid=0\n");
	STEP("link up", (set_up(1)),
		"NEWLINK lo family=0 type=772 flags=0x10049 change=0x1 oper=0 hdr=0x0 seq=0 pid=0\n"
		"NEWROUTE 127.255.255.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=127.0.0.1 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n");
	STEP("link up again", (set_up(1)),
		"");
	STEP("add primary address", (address(RTM_NEWADDR, LOCAL_ADDRESS, 24)),
		"NEWADDR lo 10.9.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=701 pid=self\n"
		"NEWROUTE 10.9.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.9.8.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.9.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=701 hdr=0x100\n");
	STEP("add secondary address", (address(RTM_NEWADDR, SECOND_ADDRESS, 24)),
		"NEWADDR lo 10.9.8.9/24 scope=0 flags=0x81 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=702 pid=self\n"
		"NEWROUTE 10.9.8.9/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=702 hdr=0x100\n");
	STEP("add duplicate address", (address(RTM_NEWADDR, LOCAL_ADDRESS, 24)),
		"ACK errno=-17 seq=703 hdr=0x0\n");
	STEP("add second network", (address(RTM_NEWADDR, OTHER_ADDRESS, 24)),
		"NEWADDR lo 10.8.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=704 pid=self\n"
		"NEWROUTE 10.8.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.8.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.8.8.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.8.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.8.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.8.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=704 hdr=0x100\n");
	STEP("add default route", (route(RTM_NEWROUTE, "0.0.0.0", 0, GATEWAY, 100, RTPROT_DHCP)),
		"NEWROUTE default/0 table=254 proto=16 scope=0 type=1 oif=lo gw=10.9.8.1 src=- prio=100 attrs=15,6,5,4, hdr=0x600 seq=705 pid=self\n"
		"ACK errno=0 seq=705 hdr=0x100\n");
	STEP("add duplicate route", (route(RTM_NEWROUTE, "0.0.0.0", 0, GATEWAY, 100, RTPROT_DHCP)),
		"ACK errno=-17 seq=706 hdr=0x0\n");
	STEP("add link route", (route(RTM_NEWROUTE, "192.168.50.0", 24, NULL, 0, RTPROT_STATIC)),
		"NEWROUTE 192.168.50.0/24 table=254 proto=4 scope=253 type=1 oif=lo gw=- src=- prio=0 attrs=15,1,4, hdr=0x600 seq=707 pid=self\n"
		"ACK errno=0 seq=707 hdr=0x100\n");
	STEP("delete link route", (route(RTM_DELROUTE, "192.168.50.0", 24, NULL, 0, RTPROT_STATIC)),
		"DELROUTE 192.168.50.0/24 table=254 proto=4 scope=253 type=1 oif=lo gw=- src=- prio=0 attrs=15,1,4, hdr=0x0 seq=708 pid=self\n"
		"ACK errno=0 seq=708 hdr=0x100\n");
	STEP("delete missing route", (route(RTM_DELROUTE, "192.168.50.0", 24, NULL, 0, RTPROT_STATIC)),
		"ACK errno=-3 seq=709 hdr=0x0\n");
	STEP("add link route again", (route(RTM_NEWROUTE, "192.168.50.0", 24, NULL, 0, RTPROT_STATIC)),
		"NEWROUTE 192.168.50.0/24 table=254 proto=4 scope=253 type=1 oif=lo gw=- src=- prio=0 attrs=15,1,4, hdr=0x600 seq=710 pid=self\n"
		"ACK errno=0 seq=710 hdr=0x100\n");
	STEP("link down with addresses and routes", (set_up(0)),
		"NEWLINK lo family=0 type=772 flags=0x8 change=0x1 oper=2 hdr=0x0 seq=0 pid=0\n");
	STEP("link up with addresses and routes", (set_up(1)),
		"NEWLINK lo family=0 type=772 flags=0x10049 change=0x1 oper=0 hdr=0x0 seq=0 pid=0\n"
		"NEWROUTE 127.255.255.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=127.0.0.1 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.9.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.8.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.8.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n");
	STEP("delete secondary address", (address(RTM_DELADDR, SECOND_ADDRESS, 24)),
		"DELADDR lo 10.9.8.9/24 scope=0 flags=0x81 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=711 pid=self\n"
		"DELROUTE 10.9.8.9/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"ACK errno=0 seq=711 hdr=0x100\n");
	STEP("delete primary address", (address(RTM_DELADDR, LOCAL_ADDRESS, 24)),
		"DELADDR lo 10.9.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=712 pid=self\n"
		"DELROUTE 10.9.8.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.9.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.9.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"ACK errno=0 seq=712 hdr=0x100\n");
	STEP("delete last network address", (address(RTM_DELADDR, OTHER_ADDRESS, 24)),
		"DELADDR lo 10.8.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=713 pid=self\n"
		"DELROUTE 10.8.8.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.8.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.8.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.8.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.8.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.8.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"ACK errno=0 seq=713 hdr=0x100\n");
	STEP("delete link route after addresses", (route(RTM_DELROUTE, "192.168.50.0", 24, NULL, 0, RTPROT_STATIC)),
		"ACK errno=-3 seq=714 hdr=0x0\n");
	STEP("add address with broadcast", (address_with_broadcast(RTM_NEWADDR, "10.7.7.7", 24, "10.7.7.200")),
		"NEWADDR lo 10.7.7.7/24 scope=0 flags=0x80 label=lo brd=10.7.7.200 attrs=1,2,4,3,8,6, hdr=0x0 seq=715 pid=self\n"
		"NEWROUTE 10.7.7.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.7.7.200/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.7.7.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.7.7.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=715 hdr=0x100\n");
	STEP("delete address with broadcast", (address_with_broadcast(RTM_DELADDR, "10.7.7.7", 24, "10.7.7.200")),
		"DELADDR lo 10.7.7.7/24 scope=0 flags=0x80 label=lo brd=10.7.7.200 attrs=1,2,4,3,8,6, hdr=0x0 seq=716 pid=self\n"
		"DELROUTE 10.7.7.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.7.7.200/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.7.7.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.7.7.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.7.7.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"ACK errno=0 seq=716 hdr=0x100\n");
	STEP("add primary and two secondaries", (address(RTM_NEWADDR, LOCAL_ADDRESS, 24), address(RTM_NEWADDR, SECOND_ADDRESS, 24), address(RTM_NEWADDR, "10.9.8.11", 24)),
		"NEWADDR lo 10.9.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=717 pid=self\n"
		"NEWROUTE 10.9.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.9.8.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"NEWROUTE 10.9.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=717 hdr=0x100\n"
		"NEWADDR lo 10.9.8.9/24 scope=0 flags=0x81 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=718 pid=self\n"
		"NEWROUTE 10.9.8.9/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=718 hdr=0x100\n"
		"NEWADDR lo 10.9.8.11/24 scope=0 flags=0x81 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=719 pid=self\n"
		"NEWROUTE 10.9.8.11/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=719 hdr=0x100\n");
	STEP("delete primary with secondaries", (address(RTM_DELADDR, LOCAL_ADDRESS, 24)),
		"DELADDR lo 10.9.8.9/24 scope=0 flags=0x81 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=720 pid=self\n"
		"DELROUTE 10.9.8.9/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELADDR lo 10.9.8.11/24 scope=0 flags=0x81 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=720 pid=self\n"
		"DELROUTE 10.9.8.11/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELADDR lo 10.9.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=720 pid=self\n"
		"DELROUTE 10.9.8.0/24 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.9.8.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"DELROUTE 10.9.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"ACK errno=0 seq=720 hdr=0x100\n");
	STEP("link down without addresses", (set_up(0)),
		"NEWLINK lo family=0 type=772 flags=0x8 change=0x1 oper=2 hdr=0x0 seq=0 pid=0\n");
	STEP("add address while down", (address(RTM_NEWADDR, LOCAL_ADDRESS, 24)),
		"NEWADDR lo 10.9.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=721 pid=self\n"
		"NEWROUTE 10.9.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n"
		"ACK errno=0 seq=721 hdr=0x100\n");
	STEP("add route while down", (route(RTM_NEWROUTE, "192.168.60.0", 24, NULL, 0, RTPROT_STATIC)),
		"ACK errno=-100 seq=722 hdr=0x0\n");
	STEP("delete address while down", (address(RTM_DELADDR, LOCAL_ADDRESS, 24)),
		"DELADDR lo 10.9.8.7/24 scope=0 flags=0x80 label=lo brd=- attrs=1,2,3,8,6, hdr=0x0 seq=723 pid=self\n"
		"DELROUTE 10.9.8.7/32 table=255 proto=2 scope=254 type=2 oif=lo gw=- src=10.9.8.7 prio=0 attrs=15,1,7,4, hdr=0x0 seq=0 pid=0\n"
		"ACK errno=0 seq=723 hdr=0x100\n");
	STEP("link up with no extra address", (set_up(1)),
		"NEWLINK lo family=0 type=772 flags=0x10049 change=0x1 oper=0 hdr=0x0 seq=0 pid=0\n"
		"NEWROUTE 127.255.255.255/32 table=255 proto=2 scope=253 type=3 oif=lo gw=- src=127.0.0.1 prio=0 attrs=15,1,7,4, hdr=0x600 seq=0 pid=0\n");
	TEST_RES(failed_steps, _ret == 0);
}
END_TEST()

static int dump_link_change(void)
{
	struct ifinfomsg body = { .ifi_family = AF_UNSPEC };
	struct rtnl_reply reply;
	struct nlmsghdr *header;
	int fd = rtnl_open(0);
	int found = -1;

	if (fd < 0 || rtnl_send(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 31,
				&body, sizeof(body)) ||
	    rtnl_receive(fd, &reply, 31)) {
		close(fd);
		return -1;
	}
	close(fd);
	for (header = rtnl_first(&reply); header; header = rtnl_next(&reply, header)) {
		struct ifinfomsg *link = NLMSG_DATA(header);

		if (link->ifi_index == (int)if_nametoindex(DEVICE))
			found = link->ifi_change == 0;
	}
	return found;
}

FN_TEST(a_dump_reports_no_change_mask)
{
	TEST_RES(dump_link_change(), _ret == 1);
}
END_TEST()

static int received_type(int fd)
{
	uint8_t datagram[RTNL_BUFFER_SIZE];
	struct pollfd waiting = { .fd = fd, .events = POLLIN };

	if (poll(&waiting, 1, 150) != 1)
		return -1;
	if (recv(fd, datagram, sizeof(datagram), MSG_DONTWAIT) < 0)
		return -2;
	return ((struct nlmsghdr *)datagram)->nlmsg_type;
}

static int sender;

FN_SETUP(sender)
{
	sender = CHECK(rtnl_open(0));
}
END_SETUP()

FN_TEST(group_membership_is_joined_and_left_by_group_number)
{
	int group = RTNLGRP_IPV4_ROUTE;
	int listener = CHECK(rtnl_open(0));

	request_socket = sender;
	request_acknowledged = 0;
	TEST_SUCC(setsockopt(listener, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)));
	route(RTM_NEWROUTE, "192.168.80.0", 24, NULL, 0, RTPROT_STATIC);
	TEST_RES(received_type(listener), _ret == RTM_NEWROUTE);
	TEST_SUCC(setsockopt(listener, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, &group, sizeof(group)));
	route(RTM_DELROUTE, "192.168.80.0", 24, NULL, 0, RTPROT_STATIC);
	TEST_RES(received_type(listener), _ret == -1);
	close(listener);
}
END_TEST()

FN_TEST(a_receive_with_dont_wait_does_not_block_on_an_idle_socket)
{
	char buffer[256];
	int listener = CHECK(rtnl_open(RTMGRP_IPV4_ROUTE));

	TEST_ERRNO(recv(listener, buffer, sizeof(buffer), MSG_DONTWAIT), EAGAIN);
	close(listener);
}
END_TEST()

FN_TEST(a_full_receive_queue_reports_one_overrun_and_keeps_its_messages)
{
	int listener = CHECK(rtnl_open(RTMGRP_IPV4_ROUTE));
	uint8_t datagram[RTNL_BUFFER_SIZE];
	int index;

	CHECK(fcntl(listener, F_SETFL, O_NONBLOCK));

	request_socket = sender;
	request_acknowledged = 0;
	for (index = 0; index < 3000; index++) {
		route(RTM_NEWROUTE, "192.168.81.0", 24, NULL, 0, RTPROT_STATIC);
		route(RTM_DELROUTE, "192.168.81.0", 24, NULL, 0, RTPROT_STATIC);
	}
	TEST_ERRNO(recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT), ENOBUFS);
	TEST_RES(recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT),
		 _ret > 0 && ((struct nlmsghdr *)datagram)->nlmsg_type == RTM_NEWROUTE);
	while (recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT) > 0)
		;
	TEST_ERRNO(recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT), EAGAIN);
	route(RTM_NEWROUTE, "192.168.81.0", 24, NULL, 0, RTPROT_STATIC);
	TEST_RES(received_type(listener), _ret == RTM_NEWROUTE);
	route(RTM_DELROUTE, "192.168.81.0", 24, NULL, 0, RTPROT_STATIC);
	close(listener);
	request_socket = requester;
	request_acknowledged = 1;
}
END_TEST()
