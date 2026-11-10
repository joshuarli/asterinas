// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"
#include "rtnl_common.h"

#include <linux/if_addr.h>
#include <sys/wait.h>

#define DEVICE "lo"
#define LOCAL_ADDRESS "10.9.8.7"
#define GATEWAY "10.9.8.1"

static uint32_t sequence = 300;

static struct in_addr parse(const char *text)
{
	struct in_addr address;

	inet_pton(AF_INET, text, &address);
	return address;
}

static int request(uint16_t type, uint16_t flags, const void *payload, size_t length)
{
	struct rtnl_reply reply;
	int fd = rtnl_open(0);

	sequence++;
	if (fd < 0 ||
	    rtnl_send(fd, type, NLM_F_REQUEST | NLM_F_ACK | flags, sequence, payload, length) ||
	    rtnl_receive(fd, &reply, sequence)) {
		close(fd);
		return -1;
	}
	close(fd);
	return reply.saw_error ? reply.error : -1000;
}

static int address(uint16_t type, const char *local, int prefix_length)
{
	uint8_t payload[128] = { 0 };
	struct ifaddrmsg *header = (struct ifaddrmsg *)payload;
	struct in_addr value = parse(local);
	size_t length = NLMSG_ALIGN(sizeof(*header));

	header->ifa_family = AF_INET;
	header->ifa_prefixlen = prefix_length;
	header->ifa_index = if_nametoindex(DEVICE);
	length = rtnl_put(payload, length, IFA_LOCAL, &value, 4);
	length = rtnl_put(payload, length, IFA_ADDRESS, &value, 4);
	return request(type, type == RTM_NEWADDR ? NLM_F_CREATE | NLM_F_EXCL : 0, payload, length);
}

struct route {
	const char *destination;
	int prefix_length;
	const char *gateway;
	int ifindex;
	uint32_t priority;
	int with_priority;
	int protocol;
	int scope;
	int type;
	int table;
	uint32_t source_prefix_attribute;
	int with_source;
	int tos;
};

static int change_route(uint16_t type, struct route route)
{
	uint8_t payload[256] = { 0 };
	struct rtmsg *header = (struct rtmsg *)payload;
	size_t length = NLMSG_ALIGN(sizeof(*header));
	int add = type == RTM_NEWROUTE;
	uint32_t ifindex = route.ifindex ? route.ifindex : if_nametoindex(DEVICE);

	header->rtm_family = AF_INET;
	header->rtm_dst_len = route.prefix_length;
	header->rtm_table = route.table ? route.table : RT_TABLE_MAIN;
	header->rtm_protocol = route.protocol;
	header->rtm_scope = add ? (route.scope ? route.scope : route.gateway ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK) : RT_SCOPE_NOWHERE;
	header->rtm_type = add ? (route.type ? route.type : RTN_UNICAST) : 0;
	header->rtm_tos = route.tos;
	if (route.prefix_length) {
		struct in_addr destination = parse(route.destination);

		length = rtnl_put(payload, length, RTA_DST, &destination, 4);
	}
	if (route.gateway) {
		struct in_addr gateway = parse(route.gateway);

		length = rtnl_put(payload, length, RTA_GATEWAY, &gateway, 4);
	}
	length = rtnl_put(payload, length, RTA_OIF, &ifindex, 4);
	if (route.with_priority)
		length = rtnl_put(payload, length, RTA_PRIORITY, &route.priority, 4);
	if (route.with_source) {
		struct in_addr source = parse(LOCAL_ADDRESS);

		length = rtnl_put(payload, length, RTA_PREFSRC, &source, 4);
	}
	return request(type, add ? NLM_F_CREATE | NLM_F_EXCL : 0, payload, length);
}

static int add(struct route route)
{
	return change_route(RTM_NEWROUTE, route);
}

static int delete(struct route route)
{
	return change_route(RTM_DELROUTE, route);
}

struct found_route {
	int present;
	int protocol;
	int scope;
	int type;
	uint32_t priority;
	int has_gateway;
	int attribute_order_is_linux;
};

static struct found_route find_route(const char *destination, int prefix_length, uint32_t priority)
{
	struct found_route found = { 0 };
	struct rtnl_reply reply;
	struct rtmsg body = { .rtm_family = AF_INET };
	struct nlmsghdr *header;
	struct in_addr wanted = parse(destination);
	int fd = rtnl_open(0);

	sequence++;
	rtnl_send(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sequence, &body, sizeof(body));
	rtnl_receive(fd, &reply, sequence);
	close(fd);
	for (header = rtnl_first(&reply); header; header = rtnl_next(&reply, header)) {
		struct rtmsg *route = NLMSG_DATA(header);
		struct rtattr *first = RTM_RTA(route);
		size_t length = RTM_PAYLOAD(header);
		struct rtattr *table = rtnl_find(first, length, RTA_TABLE);
		struct rtattr *dst = rtnl_find(first, length, RTA_DST);
		struct rtattr *gateway = rtnl_find(first, length, RTA_GATEWAY);
		struct rtattr *priority_attribute = rtnl_find(first, length, RTA_PRIORITY);
		uint32_t route_priority = priority_attribute ? *(uint32_t *)RTA_DATA(priority_attribute) : 0;
		struct rtattr *attribute = first;
		uint16_t expected[5];
		int count = 0, index = 0;

		if (!table || *(uint32_t *)RTA_DATA(table) != RT_TABLE_MAIN ||
		    route->rtm_dst_len != prefix_length || route_priority != priority ||
		    (prefix_length && (!dst || memcmp(RTA_DATA(dst), &wanted, 4))))
			continue;
		found.present = 1;
		found.protocol = route->rtm_protocol;
		found.scope = route->rtm_scope;
		found.type = route->rtm_type;
		found.priority = route_priority;
		found.has_gateway = gateway != NULL;
		expected[count++] = RTA_TABLE;
		if (prefix_length)
			expected[count++] = RTA_DST;
		if (priority_attribute)
			expected[count++] = RTA_PRIORITY;
		if (gateway)
			expected[count++] = RTA_GATEWAY;
		expected[count++] = RTA_OIF;
		found.attribute_order_is_linux = 1;
		for (; RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length))
			if (index >= count || attribute->rta_type != expected[index++])
				found.attribute_order_is_linux = 0;
		found.attribute_order_is_linux &= index == count;
	}
	return found;
}

FN_SETUP(address)
{
	CHECK(address(RTM_NEWADDR, LOCAL_ADDRESS, 24));
}
END_SETUP()

FN_TEST(a_gateway_route_is_listed_with_its_protocol_scope_and_metric)
{
	struct found_route found;

	TEST_RES(add((struct route){ .destination = "0.0.0.0", .gateway = GATEWAY, .protocol = RTPROT_DHCP, .with_priority = 1, .priority = 100 }),
		 _ret == 0);
	found = find_route("0.0.0.0", 0, 100);
	TEST_RES(found.present, _ret == 1);
	TEST_RES(found.protocol, _ret == RTPROT_DHCP);
	TEST_RES(found.scope, _ret == RT_SCOPE_UNIVERSE);
	TEST_RES(found.type, _ret == RTN_UNICAST);
	TEST_RES(found.has_gateway, _ret == 1);
	TEST_RES(found.attribute_order_is_linux, _ret == 1);
}
END_TEST()

FN_TEST(a_second_route_to_the_same_destination_needs_another_metric)
{
	TEST_RES(add((struct route){ .destination = "0.0.0.0", .gateway = GATEWAY, .protocol = RTPROT_DHCP, .with_priority = 1, .priority = 100 }),
		 _ret == -EEXIST);
	TEST_RES(add((struct route){ .destination = "0.0.0.0", .gateway = GATEWAY, .protocol = RTPROT_DHCP, .with_priority = 1, .priority = 200 }),
		 _ret == 0);
	TEST_RES(find_route("0.0.0.0", 0, 200).present, _ret == 1);
}
END_TEST()

FN_TEST(a_link_route_has_no_gateway)
{
	struct found_route found;

	TEST_RES(add((struct route){ .destination = "192.168.50.0", .prefix_length = 24, .protocol = RTPROT_STATIC }),
		 _ret == 0);
	found = find_route("192.168.50.0", 24, 0);
	TEST_RES(found.present, _ret == 1);
	TEST_RES(found.scope, _ret == RT_SCOPE_LINK);
	TEST_RES(found.has_gateway, _ret == 0);
	TEST_RES(found.attribute_order_is_linux, _ret == 1);
}
END_TEST()

FN_TEST(invalid_requests_fail_with_their_errors)
{
	TEST_RES(add((struct route){ .destination = "10.99.0.0", .prefix_length = 16, .gateway = "172.16.0.1" }),
		 _ret == -ENETUNREACH);
	TEST_RES(add((struct route){ .destination = "10.20.0.5", .prefix_length = 16, .gateway = GATEWAY }),
		 _ret == -EINVAL);
	TEST_RES(add((struct route){ .destination = "10.20.0.0", .prefix_length = 33, .gateway = GATEWAY }),
		 _ret == -EINVAL);
	TEST_RES(add((struct route){ .destination = "10.20.0.0", .prefix_length = 16, .gateway = GATEWAY, .ifindex = 4242 }),
		 _ret == -ENETUNREACH);
	TEST_RES(add((struct route){ .destination = "10.20.0.0", .prefix_length = 16, .ifindex = 4242 }),
		 _ret == -ENODEV);
	TEST_RES(find_route("10.20.0.0", 16, 0).present, _ret == 0);
}
END_TEST()

FN_TEST(removing_a_route_matches_its_destination_and_filters)
{
	TEST_RES(delete((struct route){ .destination = "0.0.0.0", .gateway = GATEWAY, .protocol = RTPROT_DHCP, .with_priority = 1, .priority = 100 }),
		 _ret == 0);
	TEST_RES(find_route("0.0.0.0", 0, 100).present, _ret == 0);
	TEST_RES(find_route("0.0.0.0", 0, 200).present, _ret == 1);
	TEST_RES(delete((struct route){ .destination = "0.0.0.0", .gateway = GATEWAY, .protocol = RTPROT_DHCP, .with_priority = 1, .priority = 100 }),
		 _ret == -ESRCH);
	TEST_RES(delete((struct route){ .destination = "0.0.0.0", .gateway = "10.9.8.2", .protocol = RTPROT_DHCP }),
		 _ret == -ESRCH);
	TEST_RES(delete((struct route){ .destination = "0.0.0.0", .gateway = GATEWAY }), _ret == 0);
	TEST_RES(find_route("0.0.0.0", 0, 200).present, _ret == 0);
}
END_TEST()

FN_TEST(changing_routes_requires_net_admin)
{
	pid_t child = CHECK(fork());

	if (child == 0) {
		if (setresuid(65534, 65534, 65534))
			_exit(2);
		_exit(add((struct route){ .destination = "10.20.0.0", .prefix_length = 16, .gateway = GATEWAY }) == -EPERM ? 0 : 1);
	}
	int status;

	TEST_RES(waitpid(child, &status, 0), WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_RES(find_route("10.20.0.0", 16, 0).present, _ret == 0);
}
END_TEST()

FN_TEST(removing_an_address_keeps_the_routes_but_the_gateway_becomes_unreachable)
{
	TEST_RES(address(RTM_DELADDR, LOCAL_ADDRESS, 24), _ret == 0);
	TEST_RES(find_route("192.168.50.0", 24, 0).present, _ret == 1);
	TEST_RES(add((struct route){ .destination = "10.20.0.0", .prefix_length = 16, .gateway = GATEWAY }),
		 _ret == -ENETUNREACH);
	TEST_RES(delete((struct route){ .destination = "192.168.50.0", .prefix_length = 24 }), _ret == 0);
}
END_TEST()

FN_TEST(a_reject_route_cannot_have_a_gateway)
{
	CHECK(address(RTM_NEWADDR, LOCAL_ADDRESS, 24));
	TEST_RES(add((struct route){ .destination = "10.20.0.0", .prefix_length = 16, .gateway = GATEWAY, .type = RTN_BLACKHOLE }),
		 _ret == -EINVAL);
	TEST_RES(address(RTM_DELADDR, LOCAL_ADDRESS, 24), _ret == 0);
}
END_TEST()

#ifdef __asterinas__
FN_TEST(unsupported_route_requests_are_rejected)
{
	CHECK(address(RTM_NEWADDR, LOCAL_ADDRESS, 24));
	TEST_RES(add((struct route){ .destination = "10.20.0.0", .prefix_length = 16, .gateway = GATEWAY, .with_source = 1 }),
		 _ret == -EOPNOTSUPP);
	TEST_RES(add((struct route){ .destination = "10.20.0.0", .prefix_length = 16, .gateway = GATEWAY, .tos = 4 }),
		 _ret == -EOPNOTSUPP);
	TEST_RES(delete((struct route){ .destination = LOCAL_ADDRESS, .prefix_length = 32, .table = RT_TABLE_LOCAL }),
		 _ret == -EOPNOTSUPP);
	TEST_RES(address(RTM_DELADDR, LOCAL_ADDRESS, 24), _ret == 0);
}
END_TEST()
#endif
