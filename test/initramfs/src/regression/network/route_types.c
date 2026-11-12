// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"
#include "rtnl_common.h"

#include <linux/if_addr.h>

#define DEVICE "lo"

static uint32_t sequence = 400;

static struct in_addr parse(const char *text)
{
	struct in_addr address;

	inet_pton(AF_INET, text, &address);
	return address;
}

static int request(uint16_t type, uint16_t flags, const void *payload,
		   size_t length)
{
	struct rtnl_reply reply;
	int fd = rtnl_open(0);

	sequence++;
	if (fd < 0 ||
	    rtnl_send(fd, type, NLM_F_REQUEST | NLM_F_ACK | flags, sequence,
		      payload, length) ||
	    rtnl_receive(fd, &reply, sequence)) {
		close(fd);
		return -1;
	}
	close(fd);
	return reply.saw_error ? reply.error : -1000;
}

struct route_request {
	const char *destination;
	int prefix_length;
	int scope;
	int type;
	int protocol;
	uint32_t priority;
	int with_priority;
	uint32_t ifindex;
	const char *gateway;
};

static int add_route(struct route_request route)
{
	uint8_t payload[128] = { 0 };
	struct rtmsg *header = (struct rtmsg *)payload;
	size_t length = NLMSG_ALIGN(sizeof(*header));

	header->rtm_family = AF_INET;
	header->rtm_dst_len = route.prefix_length;
	header->rtm_table = RT_TABLE_MAIN;
	header->rtm_protocol = route.protocol;
	header->rtm_scope = route.scope;
	header->rtm_type = route.type;
	if (route.prefix_length) {
		struct in_addr destination = parse(route.destination);

		length = rtnl_put(payload, length, RTA_DST, &destination, 4);
	}
	if (route.ifindex) {
		uint32_t ifindex = route.ifindex;

		length = rtnl_put(payload, length, RTA_OIF, &ifindex, 4);
	}
	if (route.gateway) {
		struct in_addr gateway = parse(route.gateway);

		length = rtnl_put(payload, length, RTA_GATEWAY, &gateway, 4);
	}
	if (route.with_priority)
		length = rtnl_put(payload, length, RTA_PRIORITY,
				  &route.priority, 4);
	return request(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, payload,
		       length);
}

static int delete_route(struct route_request route)
{
	uint8_t payload[128] = { 0 };
	struct rtmsg *header = (struct rtmsg *)payload;
	size_t length = NLMSG_ALIGN(sizeof(*header));

	header->rtm_family = AF_INET;
	header->rtm_dst_len = route.prefix_length;
	header->rtm_table = RT_TABLE_MAIN;
	header->rtm_protocol = route.protocol;
	header->rtm_scope = RT_SCOPE_NOWHERE;
	header->rtm_type = 0;
	if (route.prefix_length) {
		struct in_addr destination = parse(route.destination);

		length = rtnl_put(payload, length, RTA_DST, &destination, 4);
	}
	if (route.ifindex) {
		uint32_t ifindex = route.ifindex;

		length = rtnl_put(payload, length, RTA_OIF, &ifindex, 4);
	}
	if (route.gateway) {
		struct in_addr gateway = parse(route.gateway);

		length = rtnl_put(payload, length, RTA_GATEWAY, &gateway, 4);
	}
	if (route.with_priority)
		length = rtnl_put(payload, length, RTA_PRIORITY,
				  &route.priority, 4);
	return request(RTM_DELROUTE, 0, payload, length);
}

struct found_route {
	int count;
	int family;
	int destination_prefix_length;
	int source_prefix_length;
	int tos;
	int table;
	int protocol;
	int scope;
	int type;
	int flags;
	int has_gateway;
	uint32_t gateway_address;
	uint32_t ifindex;
	int has_preferred_source;
	int attributes_match;
};

static int attributes_match(struct rtattr *first, size_t length,
			    uint32_t table, const struct in_addr *destination,
			    int prefix_length, uint32_t ifindex)
{
	uint16_t expected[3];
	int count = 0, index = 0;
	struct rtattr *attribute = first;
	size_t remaining = length;

	expected[count++] = RTA_TABLE;
	if (prefix_length)
		expected[count++] = RTA_DST;
	expected[count++] = RTA_OIF;
	for (; RTA_OK(attribute, remaining); attribute = RTA_NEXT(attribute, remaining)) {
		if (index >= count || attribute->rta_type != expected[index++])
			return 0;
	}
	if (index != count)
		return 0;

	struct rtattr *table_attribute = rtnl_find(first, length, RTA_TABLE);
	struct rtattr *oif = rtnl_find(first, length, RTA_OIF);

	if (!table_attribute || *(uint32_t *)RTA_DATA(table_attribute) != table ||
	    !oif || *(uint32_t *)RTA_DATA(oif) != ifindex)
		return 0;
	if (prefix_length) {
		struct rtattr *dst = rtnl_find(first, length, RTA_DST);

		if (!dst || memcmp(RTA_DATA(dst), destination, 4))
			return 0;
	}
	return 1;
}

static struct found_route find_route(const char *destination,
				     int prefix_length)
{
	struct found_route found = { 0 };
	struct rtnl_reply reply;
	struct rtmsg body = { .rtm_family = AF_INET };
	struct nlmsghdr *header;
	struct in_addr wanted = parse(destination);
	uint32_t ifindex = if_nametoindex(DEVICE);
	int fd = rtnl_open(0);

	sequence++;
	if (fd < 0 ||
	    rtnl_send(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sequence,
		      &body, sizeof(body)) ||
	    rtnl_receive(fd, &reply, sequence)) {
		close(fd);
		return found;
	}
	close(fd);
	for (header = rtnl_first(&reply); header;
	     header = rtnl_next(&reply, header)) {
		struct rtmsg *route = NLMSG_DATA(header);
		struct rtattr *first = RTM_RTA(route);
		size_t length = RTM_PAYLOAD(header);
		struct rtattr *table_attribute =
			rtnl_find(first, length, RTA_TABLE);
		struct rtattr *dst = rtnl_find(first, length, RTA_DST);

		if (header->nlmsg_type != RTM_NEWROUTE ||
		    route->rtm_family != AF_INET ||
		    route->rtm_dst_len != prefix_length ||
		    !table_attribute ||
		    *(uint32_t *)RTA_DATA(table_attribute) != RT_TABLE_MAIN ||
		    (prefix_length && (!dst || memcmp(RTA_DATA(dst), &wanted, 4))))
			continue;
		found.count++;
		found.family = route->rtm_family;
		found.destination_prefix_length = route->rtm_dst_len;
		found.source_prefix_length = route->rtm_src_len;
		found.tos = route->rtm_tos;
		found.table = route->rtm_table;
		found.protocol = route->rtm_protocol;
		found.scope = route->rtm_scope;
		found.type = route->rtm_type;
		found.flags = route->rtm_flags;
		struct rtattr *gateway = rtnl_find(first, length, RTA_GATEWAY);
		struct rtattr *oif = rtnl_find(first, length, RTA_OIF);

		found.has_gateway = gateway != NULL;
		if (gateway)
			found.gateway_address = *(uint32_t *)RTA_DATA(gateway);
		if (oif)
			found.ifindex = *(uint32_t *)RTA_DATA(oif);
		found.has_preferred_source =
			rtnl_find(first, length, RTA_PREFSRC) != NULL;
		found.attributes_match = attributes_match(
			first, length, RT_TABLE_MAIN, &wanted, prefix_length,
			ifindex);
	}
	return found;
}

static struct route_request device_route(const char *destination,
					 int prefix_length, int type,
					 int scope)
{
	return (struct route_request){ .destination = destination,
				       .prefix_length = prefix_length,
				       .scope = scope,
				       .type = type,
				       .protocol = RTPROT_STATIC,
				       .ifindex = if_nametoindex(DEVICE) };
}

#define EXPECT_ROUTE(found_value, prefix_length, scope_value, type_value)  \
	do {                                                                 \
		struct found_route _found = (found_value);                    \
		TEST_RES(_found.count, _ret == 1);                           \
		TEST_RES(_found.family, _ret == AF_INET);                    \
		TEST_RES(_found.destination_prefix_length,                   \
			 _ret == (prefix_length));                           \
		TEST_RES(_found.source_prefix_length, _ret == 0);            \
		TEST_RES(_found.tos, _ret == 0);                             \
		TEST_RES(_found.table, _ret == RT_TABLE_MAIN);               \
		TEST_RES(_found.protocol, _ret == RTPROT_STATIC);            \
		TEST_RES(_found.scope, _ret == (scope_value));               \
		TEST_RES(_found.type, _ret == (type_value));                 \
		TEST_RES(_found.flags, _ret == 0);                           \
		TEST_RES(_found.has_gateway, _ret == 0);                     \
		TEST_RES(_found.has_preferred_source, _ret == 0);            \
		TEST_RES(_found.attributes_match, _ret == 1);                \
	} while (0)

FN_TEST(a_local_route_through_a_device_is_installed)
{
	struct route_request route = device_route("10.30.0.0", 16, RTN_LOCAL,
						   RT_SCOPE_HOST);

	TEST_RES(add_route(route), _ret == 0);
	EXPECT_ROUTE(find_route("10.30.0.0", 16), 16, RT_SCOPE_HOST, RTN_LOCAL);
	TEST_RES(add_route(route), _ret == -EEXIST);
	TEST_RES(delete_route(route), _ret == 0);
	TEST_RES(find_route("10.30.0.0", 16).count, _ret == 0);
	TEST_RES(delete_route(route), _ret == -ESRCH);
}
END_TEST()

FN_TEST(a_local_route_needs_the_host_scope)
{
	struct route_request route = device_route("10.30.1.0", 24, RTN_LOCAL,
						   RT_SCOPE_LINK);

	TEST_RES(add_route(route), _ret == -EINVAL);
	TEST_RES(add_route((struct route_request){ .destination = "10.30.1.0",
						    .prefix_length = 24,
						    .scope = RT_SCOPE_NOWHERE,
						    .type = RTN_LOCAL,
						    .protocol = RTPROT_STATIC,
						    .ifindex = if_nametoindex(DEVICE) }),
		 _ret == -EINVAL);
	TEST_RES(find_route("10.30.1.0", 24).count, _ret == 0);
}
END_TEST()

FN_TEST(a_broadcast_route_through_a_device_is_installed)
{
	struct route_request route = device_route("10.31.0.0", 16, RTN_BROADCAST,
						   RT_SCOPE_LINK);

	TEST_RES(add_route(route), _ret == 0);
	EXPECT_ROUTE(find_route("10.31.0.0", 16), 16, RT_SCOPE_LINK,
		     RTN_BROADCAST);
	TEST_RES(add_route(route), _ret == -EEXIST);
	TEST_RES(delete_route(route), _ret == 0);
	TEST_RES(find_route("10.31.0.0", 16).count, _ret == 0);
}
END_TEST()

FN_TEST(a_broadcast_route_has_a_minimum_scope)
{
	TEST_RES(add_route(device_route("10.31.1.0", 24, RTN_BROADCAST,
					RT_SCOPE_UNIVERSE)),
		 _ret == -EINVAL);
	TEST_RES(find_route("10.31.1.0", 24).count, _ret == 0);
}
END_TEST()

FN_TEST(an_anycast_route_through_a_device_is_installed)
{
	struct route_request route = device_route("10.32.0.0", 16, RTN_ANYCAST,
						   RT_SCOPE_LINK);

	TEST_RES(add_route(route), _ret == 0);
	EXPECT_ROUTE(find_route("10.32.0.0", 16), 16, RT_SCOPE_LINK, RTN_ANYCAST);
	TEST_RES(add_route(route), _ret == -EEXIST);
	TEST_RES(delete_route(route), _ret == 0);
	TEST_RES(find_route("10.32.0.0", 16).count, _ret == 0);
}
END_TEST()

FN_TEST(an_anycast_route_has_a_minimum_scope)
{
	TEST_RES(add_route(device_route("10.32.1.0", 24, RTN_ANYCAST,
					RT_SCOPE_UNIVERSE)),
		 _ret == -EINVAL);
	TEST_RES(find_route("10.32.1.0", 24).count, _ret == 0);
}
END_TEST()

FN_TEST(a_multicast_route_through_a_device_is_installed)
{
	struct route_request route = device_route("10.33.0.0", 16, RTN_MULTICAST,
						   RT_SCOPE_UNIVERSE);
	struct route_request linked = device_route("10.34.0.0", 16,
						    RTN_MULTICAST, RT_SCOPE_LINK);

	TEST_RES(add_route(route), _ret == 0);
	EXPECT_ROUTE(find_route("10.33.0.0", 16), 16, RT_SCOPE_UNIVERSE,
		     RTN_MULTICAST);
	TEST_RES(add_route(linked), _ret == 0);
	EXPECT_ROUTE(find_route("10.34.0.0", 16), 16, RT_SCOPE_LINK,
		     RTN_MULTICAST);
	TEST_RES(add_route(route), _ret == -EEXIST);
	TEST_RES(delete_route(route), _ret == 0);
	TEST_RES(delete_route(linked), _ret == 0);
	TEST_RES(find_route("10.33.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.34.0.0", 16).count, _ret == 0);
}
END_TEST()

FN_TEST(a_multicast_route_may_not_have_the_nowhere_scope)
{
	struct route_request route = device_route("10.33.1.0", 24, RTN_MULTICAST,
						   RT_SCOPE_NOWHERE);

	TEST_RES(add_route(route), _ret == -EINVAL);
	TEST_RES(find_route("10.33.1.0", 24).count, _ret == 0);
}
END_TEST()

FN_TEST(a_route_of_a_device_type_needs_a_device)
{
	TEST_RES(add_route((struct route_request){ .destination = "10.35.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_HOST,
						    .type = RTN_LOCAL,
						    .protocol = RTPROT_STATIC }),
		 _ret == -ENODEV);
	TEST_RES(add_route((struct route_request){ .destination = "10.41.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_LINK,
						    .type = RTN_BROADCAST,
						    .protocol = RTPROT_STATIC }),
		 _ret == -ENODEV);
	TEST_RES(add_route((struct route_request){ .destination = "10.42.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_LINK,
						    .type = RTN_ANYCAST,
						    .protocol = RTPROT_STATIC }),
		 _ret == -ENODEV);
	TEST_RES(add_route((struct route_request){ .destination = "10.43.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_UNIVERSE,
						    .type = RTN_MULTICAST,
						    .protocol = RTPROT_STATIC }),
		 _ret == -ENODEV);
	TEST_RES(find_route("10.35.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.41.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.42.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.43.0.0", 16).count, _ret == 0);
}
END_TEST()

FN_TEST(a_route_of_a_device_type_needs_an_existing_device)
{
	TEST_RES(add_route((struct route_request){ .destination = "10.36.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_HOST,
						    .type = RTN_LOCAL,
						    .protocol = RTPROT_STATIC,
						    .ifindex = 4242 }),
		 _ret == -ENODEV);
	TEST_RES(add_route((struct route_request){ .destination = "10.44.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_LINK,
						    .type = RTN_BROADCAST,
						    .protocol = RTPROT_STATIC,
						    .ifindex = 4242 }),
		 _ret == -ENODEV);
	TEST_RES(add_route((struct route_request){ .destination = "10.45.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_LINK,
						    .type = RTN_ANYCAST,
						    .protocol = RTPROT_STATIC,
						    .ifindex = 4242 }),
		 _ret == -ENODEV);
	TEST_RES(add_route((struct route_request){ .destination = "10.46.0.0",
						    .prefix_length = 16,
						    .scope = RT_SCOPE_UNIVERSE,
						    .type = RTN_MULTICAST,
						    .protocol = RTPROT_STATIC,
						    .ifindex = 4242 }),
		 _ret == -ENODEV);
	TEST_RES(find_route("10.36.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.44.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.45.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.46.0.0", 16).count, _ret == 0);
}
END_TEST()

FN_TEST(an_unknown_route_type_is_invalid)
{
	TEST_RES(add_route(device_route("10.37.0.0", 16, RTN_MAX + 1,
					RT_SCOPE_HOST)),
		 _ret == -EINVAL);
	TEST_RES(add_route(device_route("10.47.0.0", 16, RTN_NAT,
					RT_SCOPE_HOST)),
		 _ret == -EINVAL);
	TEST_RES(add_route(device_route("10.48.0.0", 16, RTN_XRESOLVE,
					RT_SCOPE_HOST)),
		 _ret == -EINVAL);
	TEST_RES(find_route("10.37.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.47.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.48.0.0", 16).count, _ret == 0);
}
END_TEST()

FN_TEST(the_device_route_types_share_the_dump)
{
	struct route_request local =
		device_route("10.38.0.0", 16, RTN_LOCAL, RT_SCOPE_HOST);
	struct route_request broadcast =
		device_route("10.49.0.0", 16, RTN_BROADCAST, RT_SCOPE_LINK);
	struct route_request anycast =
		device_route("10.50.0.0", 16, RTN_ANYCAST, RT_SCOPE_LINK);
	struct route_request multicast =
		device_route("10.51.0.0", 16, RTN_MULTICAST, RT_SCOPE_UNIVERSE);

	TEST_RES(add_route(local), _ret == 0);
	TEST_RES(add_route(broadcast), _ret == 0);
	TEST_RES(add_route(anycast), _ret == 0);
	TEST_RES(add_route(multicast), _ret == 0);
	EXPECT_ROUTE(find_route("10.38.0.0", 16), 16, RT_SCOPE_HOST, RTN_LOCAL);
	EXPECT_ROUTE(find_route("10.49.0.0", 16), 16, RT_SCOPE_LINK,
		     RTN_BROADCAST);
	EXPECT_ROUTE(find_route("10.50.0.0", 16), 16, RT_SCOPE_LINK, RTN_ANYCAST);
	EXPECT_ROUTE(find_route("10.51.0.0", 16), 16, RT_SCOPE_UNIVERSE,
		     RTN_MULTICAST);
	TEST_RES(delete_route(local), _ret == 0);
	TEST_RES(delete_route(broadcast), _ret == 0);
	TEST_RES(delete_route(anycast), _ret == 0);
	TEST_RES(delete_route(multicast), _ret == 0);
	TEST_RES(find_route("10.38.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.49.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.50.0.0", 16).count, _ret == 0);
	TEST_RES(find_route("10.51.0.0", 16).count, _ret == 0);
}
END_TEST()

FN_TEST(gateways_follow_the_route_type_scope_and_device_rules)
{
	const int types[] = { RTN_LOCAL, RTN_BROADCAST, RTN_ANYCAST,
			      RTN_MULTICAST };
	const int scopes[] = { RT_SCOPE_UNIVERSE, RT_SCOPE_LINK,
			       RT_SCOPE_HOST, RT_SCOPE_NOWHERE };
	uint32_t lo = if_nametoindex(DEVICE);
	const uint32_t devices[] = { 0, lo, 4242 };

	for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
		for (size_t s = 0; s < sizeof(scopes) / sizeof(scopes[0]); s++) {
			for (size_t d = 0; d < sizeof(devices) / sizeof(devices[0]); d++) {
				struct route_request route = device_route(
					"10.60.0.0", 16, types[t], scopes[s]);
				int result, expected = -EINVAL;

				route.gateway = "127.0.0.2";
				route.ifindex = devices[d];
				if ((types[t] == RTN_MULTICAST || scopes[s] == RT_SCOPE_LINK) &&
				    types[t] != RTN_LOCAL && scopes[s] < RT_SCOPE_HOST)
					expected = d == 2 ? -ENETUNREACH : 0;
				result = add_route(route);
				TEST_RES(result, _ret == expected);
				printf("NET_GATEWAY type=%d scope=%d device=%s errno=%d\n",
				       types[t], scopes[s],
				       d == 0 ? "inferred" : d == 1 ? "lo" : "missing",
				       result);
				if (result == 0) {
					TEST_RES(find_route("10.60.0.0", 16).count, _ret == 1);
					struct found_route found = find_route("10.60.0.0", 16);

					TEST_RES(found.has_gateway, _ret == 1);
					TEST_RES(found.gateway_address, _ret == parse(route.gateway).s_addr);
					TEST_RES(found.ifindex, _ret == lo);
					TEST_RES(found.scope, _ret == scopes[s]);
					TEST_RES(found.type, _ret == types[t]);
					TEST_RES(delete_route(route), _ret == 0);
				}
			}
		}
	}
}
END_TEST()
