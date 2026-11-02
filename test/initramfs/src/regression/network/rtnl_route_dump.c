// SPDX-License-Identifier: MPL-2.0

#include "../common/test.h"
#include "rtnl_common.h"

static int dump(uint16_t type, int family, uint32_t sequence,
		struct rtnl_reply *reply)
{
	struct rtmsg body = { .rtm_family = family };
	int fd = rtnl_open(0);

	if (fd < 0 || rtnl_send(fd, type, NLM_F_REQUEST | NLM_F_DUMP, sequence,
				&body, sizeof(body)) ||
	    rtnl_receive(fd, reply, sequence)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static struct rtmsg *find_route(struct rtnl_reply *reply, uint32_t table,
				const char *destination, int prefix_length,
				struct rtattr **attributes, size_t *attribute_length)
{
	struct in_addr wanted;
	struct nlmsghdr *header;

	inet_pton(AF_INET, destination, &wanted);
	for (header = rtnl_first(reply); header; header = rtnl_next(reply, header)) {
		struct rtmsg *route = NLMSG_DATA(header);
		struct rtattr *first = RTM_RTA(route);
		size_t length = RTM_PAYLOAD(header);
		struct rtattr *table_attribute = rtnl_find(first, length, RTA_TABLE);
		struct rtattr *destination_attribute = rtnl_find(first, length, RTA_DST);

		if (header->nlmsg_type != RTM_NEWROUTE ||
		    route->rtm_family != AF_INET ||
		    route->rtm_dst_len != prefix_length || !table_attribute ||
		    *(uint32_t *)RTA_DATA(table_attribute) != table ||
		    !destination_attribute ||
		    memcmp(RTA_DATA(destination_attribute), &wanted, 4))
			continue;
		*attributes = first;
		*attribute_length = length;
		return route;
	}
	return NULL;
}

static int attribute_order_is(struct rtattr *first, size_t length,
			      const uint16_t *types, int count)
{
	struct rtattr *attribute = first;
	int index = 0;

	for (; RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length))
		if (index >= count || attribute->rta_type != types[index++])
			return 0;
	return index == count;
}

static int route_matches(struct rtnl_reply *reply, uint32_t table,
			 const char *destination, int prefix_length, int scope,
			 int type)
{
	struct rtattr *attributes;
	size_t length;
	struct rtmsg *route = find_route(reply, table, destination, prefix_length,
					 &attributes, &length);
	struct rtattr *oif, *prefsrc;
	const uint16_t order[] = { RTA_TABLE, RTA_DST, RTA_PREFSRC, RTA_OIF };
	struct in_addr loopback;

	inet_pton(AF_INET, "127.0.0.1", &loopback);
	if (!route)
		return 0;
	oif = rtnl_find(attributes, length, RTA_OIF);
	prefsrc = rtnl_find(attributes, length, RTA_PREFSRC);
	return route->rtm_protocol == RTPROT_KERNEL &&
	       route->rtm_scope == scope && route->rtm_type == type &&
	       route->rtm_tos == 0 && route->rtm_src_len == 0 &&
	       route->rtm_flags == 0 && oif &&
	       *(uint32_t *)RTA_DATA(oif) == if_nametoindex("lo") && prefsrc &&
	       !memcmp(RTA_DATA(prefsrc), &loopback, 4) &&
	       attribute_order_is(attributes, length, order, 4);
}

static struct rtnl_reply routes;
static struct rtnl_reply unspecified_routes;
static struct rtnl_reply rules;

FN_TEST(ipv4_route_dump_is_a_complete_multipart_reply)
{
	TEST_SUCC(dump(RTM_GETROUTE, AF_INET, 7, &routes));
	TEST_RES(routes.saw_done, _ret == 1);
	TEST_RES(routes.multi_flags_valid, _ret == 1);
	TEST_RES(routes.count, _ret >= 3);
}
END_TEST()

FN_TEST(loopback_routes_are_local_kernel_routes)
{
	TEST_RES(route_matches(&routes, RT_TABLE_LOCAL, "127.0.0.0", 8,
			       RT_SCOPE_HOST, RTN_LOCAL),
		 _ret == 1);
	TEST_RES(route_matches(&routes, RT_TABLE_LOCAL, "127.0.0.1", 32,
			       RT_SCOPE_HOST, RTN_LOCAL),
		 _ret == 1);
	TEST_RES(route_matches(&routes, RT_TABLE_LOCAL, "127.255.255.255", 32,
			       RT_SCOPE_LINK, RTN_BROADCAST),
		 _ret == 1);
}
END_TEST()

FN_TEST(an_unspecified_family_dump_includes_ipv4_routes_first)
{
	struct nlmsghdr *header;

	TEST_SUCC(dump(RTM_GETROUTE, AF_UNSPEC, 8, &unspecified_routes));
	TEST_RES(unspecified_routes.saw_done, _ret == 1);
	TEST_RES(route_matches(&unspecified_routes, RT_TABLE_LOCAL, "127.0.0.1",
			       32, RT_SCOPE_HOST, RTN_LOCAL),
		 _ret == 1);
	header = rtnl_first(&unspecified_routes);
	TEST_RES(((struct rtmsg *)NLMSG_DATA(header))->rtm_family,
		 _ret == AF_INET);
}
END_TEST()

FN_TEST(ipv4_rule_dump_lists_the_default_policy)
{
	struct nlmsghdr *header;
	const uint32_t priorities[] = { 0, 32766, 32767 };
	const uint32_t tables[] = { RT_TABLE_LOCAL, RT_TABLE_MAIN,
				    RT_TABLE_DEFAULT };
	int index = 0;

	TEST_SUCC(dump(RTM_GETRULE, AF_INET, 9, &rules));
	TEST_RES(rules.saw_done, _ret == 1);
	TEST_RES(rules.multi_flags_valid, _ret == 1);
	TEST_RES(rules.count, _ret == 3);
	for (header = rtnl_first(&rules); header && index < 3;
	     header = rtnl_next(&rules, header), index++) {
		struct fib_rule_hdr *rule = NLMSG_DATA(header);
		struct rtattr *first = (struct rtattr *)((uint8_t *)rule +
							 NLMSG_ALIGN(sizeof(*rule)));
		size_t length = header->nlmsg_len - NLMSG_LENGTH(sizeof(*rule));
		struct rtattr *table = rtnl_find(first, length, FRA_TABLE);
		struct rtattr *priority = rtnl_find(first, length, FRA_PRIORITY);
		struct rtattr *suppress =
			rtnl_find(first, length, FRA_SUPPRESS_PREFIXLEN);
		struct rtattr *protocol = rtnl_find(first, length, FRA_PROTOCOL);

		TEST_RES(header->nlmsg_type, _ret == RTM_NEWRULE);
		TEST_RES(rule->family, _ret == AF_INET);
		TEST_RES(rule->action, _ret == FR_ACT_TO_TBL);
		TEST_RES(rule->dst_len == 0 && rule->src_len == 0 &&
				 rule->tos == 0 && rule->flags == 0,
			 _ret == 1);
		TEST_RES(table && *(uint32_t *)RTA_DATA(table) == tables[index],
			 _ret == 1);
		TEST_RES(suppress && *(uint32_t *)RTA_DATA(suppress) == 0xffffffffu,
			 _ret == 1);
		TEST_RES(protocol && *(uint8_t *)RTA_DATA(protocol) == RTPROT_KERNEL,
			 _ret == 1);
		TEST_RES((priorities[index] == 0) == (priority == NULL) &&
				 (!priority || *(uint32_t *)RTA_DATA(priority) ==
						       priorities[index]),
			 _ret == 1);
	}
}
END_TEST()

FN_TEST(a_dump_of_a_family_without_routes_dumps_every_family)
{
	struct rtnl_reply other;

	TEST_SUCC(dump(RTM_GETROUTE, AF_UNIX, 10, &other));
	TEST_RES(other.saw_done, _ret == 1);
	TEST_RES(route_matches(&other, RT_TABLE_LOCAL, "127.0.0.1", 32,
			       RT_SCOPE_HOST, RTN_LOCAL),
		 _ret == 1);
}
END_TEST()
