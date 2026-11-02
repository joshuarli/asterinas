// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"
#include "rtnl_common.h"

#include <linux/if_addr.h>
#include <netinet/in.h>
#include <sys/wait.h>

#define DEVICE "lo"
#define PRIMARY "10.9.8.7"
#define SECONDARY "10.9.8.9"

static uint32_t sequence = 100;

static struct in_addr parse(const char *text)
{
	struct in_addr address;

	inet_pton(AF_INET, text, &address);
	return address;
}

struct address_request {
	const char *local;
	int prefix_length;
	int ifindex;
	const char *label;
	const char *broadcast;
	int with_local;
	uint32_t flags_attribute;
	int with_flags;
	int with_lifetimes;
};

static size_t build(uint8_t *buffer, const struct address_request *request)
{
	struct ifaddrmsg *header = (struct ifaddrmsg *)buffer;
	size_t length = NLMSG_ALIGN(sizeof(*header));
	struct in_addr local = parse(request->local);

	header->ifa_family = AF_INET;
	header->ifa_prefixlen = request->prefix_length;
	header->ifa_index = request->ifindex;
	if (request->with_local)
		length = rtnl_put(buffer, length, IFA_LOCAL, &local, 4);
	length = rtnl_put(buffer, length, IFA_ADDRESS, &local, 4);
	if (request->broadcast) {
		struct in_addr broadcast = parse(request->broadcast);

		length = rtnl_put(buffer, length, IFA_BROADCAST, &broadcast, 4);
	}
	if (request->label)
		length = rtnl_put(buffer, length, IFA_LABEL, request->label,
				  strlen(request->label) + 1);
	if (request->with_flags)
		length = rtnl_put(buffer, length, IFA_FLAGS,
				  &request->flags_attribute, 4);
	if (request->with_lifetimes) {
		struct ifa_cacheinfo info = { .ifa_prefered = 60,
					      .ifa_valid = 120 };

		length = rtnl_put(buffer, length, IFA_CACHEINFO, &info,
				  sizeof(info));
	}
	return length;
}

static int change(uint16_t type, uint16_t flags, struct address_request request)
{
	uint8_t payload[512] = { 0 };
	struct rtnl_reply reply;
	int fd = rtnl_open(0);
	size_t length;

	if (!request.ifindex)
		request.ifindex = if_nametoindex(DEVICE);
	length = build(payload, &request);
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

static int add(struct address_request request)
{
	return change(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, request);
}

static int delete(struct address_request request)
{
	return change(RTM_DELADDR, 0, request);
}

static int dump(uint16_t type, int family, struct rtnl_reply *reply)
{
	struct rtgenmsg body = { .rtgen_family = family };
	int fd = rtnl_open(0);

	sequence++;
	if (fd < 0 || rtnl_send(fd, type, NLM_F_REQUEST | NLM_F_DUMP, sequence,
				&body, sizeof(body)) ||
	    rtnl_receive(fd, reply, sequence)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

struct found_address {
	int present;
	unsigned int flags;
	int scope;
	int prefix_length;
	char label[IFNAMSIZ];
	int attribute_order_is_linux;
	int position;
};

static struct found_address find_address(const char *text)
{
	struct found_address found = { 0 };
	struct rtnl_reply reply;
	struct nlmsghdr *header;
	struct in_addr wanted = parse(text);
	int position = 0;

	dump(RTM_GETADDR, AF_INET, &reply);
	for (header = rtnl_first(&reply); header; header = rtnl_next(&reply, header)) {
		struct ifaddrmsg *address = NLMSG_DATA(header);
		struct rtattr *first = IFA_RTA(address);
		size_t length = IFA_PAYLOAD(header);
		struct rtattr *local = rtnl_find(first, length, IFA_LOCAL);
		struct rtattr *label = rtnl_find(first, length, IFA_LABEL);
		struct rtattr *attribute = first;
		const uint16_t order[] = { IFA_ADDRESS, IFA_LOCAL, IFA_LABEL,
					   IFA_FLAGS, IFA_CACHEINFO };
		int index = 0;

		if (address->ifa_index != if_nametoindex(DEVICE))
			continue;
		position++;
		if (!local || memcmp(RTA_DATA(local), &wanted, 4))
			continue;
		found.present = 1;
		found.position = position;
		found.flags = address->ifa_flags;
		found.scope = address->ifa_scope;
		found.prefix_length = address->ifa_prefixlen;
		snprintf(found.label, sizeof(found.label), "%s",
			 (char *)RTA_DATA(label));
		found.attribute_order_is_linux = 1;
		for (; RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length))
			if (index >= 5 || attribute->rta_type != order[index++])
				found.attribute_order_is_linux = 0;
		found.attribute_order_is_linux &= index == 5;
	}
	return found;
}

static int route_with(uint32_t table, const char *destination, int prefix_length,
		      int type, int scope, const char *source)
{
	struct rtnl_reply reply;
	struct nlmsghdr *header;
	struct in_addr wanted = parse(destination);
	struct in_addr preferred = parse(source);

	dump(RTM_GETROUTE, AF_INET, &reply);
	for (header = rtnl_first(&reply); header; header = rtnl_next(&reply, header)) {
		struct rtmsg *route = NLMSG_DATA(header);
		struct rtattr *first = RTM_RTA(route);
		size_t length = RTM_PAYLOAD(header);
		struct rtattr *route_table = rtnl_find(first, length, RTA_TABLE);
		struct rtattr *route_destination = rtnl_find(first, length, RTA_DST);
		struct rtattr *route_source = rtnl_find(first, length, RTA_PREFSRC);

		if (route_table && *(uint32_t *)RTA_DATA(route_table) == table &&
		    route_destination &&
		    !memcmp(RTA_DATA(route_destination), &wanted, 4) &&
		    route->rtm_dst_len == prefix_length &&
		    route->rtm_type == type && route->rtm_scope == scope &&
		    route->rtm_protocol == RTPROT_KERNEL && route_source &&
		    !memcmp(RTA_DATA(route_source), &preferred, 4))
			return 1;
	}
	return 0;
}

static int bind_tcp(const char *text)
{
	struct sockaddr_in address = { .sin_family = AF_INET,
				       .sin_addr = parse(text) };
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int result = bind(fd, (struct sockaddr *)&address, sizeof(address)) ?
			     errno :
			     0;

	close(fd);
	errno = 0;
	return result;
}

FN_TEST(a_new_primary_address_is_reported_and_creates_its_routes)
{
	struct found_address found;

	TEST_RES(add((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1 }),
		 _ret == 0);
	found = find_address(PRIMARY);
	TEST_RES(found.present, _ret == 1);
	TEST_RES(found.flags, _ret == IFA_F_PERMANENT);
	TEST_RES(found.scope, _ret == RT_SCOPE_UNIVERSE);
	TEST_RES(found.prefix_length, _ret == 24);
	TEST_RES(strcmp(found.label, DEVICE), _ret == 0);
	TEST_RES(found.attribute_order_is_linux, _ret == 1);
	TEST_RES(route_with(RT_TABLE_LOCAL, PRIMARY, 32, RTN_LOCAL, RT_SCOPE_HOST, PRIMARY), _ret == 1);
	TEST_RES(route_with(RT_TABLE_LOCAL, "10.9.8.255", 32, RTN_BROADCAST, RT_SCOPE_LINK, PRIMARY), _ret == 1);
	TEST_RES(route_with(RT_TABLE_LOCAL, "10.9.8.0", 24, RTN_LOCAL, RT_SCOPE_HOST, PRIMARY), _ret == 1);
	TEST_RES(bind_tcp(PRIMARY), _ret == 0);
}
END_TEST()

FN_TEST(assigning_an_address_again_fails)
{
	TEST_RES(add((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1 }),
		 _ret == -EEXIST);
}
END_TEST()

FN_TEST(an_address_on_an_existing_network_is_secondary_and_listed_last)
{
	struct found_address primary, secondary;

	TEST_RES(add((struct address_request){ .local = SECONDARY, .prefix_length = 24, .with_local = 1 }),
		 _ret == 0);
	primary = find_address(PRIMARY);
	secondary = find_address(SECONDARY);
	TEST_RES(secondary.flags, _ret == (IFA_F_PERMANENT | IFA_F_SECONDARY));
	TEST_RES(secondary.position > primary.position, _ret == 1);
	TEST_RES(route_with(RT_TABLE_LOCAL, SECONDARY, 32, RTN_LOCAL, RT_SCOPE_HOST, PRIMARY), _ret == 1);
}
END_TEST()

FN_TEST(removing_a_primary_address_removes_its_secondary_addresses_and_routes)
{
	TEST_RES(delete((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1 }),
		 _ret == 0);
	TEST_RES(find_address(PRIMARY).present, _ret == 0);
	TEST_RES(find_address(SECONDARY).present, _ret == 0);
	TEST_RES(route_with(RT_TABLE_LOCAL, PRIMARY, 32, RTN_LOCAL, RT_SCOPE_HOST, PRIMARY), _ret == 0);
	TEST_RES(route_with(RT_TABLE_LOCAL, "10.9.8.255", 32, RTN_BROADCAST, RT_SCOPE_LINK, PRIMARY), _ret == 0);
	TEST_RES(bind_tcp(PRIMARY), _ret == EADDRNOTAVAIL);
	TEST_RES(delete((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1 }),
		 _ret == -EADDRNOTAVAIL);
}
END_TEST()

FN_TEST(malformed_and_misdirected_requests_fail_with_their_errors)
{
	TEST_RES(add((struct address_request){ .local = PRIMARY, .prefix_length = 33, .with_local = 1 }),
		 _ret == -EINVAL);
	TEST_RES(add((struct address_request){ .local = PRIMARY, .prefix_length = 24, .ifindex = 4242, .with_local = 1 }),
		 _ret == -ENODEV);
	TEST_RES(delete((struct address_request){ .local = PRIMARY, .prefix_length = 24, .ifindex = 4242, .with_local = 1 }),
		 _ret == -ENODEV);
	TEST_RES(find_address(PRIMARY).present, _ret == 0);
}
END_TEST()

FN_TEST(an_address_label_is_kept_as_given)
{
	TEST_RES(add((struct address_request){ .local = PRIMARY, .prefix_length = 24, .label = "tag0:1", .with_local = 1 }),
		 _ret == 0);
	TEST_RES(strcmp(find_address(PRIMARY).label, "tag0:1"), _ret == 0);
	TEST_RES(delete((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1 }),
		 _ret == 0);
}
END_TEST()

FN_TEST(an_unacknowledged_request_gets_no_reply_when_it_succeeds)
{
	uint8_t payload[512] = { 0 };
	struct address_request request = { .local = PRIMARY, .prefix_length = 24, .ifindex = 0, .with_local = 1 };
	uint8_t datagram[4096];
	int fd = rtnl_open(0);
	struct rtgenmsg body = { .rtgen_family = AF_INET };
	size_t length;
	ssize_t received;
	struct nlmsghdr *header;

	request.ifindex = if_nametoindex(DEVICE);
	length = build(payload, &request);
	CHECK(rtnl_send(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL, 900, payload, length));
	CHECK(rtnl_send(fd, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 901, &body, sizeof(body)));
	received = recv(fd, datagram, sizeof(datagram), 0);
	header = (struct nlmsghdr *)datagram;
	TEST_RES(received > 0 && header->nlmsg_seq == 901 && header->nlmsg_type == RTM_NEWADDR, _ret == 1);
	close(fd);
	TEST_RES(delete((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1 }),
		 _ret == 0);
}
END_TEST()

FN_TEST(changing_addresses_requires_net_admin)
{
	pid_t child = CHECK(fork());

	if (child == 0) {
		if (setresuid(65534, 65534, 65534))
			_exit(2);
		_exit(add((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1 }) == -EPERM ? 0 : 1);
	}
	int status;

	TEST_RES(waitpid(child, &status, 0), WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_RES(find_address(PRIMARY).present, _ret == 0);
}
END_TEST()

#ifdef __asterinas__
FN_TEST(unsupported_address_properties_are_rejected)
{
	TEST_RES(add((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1, .with_lifetimes = 1 }),
		 _ret == -EOPNOTSUPP);
	TEST_RES(add((struct address_request){ .local = PRIMARY, .prefix_length = 24, .with_local = 1, .with_flags = 1, .flags_attribute = IFA_F_NODAD }),
		 _ret == -EOPNOTSUPP);
	TEST_RES(find_address(PRIMARY).present, _ret == 0);
}
END_TEST()
#endif
