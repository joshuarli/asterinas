// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include "../common/test.h"
#include "rtnl_common.h"
#include <sys/ioctl.h>

struct query {
	const char *destination;
	const char *source;
	uint32_t device;
	uint32_t mark;
	uint32_t uid;
	uint32_t flags;
	uint8_t family;
	uint8_t prefix;
};

struct result {
	int error;
	int count;
	struct rtmsg body;
	uint32_t table;
	uint32_t device;
	uint32_t source;
	uint32_t preferred_source;
	uint32_t gateway;
	uint32_t mark;
	uint32_t uid;
	uint32_t destination;
	uint16_t attrs[16];
	int nattrs;
	int cache_length;
	int cache_error;
	int cache_expires;
	int acknowledged;
};

static uint32_t sequence = 1100;

FN_SETUP(flush_each_transcript_line)
{
	CHECK(setvbuf(stdout, NULL, _IONBF, 0));
}
END_SETUP()

static uint32_t ipv4(const char *text)
{
	struct in_addr address;

	inet_pton(AF_INET, text, &address);
	return address.s_addr;
}

static struct result lookup(struct query query)
{
	uint8_t payload[256] = { 0 };
	struct rtmsg *body = (void *)payload;
	size_t length = NLMSG_ALIGN(sizeof(*body));
	struct rtnl_reply reply;
	struct result result = { 0 };
	int fd = rtnl_open(0);

	body->rtm_family = query.family;
	body->rtm_dst_len = query.prefix;
	body->rtm_flags = query.flags;
	if (query.destination) {
		uint32_t destination = ipv4(query.destination);

		length = rtnl_put(payload, length, RTA_DST, &destination, 4);
	}
	if (query.source) {
		uint32_t source = ipv4(query.source);

		length = rtnl_put(payload, length, RTA_SRC, &source, 4);
	}
	if (query.device)
		length = rtnl_put(payload, length, RTA_OIF, &query.device, 4);
	if (query.mark)
		length = rtnl_put(payload, length, RTA_MARK, &query.mark, 4);
	length = rtnl_put(payload, length, RTA_UID, &query.uid, 4);
	sequence++;
	if (fd < 0 || rtnl_send(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_ACK,
				sequence, payload, length) ||
	    rtnl_receive(fd, &reply, sequence)) {
		result.error = -1000;
		close(fd);
		return result;
	}
	close(fd);
	result.error = reply.error;
	result.acknowledged = reply.saw_error && !reply.error;
	result.count = reply.count;
	struct nlmsghdr *header = rtnl_first(&reply);

	if (!header)
		return result;
	result.body = *(struct rtmsg *)NLMSG_DATA(header);
	struct rtattr *attr = RTM_RTA((struct rtmsg *)NLMSG_DATA(header));
	size_t remaining = RTM_PAYLOAD(header);

	for (; RTA_OK(attr, remaining); attr = RTA_NEXT(attr, remaining)) {
		uint32_t value = 0;

		if (result.nattrs < 16)
			result.attrs[result.nattrs++] = attr->rta_type;
		if (RTA_PAYLOAD(attr) == 4)
			memcpy(&value, RTA_DATA(attr), 4);
		switch (attr->rta_type) {
		case RTA_TABLE: result.table = value; break;
		case RTA_DST: result.destination = value; break;
		case RTA_SRC: result.source = value; break;
		case RTA_OIF: result.device = value; break;
		case RTA_PREFSRC: result.preferred_source = value; break;
		case RTA_GATEWAY: result.gateway = value; break;
		case RTA_MARK: result.mark = value; break;
		case RTA_UID: result.uid = value; break;
		case RTA_CACHEINFO:
			result.cache_length = RTA_PAYLOAD(attr);
			if (RTA_PAYLOAD(attr) == sizeof(struct rta_cacheinfo)) {
				struct rta_cacheinfo *cache = RTA_DATA(attr);

				result.cache_error = cache->rta_error;
				result.cache_expires = cache->rta_expires;
			}
			break;
		}
	}
	return result;
}

static struct query output_query(const char *destination)
{
	return (struct query){ .destination = destination, .family = AF_INET,
			       .prefix = 32 };
}

static void transcript(const char *name, struct result result)
{
	printf("NET_LOOKUP %s errno=%d count=%d family=%u dstlen=%u srclen=%u table=%u protocol=%u scope=%u type=%u flags=%u device=%u source=%08x prefsrc=%08x gateway=%08x mark=%u uid=%u attrs=",
	       name, result.error, result.count, result.body.rtm_family,
	       result.body.rtm_dst_len, result.body.rtm_src_len, result.table,
	       result.body.rtm_protocol, result.body.rtm_scope,
	       result.body.rtm_type, result.body.rtm_flags, result.device,
	       ntohl(result.source), ntohl(result.preferred_source),
	       ntohl(result.gateway), result.mark, result.uid);
	for (int i = 0; i < result.nattrs; i++)
		printf("%s%u", i ? "," : "", result.attrs[i]);
	printf(" cachelen=%d cacheerror=%d cacheexpires=%d\n",
	       result.cache_length, result.cache_error, result.cache_expires);
}

static int route_request(uint16_t type, int route_type)
{
	uint8_t payload[128] = { 0 };
	struct rtmsg *body = (void *)payload;
	size_t length = NLMSG_ALIGN(sizeof(*body));
	uint32_t destination = ipv4("198.18.0.0");
	uint32_t device = if_nametoindex("lo");
	struct rtnl_reply reply;
	int fd = rtnl_open(0);

	body->rtm_family = AF_INET;
	body->rtm_dst_len = 16;
	body->rtm_table = RT_TABLE_MAIN;
	body->rtm_protocol = RTPROT_STATIC;
	body->rtm_scope = route_type <= RTN_MULTICAST ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
	body->rtm_type = route_type;
	length = rtnl_put(payload, length, RTA_DST, &destination, 4);
	if (route_type <= RTN_MULTICAST)
		length = rtnl_put(payload, length, RTA_OIF, &device, 4);
	sequence++;
	if (fd < 0 || rtnl_send(fd, type, NLM_F_REQUEST | NLM_F_ACK |
				(type == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_EXCL : 0),
				sequence, payload, length) ||
	    rtnl_receive(fd, &reply, sequence)) {
		close(fd);
		return -1000;
	}
	close(fd);
	return reply.error;
}

FN_TEST(output_queries_report_the_selected_route_and_source)
{
	struct query query = output_query("127.0.0.2");
	struct result result = lookup(query);
	const uint16_t attrs[] = { RTA_TABLE, RTA_DST, RTA_OIF, RTA_PREFSRC,
				   RTA_UID, RTA_CACHEINFO };

	transcript("loopback", result);
	TEST_RES(result.error, _ret == 0);
	TEST_RES(result.count, _ret == 1);
	TEST_RES(result.acknowledged, _ret == 1);
	TEST_RES(result.body.rtm_family, _ret == AF_INET);
	TEST_RES(result.body.rtm_dst_len, _ret == 32);
	TEST_RES(result.body.rtm_src_len, _ret == 0);
	TEST_RES(result.body.rtm_protocol, _ret == 0);
	TEST_RES(result.body.rtm_scope, _ret == RT_SCOPE_UNIVERSE);
	TEST_RES(result.body.rtm_type, _ret == RTN_LOCAL);
	TEST_RES(result.body.rtm_flags, _ret == 0x80000200U);
	TEST_RES(result.table, _ret == RT_TABLE_MAIN);
	TEST_RES(result.destination, _ret == ipv4("127.0.0.2"));
	TEST_RES(result.device, _ret == if_nametoindex("lo"));
	TEST_RES(result.preferred_source, _ret == ipv4("127.0.0.1"));
	TEST_RES(result.nattrs, _ret == sizeof(attrs) / sizeof(attrs[0]));
	TEST_RES(memcmp(result.attrs, attrs, sizeof(attrs)), _ret == 0);
	TEST_RES(result.cache_length, _ret == sizeof(struct rta_cacheinfo));
	TEST_RES(result.cache_error, _ret == 0);
	TEST_RES(result.cache_expires, _ret == 0);

	query.prefix = 33;
	result = lookup(query);
	transcript("ignored-prefix", result);
	TEST_RES(result.error, _ret == 0);
	TEST_RES(result.body.rtm_dst_len, _ret == 32);

	query.uid = 1234;
	query.mark = 42;
	query.source = "127.0.0.1";
	result = lookup(query);
	transcript("source-mark-uid", result);
	TEST_RES(result.error, _ret == 0);
	TEST_RES(result.body.rtm_src_len, _ret == 32);
	TEST_RES(result.source, _ret == ipv4(query.source));
	TEST_RES(result.preferred_source, _ret == 0);
	TEST_RES(result.uid, _ret == 1234);
	TEST_RES(result.mark, _ret == 42);
}
END_TEST()

FN_TEST(output_queries_return_linux_errors)
{
	struct query query = output_query("192.0.2.2");
	struct result result = lookup(query);

	transcript("no-route", result);
	TEST_RES(result.error, _ret == -ENETUNREACH);
	query = output_query("127.0.0.1");
	query.device = 4242;
	result = lookup(query);
	transcript("no-device", result);
	TEST_RES(result.error, _ret == -ENODEV);
	query.device = 0;
	query.family = AF_UNSPEC;
	result = lookup(query);
	transcript("no-family", result);
	TEST_RES(result.error, _ret == -EOPNOTSUPP);
	query.family = AF_INET;
	query.source = "192.0.2.2";
	result = lookup(query);
	transcript("no-source", result);
	TEST_RES(result.error, _ret == -ENETUNREACH);
	query.source = "127.255.255.255";
	result = lookup(query);
	transcript("broadcast-source", result);
	TEST_RES(result.error, _ret == -ENETUNREACH);
	query = output_query("192.0.2.2");
	query.device = if_nametoindex("lo");
	result = lookup(query);
	transcript("explicit-direct-device", result);
	TEST_RES(result.error, _ret == 0);
	TEST_RES(result.body.rtm_type, _ret == RTN_UNICAST);
	TEST_RES(result.preferred_source, _ret == 0);
	query.flags = RTM_F_FIB_MATCH;
	result = lookup(query);
	transcript("direct-device-no-fib", result);
	TEST_RES(result.error, _ret == -EHOSTUNREACH);
	query = output_query("127.0.0.1");
	query.uid = UINT32_MAX;
	result = lookup(query);
	transcript("unspecified-uid", result);
	TEST_RES(result.error, _ret == 0);
	TEST_RES(result.nattrs, _ret == 5);
}
END_TEST()

FN_TEST(output_queries_and_fibmatch_share_the_socket_routing_policy)
{
	const int errors[] = { 0, 0, 0, 0, 0, 0, -EINVAL, -EHOSTUNREACH,
			       -EACCES, -ENETUNREACH };

	for (int type = RTN_UNICAST; type <= RTN_THROW; type++) {
		struct query query = output_query("198.18.1.2");
		struct result result;
		char name[64];

		TEST_RES(route_request(RTM_NEWROUTE, type), _ret == 0);
		result = lookup(query);
		snprintf(name, sizeof(name), "type-%d", type);
		transcript(name, result);
		TEST_RES(result.error, _ret == errors[type]);
		if (!result.error) {
			TEST_RES(result.body.rtm_type, _ret == type);
			TEST_RES(result.body.rtm_dst_len, _ret == 32);
			TEST_RES(result.body.rtm_scope, _ret == RT_SCOPE_UNIVERSE);
			TEST_RES(result.preferred_source, _ret == ipv4(type == RTN_LOCAL ? "198.18.1.2" : "127.0.0.1"));
		}
		query.flags = RTM_F_FIB_MATCH;
		result = lookup(query);
		snprintf(name, sizeof(name), "fibmatch-%d", type);
		transcript(name, result);
		TEST_RES(result.error, _ret == errors[type]);
		if (!result.error) {
			TEST_RES(result.destination, _ret == ipv4("198.18.0.0"));
			TEST_RES(result.body.rtm_dst_len, _ret == 16);
			TEST_RES(result.body.rtm_type, _ret == type);
			TEST_RES(result.body.rtm_scope, _ret == RT_SCOPE_HOST);
			TEST_RES(result.body.rtm_protocol, _ret == RTPROT_STATIC);
			TEST_RES(result.body.rtm_flags, _ret == 0);
			TEST_RES(result.cache_length, _ret == 0);
		}
		if (type >= RTN_BLACKHOLE) {
			query.flags = 0;
			query.device = if_nametoindex("lo");
			result = lookup(query);
			snprintf(name, sizeof(name), "reject-%d-explicit-device", type);
			transcript(name, result);
			TEST_RES(result.error, _ret == 0);
			TEST_RES(result.body.rtm_type, _ret == RTN_UNICAST);
			query.flags = RTM_F_FIB_MATCH;
			result = lookup(query);
			snprintf(name, sizeof(name), "reject-%d-direct-no-fib", type);
			transcript(name, result);
			TEST_RES(result.error, _ret == -EHOSTUNREACH);
		}
		TEST_RES(route_request(RTM_DELROUTE, type), _ret == 0);
	}
}
END_TEST()

FN_TEST(an_explicit_output_interface_must_be_up)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq device = { 0 };

	snprintf(device.ifr_name, sizeof(device.ifr_name), "lo");
	TEST_RES(ioctl(fd, SIOCGIFFLAGS, &device), _ret == 0);
	short flags = device.ifr_flags;

	device.ifr_flags &= ~IFF_UP;
	TEST_RES(ioctl(fd, SIOCSIFFLAGS, &device), _ret == 0);
	struct query query = output_query("192.0.2.2");

	query.device = if_nametoindex("lo");
	struct result result = lookup(query);

	transcript("down-device-direct", result);
	TEST_RES(result.error, _ret == -ENETUNREACH);
	query.destination = "127.0.0.1";
	result = lookup(query);
	transcript("down-device-local", result);
	TEST_RES(result.error, _ret == -ENETUNREACH);
	query.device = 0;
	result = lookup(query);
	transcript("down-implicit-local", result);
	TEST_RES(result.error, _ret == 0);
	device.ifr_flags = flags;
	TEST_RES(ioctl(fd, SIOCSIFFLAGS, &device), _ret == 0);
	close(fd);
}
END_TEST()
