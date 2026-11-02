/* SPDX-License-Identifier: MPL-2.0 */
#ifndef RTNL_COMMON_H
#define RTNL_COMMON_H

#include <arpa/inet.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RTNL_BUFFER_SIZE 65536

struct rtnl_reply {
	uint8_t data[RTNL_BUFFER_SIZE];
	size_t length;
	int error;
	int saw_done;
	int saw_error;
	int multi_flags_valid;
	int count;
	uint32_t sequence;
};

static inline int rtnl_open(unsigned int groups)
{
	struct sockaddr_nl address = { .nl_family = AF_NETLINK,
				       .nl_groups = groups };
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

	if (fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)))
		return -1;
	return fd;
}

static inline size_t rtnl_put(void *buffer, size_t length, uint16_t type,
			      const void *data, size_t size)
{
	struct rtattr *attribute = (struct rtattr *)((uint8_t *)buffer + length);

	attribute->rta_type = type;
	attribute->rta_len = RTA_LENGTH(size);
	memcpy(RTA_DATA(attribute), data, size);
	return length + RTA_ALIGN(attribute->rta_len);
}

static inline int rtnl_send(int fd, uint16_t type, uint16_t flags,
			    uint32_t sequence, const void *payload,
			    size_t payload_length)
{
	uint8_t buffer[4096] = { 0 };
	struct nlmsghdr *header = (struct nlmsghdr *)buffer;

	header->nlmsg_len = NLMSG_LENGTH(payload_length);
	header->nlmsg_type = type;
	header->nlmsg_flags = flags;
	header->nlmsg_seq = sequence;
	memcpy(NLMSG_DATA(header), payload, payload_length);
	return send(fd, buffer, header->nlmsg_len, 0) ==
			       (ssize_t)header->nlmsg_len ?
		       0 :
		       -1;
}

static inline int rtnl_receive(int fd, struct rtnl_reply *reply,
			       uint32_t sequence)
{
	memset(reply, 0, sizeof(*reply));
	reply->sequence = sequence;
	reply->multi_flags_valid = 1;
	for (;;) {
		uint8_t datagram[RTNL_BUFFER_SIZE];
		ssize_t received = recv(fd, datagram, sizeof(datagram), 0);
		struct nlmsghdr *header = (struct nlmsghdr *)datagram;

		if (received < 0)
			return -1;
		for (; NLMSG_OK(header, (size_t)received);
		     header = NLMSG_NEXT(header, received)) {
			if (header->nlmsg_seq != sequence)
				continue;
			if (header->nlmsg_type == NLMSG_DONE) {
				reply->saw_done = 1;
				if (!(header->nlmsg_flags & NLM_F_MULTI))
					reply->multi_flags_valid = 0;
				return 0;
			}
			if (header->nlmsg_type == NLMSG_ERROR) {
				reply->saw_error = 1;
				reply->error = ((struct nlmsgerr *)NLMSG_DATA(header))
						       ->error;
				return 0;
			}
			if (!(header->nlmsg_flags & NLM_F_MULTI))
				reply->multi_flags_valid = 0;
			if (reply->length + header->nlmsg_len > sizeof(reply->data))
				return -1;
			memcpy(reply->data + reply->length, header,
			       header->nlmsg_len);
			reply->length += NLMSG_ALIGN(header->nlmsg_len);
			reply->count++;
		}
	}
}

static inline struct nlmsghdr *rtnl_first(struct rtnl_reply *reply)
{
	return reply->length ? (struct nlmsghdr *)reply->data : NULL;
}

static inline struct nlmsghdr *rtnl_next(struct rtnl_reply *reply,
					 struct nlmsghdr *header)
{
	uint8_t *next = (uint8_t *)header + NLMSG_ALIGN(header->nlmsg_len);

	return next < reply->data + reply->length ? (struct nlmsghdr *)next : NULL;
}

static inline struct rtattr *rtnl_find(struct rtattr *first, size_t length,
				       uint16_t type)
{
	struct rtattr *attribute = first;

	for (; RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length))
		if (attribute->rta_type == type)
			return attribute;
	return NULL;
}

#endif
