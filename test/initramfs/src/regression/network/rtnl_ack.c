// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"
#include "rtnl_common.h"

#include <linux/if_addr.h>
#include <poll.h>

#define PEER_ADDRESS "10.9.8.7"

static int fd;

FN_SETUP(socket)
{
	fd = CHECK(rtnl_open(0));
}
END_SETUP()

static ssize_t receive_one(uint8_t *buffer, size_t size, int timeout_ms)
{
	struct pollfd waiting = { .fd = fd, .events = POLLIN };

	if (poll(&waiting, 1, timeout_ms) != 1)
		return -1;
	return recv(fd, buffer, size, 0);
}

static void drain(void)
{
	uint8_t buffer[RTNL_BUFFER_SIZE];

	while (receive_one(buffer, sizeof(buffer), 100) >= 0)
		;
}

static size_t address_message(uint8_t *buffer, uint16_t type, uint16_t flags, uint32_t sequence,
			      const char *local, size_t body_length, int truncate_attribute)
{
	struct nlmsghdr *header = (struct nlmsghdr *)buffer;
	struct ifaddrmsg *body = NLMSG_DATA(header);
	struct in_addr address;
	size_t length = NLMSG_LENGTH(body_length);

	memset(buffer, 0, 256);
	inet_pton(AF_INET, local, &address);
	header->nlmsg_type = type;
	header->nlmsg_flags = flags;
	header->nlmsg_seq = sequence;
	body->ifa_family = AF_INET;
	body->ifa_prefixlen = 24;
	body->ifa_index = if_nametoindex("lo");
	if (body_length >= sizeof(*body)) {
		length = rtnl_put(buffer, length, IFA_LOCAL, &address, 4);
		length = rtnl_put(buffer, length, IFA_ADDRESS, &address, 4);
		if (truncate_attribute == 1)
			((struct rtattr *)(buffer + length - 8))->rta_len = 200;
		if (truncate_attribute == 2)
			((struct rtattr *)(buffer + length - 8))->rta_len = 2;
	}
	header->nlmsg_len = length;
	return length;
}

static int error_for(uint16_t type, uint16_t flags, size_t body_length, int truncate_attribute)
{
	uint8_t request[256], reply[RTNL_BUFFER_SIZE];
	size_t length = address_message(request, type, flags, 4000 + truncate_attribute, PEER_ADDRESS,
					body_length, truncate_attribute);
	ssize_t received;
	struct nlmsghdr *header = (struct nlmsghdr *)reply;

	drain();
	if (send(fd, request, length, 0) != (ssize_t)length)
		return -1;
	received = receive_one(reply, sizeof(reply), 1000);
	if (received < 0)
		return -1000;
	if (header->nlmsg_type != NLMSG_ERROR)
		return -2000;
	return ((struct nlmsgerr *)NLMSG_DATA(header))->error;
}

FN_TEST(an_unknown_message_type_fails)
{
	uint8_t request[64] = { 0 }, reply[RTNL_BUFFER_SIZE];
	struct nlmsghdr *header = (struct nlmsghdr *)request;
	struct rtgenmsg *body = NLMSG_DATA(header);

	header->nlmsg_len = NLMSG_LENGTH(sizeof(*body));
	header->nlmsg_type = 200;
	header->nlmsg_flags = NLM_F_REQUEST;
	header->nlmsg_seq = 77;
	body->rtgen_family = AF_INET;
	drain();
	CHECK(send(fd, request, header->nlmsg_len, 0));
	TEST_RES(receive_one(reply, sizeof(reply), 1000) > 0 &&
			 ((struct nlmsghdr *)reply)->nlmsg_type == NLMSG_ERROR &&
			 ((struct nlmsgerr *)NLMSG_DATA((struct nlmsghdr *)reply))->error == -EOPNOTSUPP &&
			 ((struct nlmsghdr *)reply)->nlmsg_seq == 77,
		 _ret == 1);
}
END_TEST()

FN_TEST(a_truncated_body_fails_instead_of_being_acknowledged)
{
	TEST_RES(error_for(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 4, 0), _ret == -EINVAL);
	TEST_RES(error_for(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 4, 0), _ret == -EINVAL);
}
END_TEST()

#ifdef __asterinas__
FN_TEST(a_malformed_attribute_fails_instead_of_being_acknowledged)
{
	TEST_RES(error_for(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sizeof(struct ifaddrmsg), 1), _ret == -EINVAL);
	TEST_RES(error_for(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sizeof(struct ifaddrmsg), 2), _ret == -EINVAL);
	TEST_RES(error_for(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL, sizeof(struct ifaddrmsg), 1), _ret == -EINVAL);
}
END_TEST()
#endif

FN_TEST(an_acknowledgement_echoes_the_request_header_and_a_failure_carries_the_error)
{
	uint8_t request[256], reply[RTNL_BUFFER_SIZE];
	size_t length = address_message(request, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
					5000, PEER_ADDRESS, sizeof(struct ifaddrmsg), 0);
	struct nlmsghdr *header = (struct nlmsghdr *)reply;
	struct nlmsgerr *error = NLMSG_DATA(header);
	struct nlmsghdr *request_header = (struct nlmsghdr *)request;
	struct sockaddr_nl self = { 0 };
	socklen_t self_length = sizeof(self);

	getsockname(fd, (struct sockaddr *)&self, &self_length);
	drain();
	CHECK(send(fd, request, length, 0));
	TEST_RES(receive_one(reply, sizeof(reply), 1000), _ret > 0);
	TEST_RES(header->nlmsg_type, _ret == NLMSG_ERROR);
	TEST_RES(header->nlmsg_seq, _ret == 5000);
	TEST_RES(header->nlmsg_pid, _ret == self.nl_pid);
	TEST_RES(header->nlmsg_len, _ret == NLMSG_LENGTH(sizeof(struct nlmsgerr)));
	TEST_RES(error->error, _ret == 0);
	TEST_RES(error->msg.nlmsg_type, _ret == RTM_NEWADDR);
	TEST_RES(error->msg.nlmsg_seq, _ret == 5000);
	TEST_RES(error->msg.nlmsg_len, _ret == request_header->nlmsg_len);
	TEST_RES(error_for(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sizeof(struct ifaddrmsg), 0),
		 _ret == -EEXIST);
	length = address_message(request, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 5001, PEER_ADDRESS,
				 sizeof(struct ifaddrmsg), 0);
	CHECK(send(fd, request, length, 0));
	TEST_RES(receive_one(reply, sizeof(reply), 1000) > 0 && error->error == 0, _ret == 1);
}
END_TEST()

FN_TEST(several_requests_in_one_datagram_get_one_reply_each_in_order)
{
	uint8_t datagram[512], reply[RTNL_BUFFER_SIZE];
	size_t first = address_message(datagram, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
				       6000, PEER_ADDRESS, sizeof(struct ifaddrmsg), 0);
	size_t aligned = NLMSG_ALIGN(first);
	size_t second = address_message(datagram + aligned, RTM_NEWADDR,
					NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 6001, PEER_ADDRESS,
					sizeof(struct ifaddrmsg), 0);
	int errors[2] = { 1, 1 }, seen = 0;

	drain();
	CHECK(send(fd, datagram, aligned + second, 0));
	while (seen < 2 && receive_one(reply, sizeof(reply), 1000) > 0) {
		struct nlmsghdr *header = (struct nlmsghdr *)reply;

		if (header->nlmsg_type == NLMSG_ERROR)
			errors[header->nlmsg_seq - 6000] = ((struct nlmsgerr *)NLMSG_DATA(header))->error;
		seen++;
	}
	TEST_RES(seen == 2 && errors[0] == 0 && errors[1] == -EEXIST, _ret == 1);
	error_for(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, sizeof(struct ifaddrmsg), 0);
}
END_TEST()

FN_TEST(a_dump_is_multipart_complete_and_never_acknowledged)
{
	uint8_t reply[RTNL_BUFFER_SIZE];
	struct rtgenmsg body = { .rtgen_family = AF_INET };
	int seen_done = 0, seen_ack = 0, multi = 1, count = 0;

	drain();
	CHECK(rtnl_send(fd, RTM_GETADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, 7000, &body, sizeof(body)));
	while (!seen_done) {
		ssize_t received = receive_one(reply, sizeof(reply), 1000);
		struct nlmsghdr *header = (struct nlmsghdr *)reply;

		if (received < 0)
			break;
		for (; NLMSG_OK(header, (size_t)received); header = NLMSG_NEXT(header, received)) {
			if (header->nlmsg_type == NLMSG_DONE) {
				seen_done = 1;
				multi &= !!(header->nlmsg_flags & NLM_F_MULTI);
			} else if (header->nlmsg_type == NLMSG_ERROR) {
				seen_ack = 1;
			} else {
				count++;
				multi &= !!(header->nlmsg_flags & NLM_F_MULTI);
			}
		}
	}
	TEST_RES(seen_done && multi && count >= 1, _ret == 1);
	drain();
	TEST_RES(seen_ack, _ret == 0);
}
END_TEST()
