// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#endif

#define NANOS 1000000000LL

static int receiver;
static int sender;
static struct sockaddr_in receiver_address;

static long long realtime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (long long)ts.tv_sec * NANOS + ts.tv_nsec;
}

static int send_datagram(int fd, const char *text)
{
	return sendto(fd, text, strlen(text), 0,
		      (struct sockaddr *)&receiver_address,
		      sizeof(receiver_address));
}

static int receive(int fd, int flags, char *data, size_t size, char *control,
		   size_t control_size, struct msghdr *message)
{
	struct iovec io = { .iov_base = data, .iov_len = size };
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };

	if (!(flags & MSG_ERRQUEUE) && poll(&poll_fd, 1, 3000) != 1)
		return -1;
	*message = (struct msghdr){ .msg_iov = &io,
				    .msg_iovlen = size ? 1 : 0,
				    .msg_control = control,
				    .msg_controllen = control_size };
	return recvmsg(fd, message, flags);
}

static struct cmsghdr *find_message(struct msghdr *message, int level, int type)
{
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(message); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(message, cmsg)) {
		if (cmsg->cmsg_level == level && cmsg->cmsg_type == type)
			return cmsg;
	}
	return NULL;
}

static int set_flag(int fd, int level, int option, int value)
{
	return setsockopt(fd, level, option, &value, sizeof(value));
}

static int set_timestamping(int fd, unsigned int flags)
{
	struct so_timestamping config = { .flags = flags, .bind_phc = 0 };

	return setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &config,
			  sizeof(config));
}

static int timestamp_is_recent(const struct timespec *ts, long long before,
			       long long after)
{
	long long value = (long long)ts->tv_sec * NANOS + ts->tv_nsec;

	return value >= before - NANOS && value <= after + NANOS;
}

FN_SETUP(sockets)
{
	socklen_t length = sizeof(receiver_address);

	receiver = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	sender = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	receiver_address = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	CHECK(bind(receiver, (struct sockaddr *)&receiver_address,
		   sizeof(receiver_address)));
	CHECK(getsockname(receiver, (struct sockaddr *)&receiver_address,
			  &length));
}
END_SETUP()

FN_TEST(a_datagram_carries_no_control_message_by_default)
{
	char data[64], control[256];
	struct msghdr message;

	TEST_SUCC(send_datagram(sender, "plain"));
	TEST_RES(receive(receiver, 0, data, sizeof(data), control,
			 sizeof(control), &message),
		 _ret == 5 && message.msg_controllen == 0);
}
END_TEST()

FN_TEST(ip_pktinfo_reports_the_arrival_interface_and_addresses)
{
	char data[64], control[256];
	struct msghdr message;
	struct cmsghdr *cmsg;
	int enabled = 0;
	socklen_t length = sizeof(enabled);

	TEST_RES(getsockopt(receiver, IPPROTO_IP, IP_PKTINFO, &enabled, &length),
		 enabled == 0);
	TEST_SUCC(set_flag(receiver, IPPROTO_IP, IP_PKTINFO, 1));
	TEST_RES(getsockopt(receiver, IPPROTO_IP, IP_PKTINFO, &enabled, &length),
		 enabled == 1);

	TEST_SUCC(send_datagram(sender, "pktinfo"));
	TEST_RES(receive(receiver, 0, data, sizeof(data), control,
			 sizeof(control), &message),
		 _ret == 7);
	cmsg = find_message(&message, IPPROTO_IP, IP_PKTINFO);
	TEST_RES(cmsg != NULL, _ret);
	if (cmsg != NULL) {
		struct in_pktinfo info;

		memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
		TEST_RES(cmsg->cmsg_len, _ret == CMSG_LEN(sizeof(info)));
		TEST_RES(info.ipi_ifindex, _ret == (int)if_nametoindex("lo"));
		TEST_RES(info.ipi_addr.s_addr, _ret == htonl(INADDR_LOOPBACK));
		TEST_RES(info.ipi_spec_dst.s_addr, _ret == htonl(INADDR_LOOPBACK));
	}
	TEST_SUCC(set_flag(receiver, IPPROTO_IP, IP_PKTINFO, 0));
}
END_TEST()

FN_TEST(so_timestampns_and_so_timestamp_report_the_arrival_time)
{
	char data[64], control[256];
	struct msghdr message;
	struct cmsghdr *cmsg;
	long long before, after;

	TEST_SUCC(set_flag(receiver, SOL_SOCKET, SO_TIMESTAMPNS, 1));
	before = realtime_ns();
	TEST_SUCC(send_datagram(sender, "ns"));
	TEST_RES(receive(receiver, 0, data, sizeof(data), control,
			 sizeof(control), &message),
		 _ret == 2);
	after = realtime_ns();
	cmsg = find_message(&message, SOL_SOCKET, SCM_TIMESTAMPNS);
	TEST_RES(cmsg != NULL, _ret);
	if (cmsg != NULL) {
		struct timespec ts;

		memcpy(&ts, CMSG_DATA(cmsg), sizeof(ts));
		TEST_RES(timestamp_is_recent(&ts, before, after), _ret);
	}

	TEST_SUCC(set_flag(receiver, SOL_SOCKET, SO_TIMESTAMP, 1));
	before = realtime_ns();
	TEST_SUCC(send_datagram(sender, "us"));
	TEST_RES(receive(receiver, 0, data, sizeof(data), control,
			 sizeof(control), &message),
		 _ret == 2);
	after = realtime_ns();
	cmsg = find_message(&message, SOL_SOCKET, SCM_TIMESTAMP);
	TEST_RES(cmsg != NULL, _ret);
	if (cmsg != NULL) {
		struct timeval tv;
		struct timespec ts;

		memcpy(&tv, CMSG_DATA(cmsg), sizeof(tv));
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000;
		TEST_RES(timestamp_is_recent(&ts, before, after), _ret);
	}
	TEST_SUCC(set_flag(receiver, SOL_SOCKET, SO_TIMESTAMP, 0));
}
END_TEST()

FN_TEST(so_timestamping_reports_a_software_receive_time)
{
	char data[64], control[256];
	struct msghdr message;
	struct cmsghdr *cmsg;
	int flags = 0;
	socklen_t length = sizeof(flags);
	long long before, after;

	TEST_SUCC(set_timestamping(receiver, SOF_TIMESTAMPING_SOFTWARE |
						     SOF_TIMESTAMPING_RX_SOFTWARE));
	TEST_RES(getsockopt(receiver, SOL_SOCKET, SO_TIMESTAMPING, &flags,
			    &length),
		 flags == (int)(SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE));

	before = realtime_ns();
	TEST_SUCC(send_datagram(sender, "rx"));
	TEST_RES(receive(receiver, 0, data, sizeof(data), control,
			 sizeof(control), &message),
		 _ret == 2);
	after = realtime_ns();
	cmsg = find_message(&message, SOL_SOCKET, SO_TIMESTAMPING);
	TEST_RES(cmsg != NULL, _ret);
	if (cmsg != NULL) {
		struct timespec stamps[3];

		memcpy(stamps, CMSG_DATA(cmsg), sizeof(stamps));
		TEST_RES(timestamp_is_recent(&stamps[0], before, after), _ret);
		TEST_RES(stamps[1].tv_sec == 0 && stamps[1].tv_nsec == 0 &&
				 stamps[2].tv_sec == 0 && stamps[2].tv_nsec == 0,
			 _ret);
	}
	TEST_SUCC(set_timestamping(receiver, 0));
}
END_TEST()

FN_TEST(a_transmit_timestamp_arrives_through_the_error_queue)
{
	char control[256];
	struct msghdr message;
	struct pollfd poll_fd = { .fd = sender, .events = 0 };
	struct cmsghdr *stamp, *error;
	long long before, after;

	TEST_ERRNO(receive(sender, MSG_ERRQUEUE | MSG_DONTWAIT, NULL, 0, control,
			   sizeof(control), &message),
		   EAGAIN);

	TEST_SUCC(set_timestamping(sender, SOF_TIMESTAMPING_SOFTWARE |
						   SOF_TIMESTAMPING_TX_SOFTWARE |
						   SOF_TIMESTAMPING_OPT_TSONLY |
						   SOF_TIMESTAMPING_OPT_ID));
	for (unsigned int id = 0; id < 2; id++) {
		before = realtime_ns();
		TEST_SUCC(send_datagram(sender, "tx"));
		TEST_RES(poll(&poll_fd, 1, 3000), _ret == 1 && (poll_fd.revents & POLLERR));
		after = realtime_ns();

		TEST_RES(receive(sender, MSG_ERRQUEUE, NULL, 0, control,
				 sizeof(control), &message),
			 _ret == 0);
		stamp = find_message(&message, SOL_SOCKET, SO_TIMESTAMPING);
		error = find_message(&message, IPPROTO_IP, IP_RECVERR);
		TEST_RES(stamp != NULL && error != NULL, _ret);
		if (stamp != NULL && error != NULL) {
			struct timespec stamps[3];
			struct sock_extended_err info;

			memcpy(stamps, CMSG_DATA(stamp), sizeof(stamps));
			memcpy(&info, CMSG_DATA(error), sizeof(info));
			TEST_RES(timestamp_is_recent(&stamps[0], before, after) &&
					 stamps[0].tv_sec != 0,
				 _ret);
			TEST_RES(info.ee_errno == ENOMSG &&
					 info.ee_origin == SO_EE_ORIGIN_TIMESTAMPING &&
					 info.ee_info == SCM_TSTAMP_SND && info.ee_data == id,
				 _ret);
		}
		poll_fd.revents = 0;
	}
	TEST_ERRNO(receive(sender, MSG_ERRQUEUE | MSG_DONTWAIT, NULL, 0, control,
			   sizeof(control), &message),
		   EAGAIN);
	TEST_SUCC(set_timestamping(sender, 0));
}
END_TEST()

#ifdef __asterinas__
FN_TEST(timestamping_modes_the_stack_cannot_honor_are_rejected)
{
	TEST_ERRNO(set_timestamping(sender, SOF_TIMESTAMPING_RAW_HARDWARE),
		   EINVAL);
	TEST_ERRNO(set_timestamping(sender, SOF_TIMESTAMPING_SOFTWARE |
						    SOF_TIMESTAMPING_TX_SOFTWARE),
		   EINVAL);
}
END_TEST()
#endif

FN_TEST(an_unprivileged_user_can_bind_an_ephemeral_port_and_connect)
{
	pid_t child = CHECK(fork());

	if (child == 0) {
		struct sockaddr_in any = { .sin_family = AF_INET,
					   .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
		int failures = 0;
		int bound, connected;

		if (setresgid(1000, 1000, 1000) != 0 ||
		    setresuid(1000, 1000, 1000) != 0)
			_exit(100);
		bound = socket(AF_INET, SOCK_DGRAM, 0);
		if (bound < 0 || bind(bound, (struct sockaddr *)&any, sizeof(any)) != 0)
			failures++;
		connected = socket(AF_INET, SOCK_DGRAM, 0);
		if (connected < 0 ||
		    connect(connected, (struct sockaddr *)&receiver_address,
			    sizeof(receiver_address)) != 0)
			failures++;
		any.sin_port = htons(80);
		if (bind(socket(AF_INET, SOCK_DGRAM, 0), (struct sockaddr *)&any,
			 sizeof(any)) != -1 || errno != EACCES)
			failures++;
		_exit(failures);
	}
	int status;

	TEST_RES(waitpid(child, &status, 0), WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()
