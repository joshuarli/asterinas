// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"
#include "rtnl_common.h"

#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#define UP_FLAGS (IFF_UP | IFF_RUNNING)
#define OPERSTATE_UNKNOWN 0
#define OPERSTATE_DOWN 2

static int control_socket;

static int get_flags(const char *name, unsigned int *flags)
{
	struct ifreq request = { 0 };

	strncpy(request.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(control_socket, SIOCGIFFLAGS, &request))
		return -1;
	*flags = (unsigned short)request.ifr_flags;
	return 0;
}

static int set_flags(const char *name, unsigned int flags)
{
	struct ifreq request = { 0 };

	strncpy(request.ifr_name, name, IFNAMSIZ - 1);
	request.ifr_flags = (short)flags;
	return ioctl(control_socket, SIOCSIFFLAGS, &request);
}

static int set_up(const char *name, int up)
{
	unsigned int flags;

	if (get_flags(name, &flags))
		return -1;
	return set_flags(name, up ? flags | IFF_UP : flags & ~IFF_UP);
}

static int link_operstate(const char *name)
{
	struct ifinfomsg body = { .ifi_family = AF_UNSPEC };
	struct rtnl_reply reply;
	struct nlmsghdr *header;
	int fd = rtnl_open(0);
	int state = -1;

	if (fd < 0 || rtnl_send(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 21,
				&body, sizeof(body)) ||
	    rtnl_receive(fd, &reply, 21)) {
		close(fd);
		return -1;
	}
	close(fd);
	for (header = rtnl_first(&reply); header; header = rtnl_next(&reply, header)) {
		struct ifinfomsg *link = NLMSG_DATA(header);
		struct rtattr *first = IFLA_RTA(link);
		size_t length = IFLA_PAYLOAD(header);
		struct rtattr *interface_name = rtnl_find(first, length, IFLA_IFNAME);
		struct rtattr *operstate = rtnl_find(first, length, IFLA_OPERSTATE);

		if (interface_name && !strcmp(RTA_DATA(interface_name), name) &&
		    operstate)
			state = *(uint8_t *)RTA_DATA(operstate);
	}
	return state;
}

static int ipv4_loopback_route_count(void)
{
	struct rtmsg body = { .rtm_family = AF_INET };
	struct rtnl_reply reply;
	struct nlmsghdr *header;
	int count = 0;
	int fd = rtnl_open(0);

	if (fd < 0 || rtnl_send(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 22,
				&body, sizeof(body)) ||
	    rtnl_receive(fd, &reply, 22)) {
		close(fd);
		return -1;
	}
	close(fd);
	for (header = rtnl_first(&reply); header; header = rtnl_next(&reply, header)) {
		struct rtmsg *route = NLMSG_DATA(header);
		struct rtattr *oif = rtnl_find(RTM_RTA(route), RTM_PAYLOAD(header),
					       RTA_OIF);

		if (oif && *(uint32_t *)RTA_DATA(oif) == if_nametoindex("lo"))
			count++;
	}
	return count;
}

static int loopback_connect_and_bind(int *connect_errno, int *bind_errno)
{
	struct sockaddr_in address = { .sin_family = AF_INET,
				       .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	int listener = socket(AF_INET, SOCK_STREAM, 0);
	int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

	*bind_errno = bind(listener, (struct sockaddr *)&address,
			   sizeof(address)) ?
			      errno :
			      0;
	if (!*bind_errno)
		listen(listener, 1);
	*connect_errno = 0;
	if (!*bind_errno) {
		socklen_t length = sizeof(address);

		getsockname(listener, (struct sockaddr *)&address, &length);
		*connect_errno = connect(client, (struct sockaddr *)&address,
					 sizeof(address)) ?
					 errno :
					 0;
	} else {
		address.sin_port = htons(9);
		*connect_errno = connect(client, (struct sockaddr *)&address,
					 sizeof(address)) ?
					 errno :
					 0;
	}
	if (*connect_errno == EINPROGRESS) {
		struct pollfd waiting = { .fd = client, .events = POLLOUT };
		int error = 0;
		socklen_t length = sizeof(error);

		if (poll(&waiting, 1, 1500) == 1) {
			getsockopt(client, SOL_SOCKET, SO_ERROR, &error, &length);
			*connect_errno = error;
		}
	}
	close(client);
	close(listener);
	errno = 0;
	return 0;
}

FN_SETUP(control_socket)
{
	control_socket = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
}
END_SETUP()

FN_TEST(loopback_starts_up)
{
	unsigned int flags;

	TEST_SUCC(get_flags("lo", &flags));
	TEST_RES(flags & UP_FLAGS, _ret == UP_FLAGS);
	TEST_RES(flags & IFF_LOOPBACK, _ret == IFF_LOOPBACK);
	TEST_RES(link_operstate("lo"), _ret == OPERSTATE_UNKNOWN);
	TEST_RES(ipv4_loopback_route_count(), _ret == 3);
}
END_TEST()

FN_TEST(a_down_interface_keeps_only_its_host_routes_and_carries_no_traffic)
{
	unsigned int flags;
	int connect_errno, bind_errno;

	TEST_SUCC(set_up("lo", 0));
	TEST_SUCC(get_flags("lo", &flags));
	TEST_RES(flags & UP_FLAGS, _ret == 0);
	TEST_RES(flags & IFF_LOOPBACK, _ret == IFF_LOOPBACK);
	TEST_RES(link_operstate("lo"), _ret == OPERSTATE_DOWN);
	TEST_RES(ipv4_loopback_route_count(), _ret == 2);
	TEST_RES(loopback_connect_and_bind(&connect_errno, &bind_errno),
		 bind_errno == 0 && connect_errno == EINPROGRESS);
}
END_TEST()

FN_TEST(bringing_an_interface_up_restores_its_routes_and_traffic)
{
	unsigned int flags;
	int connect_errno, bind_errno;

	TEST_SUCC(set_up("lo", 1));
	TEST_SUCC(get_flags("lo", &flags));
	TEST_RES(flags & UP_FLAGS, _ret == UP_FLAGS);
	TEST_RES(link_operstate("lo"), _ret == OPERSTATE_UNKNOWN);
	TEST_RES(ipv4_loopback_route_count(), _ret == 3);
	TEST_RES(loopback_connect_and_bind(&connect_errno, &bind_errno),
		 bind_errno == 0 && connect_errno == 0);
}
END_TEST()

FN_TEST(setting_the_same_state_again_succeeds)
{
	TEST_SUCC(set_up("lo", 1));
	TEST_SUCC(set_up("lo", 1));
}
END_TEST()

FN_TEST(an_unknown_interface_is_not_found)
{
	TEST_ERRNO(set_flags("missing0", IFF_UP), ENODEV);
}
END_TEST()

FN_TEST(changing_the_interface_flags_requires_net_admin)
{
	pid_t child = CHECK(fork());

	if (child == 0) {
		unsigned int flags;

		if (setresuid(65534, 65534, 65534) || get_flags("lo", &flags))
			_exit(2);
		errno = 0;
		_exit(set_flags("lo", flags & ~IFF_UP) == -1 && errno == EPERM ?
			      0 :
			      1);
	}
	int status;

	TEST_RES(waitpid(child, &status, 0),
		 WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_RES(link_operstate("lo"), _ret == OPERSTATE_UNKNOWN);
}
END_TEST()

#ifdef __asterinas__
FN_TEST(changing_another_flag_is_not_supported)
{
	unsigned int flags;

	TEST_SUCC(get_flags("lo", &flags));
	TEST_ERRNO(set_flags("lo", flags | IFF_NOARP), EOPNOTSUPP);
}
END_TEST()
#endif
