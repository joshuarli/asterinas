// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/test.h"
#include "rtnl_common.h"

FN_SETUP(configure_ethernet_and_gateway)
{
	int control = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	struct ifreq request = {};
	strncpy(request.ifr_name, "eth0", IFNAMSIZ - 1);
	CHECK(ioctl(control, SIOCGIFFLAGS, &request));
	request.ifr_flags |= IFF_UP;
	CHECK(ioctl(control, SIOCSIFFLAGS, &request));
	CHECK(close(control));
	unsigned int index = CHECK_WITH(if_nametoindex("eth0"), _ret != 0);
	struct in_addr local, gateway;
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.100", &local), _ret == 1);
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.1", &gateway), _ret == 1);
	int fd = CHECK(rtnl_open(0));
	struct rtnl_reply reply;
	struct { struct ifaddrmsg body; uint8_t attributes[64]; } address = {
		.body = { .ifa_family = AF_INET, .ifa_prefixlen = 24, .ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = index }
	};
	size_t len = sizeof(address.body);
	len = rtnl_put(&address, len, IFA_LOCAL, &local, sizeof(local));
	len = rtnl_put(&address, len, IFA_ADDRESS, &local, sizeof(local));
	CHECK(rtnl_send(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			71, &address, len));
	CHECK(rtnl_receive(fd, &reply, 71));
	CHECK_WITH(reply.saw_error && !reply.error, _ret != 0);
	struct { struct rtmsg body; uint8_t attributes[64]; } route = {
		.body = { .rtm_family = AF_INET, .rtm_table = RT_TABLE_MAIN, .rtm_protocol = RTPROT_STATIC,
			.rtm_scope = RT_SCOPE_UNIVERSE, .rtm_type = RTN_UNICAST }
	};
	len = sizeof(route.body);
	len = rtnl_put(&route, len, RTA_GATEWAY, &gateway, sizeof(gateway));
	len = rtnl_put(&route, len, RTA_OIF, &index, sizeof(index));
	CHECK(rtnl_send(fd, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			72, &route, len));
	CHECK(rtnl_receive(fd, &reply, 72));
	CHECK_WITH(reply.saw_error && !reply.error, _ret != 0);
	CHECK(close(fd));
}
END_SETUP()

FN_TEST(dont_route_requires_a_direct_route)
{
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in direct = { .sin_family = AF_INET, .sin_port = htons(39125) };
	struct sockaddr_in remote = direct;
	TEST_RES(inet_pton(AF_INET, "192.0.2.1", &direct.sin_addr), _ret == 1);
	TEST_RES(inet_pton(AF_INET, "198.51.100.1", &remote.sin_addr), _ret == 1);
	int unbound = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	TEST_ERRNO(sendto(unbound, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&remote, sizeof(remote)), ENETUNREACH);
	struct sockaddr_in assigned = {};
	socklen_t assigned_len = sizeof(assigned);
	TEST_SUCC(getsockname(unbound, (struct sockaddr *)&assigned, &assigned_len));
	TEST_RES(assigned.sin_port, _ret != 0);
	TEST_RES(assigned.sin_addr.s_addr, _ret == htonl(INADDR_ANY));
	int loopback_sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int ethernet_sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in local_target = { .sin_family = AF_INET, .sin_port = assigned.sin_port,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_RES(sendto(loopback_sender, "lo", 2, 0, (struct sockaddr *)&local_target, sizeof(local_target)), _ret == 2);
	TEST_RES(inet_pton(AF_INET, "192.0.2.100", &local_target.sin_addr), _ret == 1);
	TEST_RES(sendto(ethernet_sender, "eth", 3, 0, (struct sockaddr *)&local_target, sizeof(local_target)), _ret == 3);
	int received = 0;
	for (int i = 0; i < 2; i++) {
		struct pollfd ready = { .fd = unbound, .events = POLLIN };
		if (TEST_RES(poll(&ready, 1, 1000), _ret == 1) != 1) break;
		char payload[8];
		ssize_t count = recv(unbound, payload, sizeof(payload), 0);
		if (count == 2 && !memcmp(payload, "lo", 2)) received |= 1;
		if (count == 3 && !memcmp(payload, "eth", 3)) received |= 2;
	}
	TEST_RES(received, _ret == 3);
	TEST_SUCC(close(loopback_sender));
	TEST_SUCC(close(ethernet_sender));
	int collision = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in occupied = { .sin_family = AF_INET, .sin_port = assigned.sin_port,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_ERRNO(bind(collision, (struct sockaddr *)&occupied, sizeof(occupied)), EADDRINUSE);
	TEST_RES(inet_pton(AF_INET, "192.0.2.100", &occupied.sin_addr), _ret == 1);
	TEST_ERRNO(bind(collision, (struct sockaddr *)&occupied, sizeof(occupied)), EADDRINUSE);
	TEST_RES(sendto(unbound, "x", 1, 0, (struct sockaddr *)&direct, sizeof(direct)), _ret == 1);
	assigned_len = sizeof(assigned);
	TEST_SUCC(getsockname(unbound, (struct sockaddr *)&assigned, &assigned_len));
	TEST_RES(assigned.sin_addr.s_addr, _ret == htonl(INADDR_ANY));
	TEST_SUCC(close(unbound));
	TEST_SUCC(bind(collision, (struct sockaddr *)&occupied, sizeof(occupied)));
	TEST_SUCC(close(collision));
	int connection = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_ERRNO(sendto(connection, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&remote, sizeof(remote)), ENETUNREACH);
	assigned_len = sizeof(assigned);
	TEST_SUCC(getsockname(connection, (struct sockaddr *)&assigned, &assigned_len));
	in_port_t reserved = assigned.sin_port;
	TEST_RES(reserved, _ret != 0);
	TEST_SUCC(connect(connection, (struct sockaddr *)&direct, sizeof(direct)));
	assigned_len = sizeof(assigned);
	TEST_SUCC(getsockname(connection, (struct sockaddr *)&assigned, &assigned_len));
	TEST_RES(assigned.sin_port, _ret == reserved);
	TEST_RES(assigned.sin_addr.s_addr, _ret == occupied.sin_addr.s_addr);
	TEST_SUCC(close(connection));
	int directed = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int direct_only = 1;
	TEST_SUCC(setsockopt(directed, SOL_SOCKET, SO_DONTROUTE, &direct_only, sizeof(direct_only)));
	TEST_ERRNO(connect(directed, (struct sockaddr *)&remote, sizeof(remote)), ENETUNREACH);
	TEST_SUCC(connect(directed, (struct sockaddr *)&direct, sizeof(direct)));
	TEST_SUCC(close(directed));
	TEST_RES(sendto(sender, "x", 1, 0, (struct sockaddr *)&remote, sizeof(remote)), _ret == 1);
	TEST_ERRNO(sendto(sender, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&remote, sizeof(remote)), ENETUNREACH);
	int enabled = 1;
	TEST_SUCC(setsockopt(sender, SOL_SOCKET, SO_DONTROUTE, &enabled, sizeof(enabled)));
	int actual = 0;
	socklen_t length = sizeof(actual);
	TEST_SUCC(getsockopt(sender, SOL_SOCKET, SO_DONTROUTE, &actual, &length));
	TEST_RES(actual, _ret == 1);
	TEST_RES(sendto(sender, "x", 1, 0, (struct sockaddr *)&direct, sizeof(direct)), _ret == 1);
	TEST_ERRNO(sendto(sender, "x", 1, 0, (struct sockaddr *)&remote, sizeof(remote)), ENETUNREACH);
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(udp_reuseport_requires_the_same_socket_owner)
{
	int first = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int second = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int enabled = 1;
	TEST_SUCC(setsockopt(first, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)));
	TEST_SUCC(setsockopt(second, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)));
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(first, (struct sockaddr *)&address, sizeof(address)));
	socklen_t length = sizeof(address);
	TEST_SUCC(getsockname(first, (struct sockaddr *)&address, &length));
	TEST_SUCC(bind(second, (struct sockaddr *)&address, sizeof(address)));
	int recipients = 0;
	int consistent = 1;
	for (int i = 0; i < 128 && consistent; i++) {
		int sender = socket(AF_INET, SOCK_DGRAM, 0);
		if (sender < 0) { consistent = 0; break; }
		int previous = -1;
		for (int n = 0; n < 2; n++) {
			if (sendto(sender, "x", 1, 0, (struct sockaddr *)&address, sizeof(address)) != 1) { consistent = 0; break; }
			struct pollfd ready[2] = { { .fd = first, .events = POLLIN }, { .fd = second, .events = POLLIN } };
			if (poll(ready, 2, 1000) != 1) { consistent = 0; break; }
			int chosen = (ready[0].revents & POLLIN) ? 0 : 1;
			char payload;
			if (!(ready[chosen].revents & POLLIN) || recv(ready[chosen].fd, &payload, 1, 0) != 1 || payload != 'x') {
				consistent = 0;
				break;
			}
			if (previous >= 0 && previous != chosen) consistent = 0;
			previous = chosen;
			recipients |= 1 << chosen;
		}
		close(sender);
	}
	TEST_RES(consistent && recipients == 3, _ret != 0);
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		if (setuid(65534)) _exit(2);
		int other = socket(AF_INET, SOCK_DGRAM, 0);
		if (other < 0 || setsockopt(other, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled))) _exit(3);
		struct stat metadata;
		if (fstat(other, &metadata) || metadata.st_uid != 65534) _exit(5);
		int result = bind(other, (struct sockaddr *)&address, sizeof(address));
		_exit(result == -1 && errno == EADDRINUSE ? 0 : 4);
	}
	int status = 0;
	TEST_RES(waitpid(child, &status, 0), _ret == child);
	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret != 0);
	TEST_SUCC(close(second));
	TEST_SUCC(close(first));
}
END_TEST()

FN_TEST(udp_reuseport_tracks_socket_ownership_changes)
{
	int first = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int enabled = 1;
	TEST_SUCC(setsockopt(first, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)));
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(first, (struct sockaddr *)&address, sizeof(address)));
	socklen_t length = sizeof(address);
	TEST_SUCC(getsockname(first, (struct sockaddr *)&address, &length));
	TEST_SUCC(fchown(first, 65534, (gid_t)-1));
	int second = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_SUCC(setsockopt(second, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)));
	TEST_ERRNO(bind(second, (struct sockaddr *)&address, sizeof(address)), EADDRINUSE);
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		if (setuid(65534)) _exit(2);
		int other = socket(AF_INET, SOCK_DGRAM, 0);
		if (other < 0 || setsockopt(other, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled))) _exit(3);
		_exit(bind(other, (struct sockaddr *)&address, sizeof(address)) == 0 ? 0 : 4);
	}
	int status = 0;
	TEST_RES(waitpid(child, &status, 0), _ret == child);
	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret != 0);
	TEST_SUCC(close(second));
	TEST_SUCC(close(first));
}
END_TEST()

FN_TEST(udp_port_conflicts_respect_address_and_reuse)
{
	int first = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int second = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int wildcard = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in loopback = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(first, (struct sockaddr *)&loopback, sizeof(loopback)));
	socklen_t length = sizeof(loopback);
	TEST_SUCC(getsockname(first, (struct sockaddr *)&loopback, &length));
	struct sockaddr_in ethernet = { .sin_family = AF_INET, .sin_port = loopback.sin_port };
	TEST_RES(inet_pton(AF_INET, "192.0.2.100", &ethernet.sin_addr), _ret == 1);
	TEST_SUCC(bind(second, (struct sockaddr *)&ethernet, sizeof(ethernet)));
	struct sockaddr_in any = { .sin_family = AF_INET, .sin_port = loopback.sin_port,
		.sin_addr.s_addr = htonl(INADDR_ANY) };
	TEST_ERRNO(bind(wildcard, (struct sockaddr *)&any, sizeof(any)), EADDRINUSE);
	int reuse = 1;
	TEST_SUCC(setsockopt(first, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
	TEST_SUCC(setsockopt(second, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
	TEST_SUCC(setsockopt(wildcard, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
	TEST_SUCC(bind(wildcard, (struct sockaddr *)&any, sizeof(any)));
	TEST_SUCC(close(wildcard));
	TEST_SUCC(close(second));
	TEST_SUCC(close(first));
}
END_TEST()

FN_TEST(wildcard_sender_uses_each_destination_interface)
{
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int loopback = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int ethernet = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	struct sockaddr_in lo = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	struct sockaddr_in eth = { .sin_family = AF_INET };
	TEST_RES(inet_pton(AF_INET, "192.0.2.100", &eth.sin_addr), _ret == 1);
	TEST_SUCC(bind(loopback, (struct sockaddr *)&lo, sizeof(lo)));
	TEST_SUCC(bind(ethernet, (struct sockaddr *)&eth, sizeof(eth)));
	socklen_t length = sizeof(lo);
	TEST_SUCC(getsockname(loopback, (struct sockaddr *)&lo, &length));
	length = sizeof(eth);
	TEST_SUCC(getsockname(ethernet, (struct sockaddr *)&eth, &length));
	TEST_RES(sendto(sender, "lo", 2, 0, (struct sockaddr *)&lo, sizeof(lo)), _ret == 2);
	TEST_RES(sendto(sender, "eth", 3, 0, (struct sockaddr *)&eth, sizeof(eth)), _ret == 3);
	struct sockaddr_in source_lo = {}, source_eth = {};
	char payload[8];
	struct pollfd ready = { .fd = loopback, .events = POLLIN };
	if (TEST_RES(poll(&ready, 1, 1000), _ret == 1) == 1) {
		length = sizeof(source_lo);
		TEST_RES(recvfrom(loopback, payload, sizeof(payload), 0, (struct sockaddr *)&source_lo, &length),
			_ret == 2 && !memcmp(payload, "lo", 2));
	}
	ready.fd = ethernet;
	if (TEST_RES(poll(&ready, 1, 1000), _ret == 1) == 1) {
		length = sizeof(source_eth);
		TEST_RES(recvfrom(ethernet, payload, sizeof(payload), 0, (struct sockaddr *)&source_eth, &length),
			_ret == 3 && !memcmp(payload, "eth", 3));
	}
	TEST_RES(source_lo.sin_addr.s_addr, _ret == htonl(INADDR_LOOPBACK));
	TEST_RES(source_eth.sin_addr.s_addr, _ret == eth.sin_addr.s_addr);
	TEST_RES(source_lo.sin_port, _ret != 0 && _ret == source_eth.sin_port);
	TEST_SUCC(close(ethernet));
	TEST_SUCC(close(loopback));
	TEST_SUCC(close(sender));
}
END_TEST()

FN_TEST(connected_udp_receives_only_from_its_peer)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int allowed = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int other = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in peer = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(allowed, (struct sockaddr *)&peer, sizeof(peer)));
	socklen_t length = sizeof(peer);
	TEST_SUCC(getsockname(allowed, (struct sockaddr *)&peer, &length));
	TEST_SUCC(connect(receiver, (struct sockaddr *)&peer, sizeof(peer)));
	struct sockaddr_in local = {};
	length = sizeof(local);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&local, &length));
	TEST_RES(sendto(other, "bad", 3, 0, (struct sockaddr *)&local, sizeof(local)), _ret == 3);
	struct pollfd ready = { .fd = receiver, .events = POLLIN };
	TEST_RES(poll(&ready, 1, 100), _ret == 0);
	TEST_RES(sendto(allowed, "ok", 2, 0, (struct sockaddr *)&local, sizeof(local)), _ret == 2);
	if (TEST_RES(poll(&ready, 1, 1000), _ret == 1 && (ready.revents & POLLIN)) == 1) {
		char payload[8];
		TEST_RES(recv(receiver, payload, sizeof(payload), 0), _ret == 2 && !memcmp(payload, "ok", 2));
	}
	TEST_SUCC(close(other));
	TEST_SUCC(close(allowed));
	TEST_SUCC(close(receiver));
}
END_TEST()

FN_TEST(faulted_udp_send_does_not_enqueue_a_datagram)
{
	int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	TEST_SUCC(bind(receiver, (struct sockaddr *)&address, sizeof(address)));
	socklen_t length = sizeof(address);
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&address, &length));
	void *memory = TEST_RES(mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), _ret != MAP_FAILED);
	TEST_ERRNO(sendto(sender, memory, 8, 0, (struct sockaddr *)&address, sizeof(address)), EFAULT);
	struct pollfd ready = { .fd = receiver, .events = POLLIN };
	TEST_RES(poll(&ready, 1, 100), _ret == 0);
	TEST_RES(sendto(sender, "ok", 2, 0, (struct sockaddr *)&address, sizeof(address)), _ret == 2);
	if (TEST_RES(poll(&ready, 1, 1000), _ret == 1 && (ready.revents & POLLIN)) == 1) {
		char payload[8];
		TEST_RES(recv(receiver, payload, sizeof(payload), 0), _ret == 2 && !memcmp(payload, "ok", 2));
	}
	TEST_SUCC(munmap(memory, 4096));
	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()
