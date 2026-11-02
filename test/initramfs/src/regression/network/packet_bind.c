// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define SLL_HEADER_LENGTH offsetof(struct sockaddr_ll, sll_addr)
#define SLL_ETHERNET_LENGTH (SLL_HEADER_LENGTH + ETH_ALEN)

static unsigned int loopback;

static struct sockaddr_ll address_for(unsigned int ifindex, unsigned short protocol)
{
	struct sockaddr_ll address = { .sll_family = AF_PACKET,
				       .sll_protocol = htons(protocol),
				       .sll_ifindex = (int)ifindex };

	return address;
}

static int bind_to(int fd, unsigned int ifindex, unsigned short protocol)
{
	struct sockaddr_ll address = address_for(ifindex, protocol);

	return bind(fd, (struct sockaddr *)&address, sizeof(address));
}

static int name_of(int fd, struct sockaddr_ll *address, socklen_t *length)
{
	memset(address, 0xa5, sizeof(*address));
	*length = sizeof(*address);
	return getsockname(fd, (struct sockaddr *)address, length);
}

FN_SETUP(loopback)
{
	loopback = CHECK_WITH(if_nametoindex("lo"), _ret != 0);
}
END_SETUP()

FN_TEST(raw_and_cooked_sockets_can_be_created)
{
	int raw, cooked;

	raw = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));
	cooked = TEST_SUCC(socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)));
	TEST_SUCC(close(raw));
	TEST_SUCC(close(cooked));
}
END_TEST()

FN_TEST(other_socket_types_are_not_supported)
{
	TEST_ERRNO(socket(AF_PACKET, SOCK_STREAM, htons(ETH_P_IP)),
		   ESOCKTNOSUPPORT);
	TEST_ERRNO(socket(AF_PACKET, SOCK_SEQPACKET, htons(ETH_P_IP)),
		   ESOCKTNOSUPPORT);
}
END_TEST()

FN_TEST(creating_a_packet_socket_requires_net_raw)
{
	pid_t child = TEST_SUCC(fork());

	if (child == 0) {
		if (setresuid(65534, 65534, 65534))
			_exit(2);
		errno = 0;
		_exit(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)) == -1 &&
				      errno == EPERM ?
			      0 :
			      1);
	}
	int status;

	TEST_RES(waitpid(child, &status, 0),
		 WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(creation_flags_apply)
{
	int fd = TEST_SUCC(socket(AF_PACKET,
				  SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
				  htons(ETH_P_ARP)));

	TEST_RES(fcntl(fd, F_GETFL), (_ret & O_NONBLOCK) != 0);
	TEST_RES(fcntl(fd, F_GETFD), (_ret & FD_CLOEXEC) != 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(a_new_socket_names_its_protocol_and_no_interface)
{
	struct sockaddr_ll address;
	socklen_t length;
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

	TEST_SUCC(name_of(fd, &address, &length));
	TEST_RES(length, _ret == SLL_HEADER_LENGTH);
	TEST_RES(address.sll_family, _ret == AF_PACKET);
	TEST_RES(address.sll_protocol, _ret == htons(ETH_P_IP));
	TEST_RES(address.sll_ifindex, _ret == 0);
	TEST_RES(address.sll_hatype, _ret == 0);
	TEST_RES(address.sll_halen, _ret == 0);
	TEST_SUCC(close(fd));

	fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, 0));
	TEST_SUCC(name_of(fd, &address, &length));
	TEST_RES(address.sll_protocol, _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(binding_names_the_interface_and_its_link_layer_address)
{
	struct sockaddr_ll address;
	socklen_t length;
	static const unsigned char zero[ETH_ALEN];
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

	TEST_SUCC(bind_to(fd, loopback, ETH_P_ARP));
	TEST_SUCC(name_of(fd, &address, &length));
	TEST_RES(length, _ret == SLL_ETHERNET_LENGTH);
	TEST_RES(address.sll_family, _ret == AF_PACKET);
	TEST_RES(address.sll_protocol, _ret == htons(ETH_P_ARP));
	TEST_RES(address.sll_ifindex, _ret == (int)loopback);
	TEST_RES(address.sll_hatype, _ret == ARPHRD_LOOPBACK);
	TEST_RES(address.sll_pkttype, _ret == 0);
	TEST_RES(address.sll_halen, _ret == ETH_ALEN);
	TEST_RES(memcmp(address.sll_addr, zero, ETH_ALEN), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(binding_with_protocol_zero_keeps_the_protocol)
{
	struct sockaddr_ll address;
	socklen_t length;
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)));

	TEST_SUCC(bind_to(fd, loopback, 0));
	TEST_SUCC(name_of(fd, &address, &length));
	TEST_RES(address.sll_protocol, _ret == htons(ETH_P_IP));
	TEST_RES(address.sll_ifindex, _ret == (int)loopback);

	TEST_SUCC(bind_to(fd, 0, ETH_P_ARP));
	TEST_SUCC(name_of(fd, &address, &length));
	TEST_RES(length, _ret == SLL_HEADER_LENGTH);
	TEST_RES(address.sll_protocol, _ret == htons(ETH_P_ARP));
	TEST_RES(address.sll_ifindex, _ret == 0);
	TEST_RES(address.sll_hatype, _ret == 0);
	TEST_RES(address.sll_halen, _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(binding_can_be_repeated)
{
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, 0));

	TEST_SUCC(bind_to(fd, loopback, ETH_P_IP));
	TEST_SUCC(bind_to(fd, loopback, ETH_P_IP));
	TEST_SUCC(bind_to(fd, loopback, ETH_P_ARP));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(binding_rejects_a_missing_interface)
{
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

	TEST_ERRNO(bind_to(fd, 9999, ETH_P_IP), ENODEV);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(binding_rejects_a_malformed_address)
{
	struct sockaddr_ll address = address_for(loopback, ETH_P_IP);
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

	TEST_ERRNO(bind(fd, (struct sockaddr *)&address, SLL_HEADER_LENGTH),
		   EINVAL);
	TEST_ERRNO(bind(fd, (struct sockaddr *)&address, sizeof(address) - 1),
		   EINVAL);
	address.sll_family = AF_INET;
	TEST_ERRNO(bind(fd, (struct sockaddr *)&address, sizeof(address)),
		   EINVAL);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(the_address_is_truncated_to_the_buffer_and_its_length_reported)
{
	struct sockaddr_ll address;
	socklen_t length = 4;
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

	TEST_SUCC(bind_to(fd, loopback, ETH_P_IP));
	memset(&address, 0xa5, sizeof(address));
	TEST_SUCC(getsockname(fd, (struct sockaddr *)&address, &length));
	TEST_RES(length, _ret == SLL_ETHERNET_LENGTH);
	TEST_RES(address.sll_family, _ret == AF_PACKET);
	TEST_RES(address.sll_ifindex, _ret == (int)0xa5a5a5a5);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(a_packet_socket_has_no_peer_and_no_connection)
{
	struct sockaddr_ll address = address_for(loopback, ETH_P_IP);
	socklen_t length = sizeof(address);
	int fd = TEST_SUCC(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

	TEST_ERRNO(getpeername(fd, (struct sockaddr *)&address, &length),
		   EOPNOTSUPP);
	TEST_ERRNO(connect(fd, (struct sockaddr *)&address, sizeof(address)),
		   EOPNOTSUPP);
	TEST_ERRNO(listen(fd, 1), EOPNOTSUPP);
	TEST_ERRNO(accept(fd, NULL, NULL), EOPNOTSUPP);
	TEST_ERRNO(shutdown(fd, SHUT_RDWR), EOPNOTSUPP);
	TEST_SUCC(close(fd));
}
END_TEST()
