// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int udp_socket(void)
{
	return CHECK(socket(AF_INET, SOCK_DGRAM, 0));
}

static int bind_to_device(int fd, const char *name)
{
	return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name));
}

static int bound_device(int fd, char *name, socklen_t *length)
{
	return getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, length);
}

static int bind_any(int fd, int port)
{
	struct sockaddr_in address = { .sin_family = AF_INET,
				       .sin_port = htons(port) };

	return bind(fd, (struct sockaddr *)&address, sizeof(address));
}

static int bound_port(int fd)
{
	struct sockaddr_in address;
	socklen_t length = sizeof(address);

	if (getsockname(fd, (struct sockaddr *)&address, &length))
		return -1;
	return ntohs(address.sin_port);
}

static int send_to_loopback(int fd, int port, const char *text)
{
	struct sockaddr_in address = { .sin_family = AF_INET,
				       .sin_port = htons(port),
				       .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };

	return sendto(fd, text, strlen(text), 0, (struct sockaddr *)&address,
		      sizeof(address));
}

static int receive_text(int fd, char *text, size_t size)
{
	struct pollfd waiting = { .fd = fd, .events = POLLIN };
	int length;

	if (poll(&waiting, 1, 3000) != 1)
		return -1;
	length = recv(fd, text, size - 1, 0);
	if (length >= 0)
		text[length] = '\0';
	return length;
}

FN_TEST(a_socket_starts_without_a_device)
{
	int fd = udp_socket();
	char name[IFNAMSIZ] = "unchanged";
	socklen_t length = sizeof(name);

	TEST_SUCC(bound_device(fd, name, &length));
	TEST_RES(length, _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(a_known_device_is_accepted_and_reported_with_its_terminator)
{
	int fd = udp_socket();
	char name[IFNAMSIZ] = { 0 };
	socklen_t length = sizeof(name);

	TEST_SUCC(bind_to_device(fd, "lo"));
	TEST_SUCC(bound_device(fd, name, &length));
	TEST_RES(length, _ret == 3 && strcmp(name, "lo") == 0);
	close(fd);
}
END_TEST()

FN_TEST(a_short_buffer_cannot_hold_the_name)
{
	int fd = udp_socket();
	char name[IFNAMSIZ] = { 0 };
	socklen_t length = 2;

	TEST_SUCC(bind_to_device(fd, "lo"));
	TEST_ERRNO(bound_device(fd, name, &length), EINVAL);
	close(fd);
}
END_TEST()

FN_TEST(an_unknown_device_is_refused)
{
	int fd = udp_socket();

	TEST_ERRNO(bind_to_device(fd, "missing0"), ENODEV);
	close(fd);
}
END_TEST()

FN_TEST(an_empty_name_removes_the_device)
{
	int fd = udp_socket();
	char name[IFNAMSIZ] = { 0 };
	socklen_t length = sizeof(name);

	TEST_SUCC(bind_to_device(fd, "lo"));
	TEST_SUCC(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "", 0));
	TEST_SUCC(bound_device(fd, name, &length));
	TEST_RES(length, _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(a_socket_on_a_device_binds_the_wildcard_address_and_receives_from_it)
{
	int receiver = udp_socket();
	int sender = udp_socket();
	char text[16];
	int port;

	TEST_SUCC(bind_to_device(receiver, "lo"));
	TEST_SUCC(bind_any(receiver, 0));
	port = TEST_SUCC(bound_port(receiver));
	TEST_RES(send_to_loopback(sender, port, "ping"), _ret == 4);
	TEST_RES(receive_text(receiver, text, sizeof(text)),
		 _ret == 4 && strcmp(text, "ping") == 0);
	close(receiver);
	close(sender);
}
END_TEST()

FN_TEST(a_socket_on_a_device_sends_without_binding_first)
{
	int receiver = udp_socket();
	int sender = udp_socket();
	struct sockaddr_in source;
	socklen_t source_length = sizeof(source);
	char text[16];
	int port;

	TEST_SUCC(bind_to_device(sender, "lo"));
	TEST_SUCC(bind_to_device(receiver, "lo"));
	TEST_SUCC(bind_any(receiver, 0));
	port = TEST_SUCC(bound_port(receiver));
	TEST_RES(send_to_loopback(sender, port, "pong"), _ret == 4);
	TEST_RES(recvfrom(receiver, text, sizeof(text), 0,
			  (struct sockaddr *)&source, &source_length),
		 _ret == 4 && source.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	close(receiver);
	close(sender);
}
END_TEST()

FN_TEST(a_device_socket_can_connect)
{
	int receiver = udp_socket();
	int sender = udp_socket();
	struct sockaddr_in address = { .sin_family = AF_INET,
				       .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	char text[16];

	TEST_SUCC(bind_to_device(sender, "lo"));
	TEST_SUCC(bind_to_device(receiver, "lo"));
	TEST_SUCC(bind_any(receiver, 0));
	address.sin_port = htons(bound_port(receiver));
	TEST_SUCC(connect(sender, (struct sockaddr *)&address, sizeof(address)));
	TEST_RES(send(sender, "link", 4, 0), _ret == 4);
	TEST_RES(receive_text(receiver, text, sizeof(text)),
		 _ret == 4 && strcmp(text, "link") == 0);
	close(receiver);
	close(sender);
}
END_TEST()

FN_TEST(setting_the_device_it_already_has_succeeds_after_binding)
{
	int fd = udp_socket();

	TEST_SUCC(bind_to_device(fd, "lo"));
	TEST_SUCC(bind_any(fd, 0));
	TEST_SUCC(bind_to_device(fd, "lo"));
	close(fd);
}
END_TEST()

FN_TEST(changing_the_device_needs_net_raw_once_one_is_set)
{
	int fd = udp_socket();
	pid_t child;
	int status;

	TEST_SUCC(bind_to_device(fd, "lo"));
	child = CHECK(fork());
	if (child == 0) {
		if (setresuid(65534, 65534, 65534))
			_exit(2);
		errno = 0;
		_exit(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "", 0) == -1 &&
				      errno == EPERM ?
			      0 :
			      1);
	}
	TEST_RES(waitpid(child, &status, 0),
		 WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(fd);
}
END_TEST()

FN_TEST(an_unprivileged_user_may_set_the_first_device)
{
	pid_t child = CHECK(fork());
	int status;

	if (child == 0) {
		int fd;

		if (setresuid(65534, 65534, 65534))
			_exit(2);
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		_exit(bind_to_device(fd, "lo") == 0 ? 0 : 1);
	}
	TEST_RES(waitpid(child, &status, 0),
		 WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(a_wildcard_socket_receives_without_device_binding)
{
	int receiver = udp_socket();
	int sender = udp_socket();
	char text[16];
	int port;

	TEST_SUCC(bind_any(receiver, 0));
	port = TEST_SUCC(bound_port(receiver));
	TEST_RES(send_to_loopback(sender, port, "wildcard"), _ret == 8);
	TEST_RES(receive_text(receiver, text, sizeof(text)),
		 _ret == 8 && strcmp(text, "wildcard") == 0);
	close(receiver);
	close(sender);
}
END_TEST()

#ifdef __asterinas__
FN_TEST(a_bound_socket_cannot_change_its_device)
{
	int fd = udp_socket();

	TEST_SUCC(bind_to_device(fd, "lo"));
	TEST_SUCC(bind_any(fd, 0));
	TEST_ERRNO(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "", 0),
		   EOPNOTSUPP);
	close(fd);
}
END_TEST()
#endif
