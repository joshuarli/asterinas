// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static void alarm_handler(int number)
{
	(void)number;
}

static void expect_empty(int fd, int operation)
{
	char byte;
	struct iovec vector = {.iov_base = &byte, .iov_len = 1};
	struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
	ssize_t result;
	int error;

	alarm(2);
	if (operation == 0)
		result = recv(fd, &byte, 1, MSG_DONTWAIT);
	else if (operation == 1)
		result = recvfrom(fd, &byte, 1, MSG_DONTWAIT, NULL, NULL);
	else
		result = recvmsg(fd, &message, MSG_DONTWAIT);
	error = errno;
	alarm(0);
	if (result != -1 || error != EAGAIN)
		fprintf(stderr, "empty receive %d: result=%zd errno=%d, expected EAGAIN\n", operation, result, error);
	assert(result == -1 && error == EAGAIN);
	assert((fcntl(fd, F_GETFL) & O_NONBLOCK) == 0);
}

int main(void)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sigaction action = {.sa_handler = alarm_handler};
	socklen_t address_size = sizeof(address);
	char bytes[4] = {0};
	struct iovec vector = {.iov_base = bytes, .iov_len = sizeof(bytes)};
	struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
	int receiver = socket(AF_INET, SOCK_DGRAM, 0);
	int sender = socket(AF_INET, SOCK_DGRAM, 0);
	int alias;

	assert(receiver >= 0 && sender >= 0);
	assert(sigemptyset(&action.sa_mask) == 0);
	assert(sigaction(SIGALRM, &action, NULL) == 0);
	assert(bind(receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
	assert(getsockname(receiver, (struct sockaddr *)&address, &address_size) == 0);
	alias = dup(receiver);
	assert(alias >= 0);
	for (int operation = 0; operation < 3; operation++) {
		expect_empty(receiver, operation);
		assert((fcntl(alias, F_GETFL) & O_NONBLOCK) == 0);
	}
	assert(sendto(sender, "abc", 3, 0, (struct sockaddr *)&address, sizeof(address)) == 3);
	struct pollfd ready = {.fd = receiver, .events = POLLIN};
	assert(poll(&ready, 1, 2000) == 1);
	assert(recv(receiver, bytes, 1, MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC) == 3);
	assert(bytes[0] == 'a');
	assert(recvmsg(alias, &message, MSG_DONTWAIT) == 3);
	assert(bytes[0] == 'a' && bytes[1] == 'b' && bytes[2] == 'c');
	expect_empty(receiver, 2);
	assert(close(alias) == 0);
	assert(close(receiver) == 0);
	assert(close(sender) == 0);
	puts("udp dontwait: empty receives return EAGAIN, descriptor flags stay blocking, peek and truncation compose");
	return 0;
}
