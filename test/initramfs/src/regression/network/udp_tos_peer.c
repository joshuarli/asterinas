// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return 1;
	int tos = 0xb9;
	if (setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos))) return 1;
	struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(39124) };
	if (inet_pton(AF_INET, "192.0.2.100", &destination.sin_addr) != 1) return 1;
	for (int i = 0; i < 200; i++) {
		sendto(fd, "peer", 4, 0, (struct sockaddr *)&destination, sizeof(destination));
		usleep(250000);
	}
	close(fd);
	return 0;
}
