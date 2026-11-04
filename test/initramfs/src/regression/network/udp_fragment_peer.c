// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return 1;
	int mode = IP_PMTUDISC_DONT;
	if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode))) return 1;
	struct sockaddr_in target = { .sin_family = AF_INET, .sin_port = htons(39130) };
	if (inet_pton(AF_INET, "192.0.2.100", &target.sin_addr) != 1) return 1;
	unsigned char data[2000];
	for (int i = 0; i < sizeof(data); i++) data[i] = i % 251;
	for (int i = 0; i < 200; i++) {
		sendto(fd, data, sizeof(data), 0, (struct sockaddr *)&target, sizeof(target));
		usleep(250000);
	}
	close(fd);
	return 0;
}
