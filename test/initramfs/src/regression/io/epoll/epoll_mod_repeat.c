// SPDX-License-Identifier: MPL-2.0

#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define ROUNDS 4000000
#define MAX_GROWTH_KIB (16 * 1024)

static long mem_free_kib(void)
{
	char line[256];
	long value = -1;
	FILE *meminfo = fopen("/proc/meminfo", "r");

	if (!meminfo)
		return -1;
	while (fgets(line, sizeof(line), meminfo))
		if (sscanf(line, "MemFree: %ld kB", &value) == 1)
			break;
	fclose(meminfo);
	return value;
}

int main(void)
{
	struct epoll_event event = { .events = EPOLLIN };
	struct itimerspec timer = { .it_value = { .tv_nsec = 1000000 } };
	int epfd = epoll_create1(0);
	int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	long before, after;

	if (epfd < 0 || tfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &event)) {
		perror("setup");
		return 1;
	}
	before = mem_free_kib();
	for (int i = 0; i < ROUNDS; i++) {
		event.events = (i & 1) ? EPOLLIN : EPOLLIN | EPOLLET;
		if (epoll_ctl(epfd, EPOLL_CTL_MOD, tfd, &event)) {
			perror("EPOLL_CTL_MOD");
			return 1;
		}
	}
	after = mem_free_kib();
	if (before < 0 || after < 0) {
		fprintf(stderr, "MemFree unavailable\n");
		return 1;
	}
	if (before - after > MAX_GROWTH_KIB) {
		fprintf(stderr, "EPOLL_CTL_MOD grew kernel memory by %ld KiB\n",
			before - after);
		return 1;
	}
	if (timerfd_settime(tfd, 0, &timer, NULL) ||
	    epoll_wait(epfd, &event, 1, 1000) != 1) {
		fprintf(stderr, "timerfd did not become ready\n");
		return 1;
	}
	close(tfd);
	close(epfd);
	return 0;
}
