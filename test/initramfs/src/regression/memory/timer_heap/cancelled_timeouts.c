// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#include "../../common/test.h"

#define ROUNDS 400000
#define HOUR_MS (60 * 60 * 1000)
#define MAX_GROWTH_KB (24 * 1024)

static int to_helper[2];
static int to_main[2];
static int meminfo_fd;

static unsigned long meminfo_kb(const char *name)
{
	char buf[2048];
	ssize_t len = CHECK(pread(meminfo_fd, buf, sizeof(buf) - 1, 0));
	char *line;

	buf[len] = '\0';
	line = strstr(buf, name);
	if (!line)
		exit(EXIT_FAILURE);
	return strtoul(line + strlen(name), NULL, 10);
}

static void wait_readable_then_take(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	char byte;

	if (poll(&pfd, 1, HOUR_MS) != 1 || read(fd, &byte, 1) != 1)
		exit(EXIT_FAILURE);
}

static void *helper(void *arg)
{
	char byte = 1;

	(void)arg;
	for (int i = 0; i < ROUNDS; i++) {
		wait_readable_then_take(to_helper[0]);
		for (volatile int spin = 0; spin < 2000; spin++)
			;
		if (write(to_main[1], &byte, 1) != 1)
			exit(EXIT_FAILURE);
	}
	return NULL;
}

FN_SETUP(init)
{
	meminfo_fd = CHECK(open("/proc/meminfo", O_RDONLY));
	CHECK(pipe(to_helper));
	CHECK(pipe(to_main));
}
END_SETUP()

FN_TEST(cancelled_long_timeouts_do_not_pile_up)
{
	pthread_t thread;
	unsigned long slab_before = meminfo_kb("Slab:");
	unsigned long free_before = meminfo_kb("MemFree:");
	unsigned long slab_after;
	unsigned long free_after;
	char byte = 1;

	CHECK(pthread_create(&thread, NULL, helper, NULL));
	for (int i = 0; i < ROUNDS; i++) {
		if (write(to_helper[1], &byte, 1) != 1)
			exit(EXIT_FAILURE);
		wait_readable_then_take(to_main[0]);
	}
	CHECK(pthread_join(thread, NULL));

	slab_after = meminfo_kb("Slab:");
	free_after = meminfo_kb("MemFree:");
	fprintf(stderr, "slab %lu -> %lu kB, free %lu -> %lu kB\n", slab_before,
		slab_after, free_before, free_after);

	TEST_RES(slab_after, _ret < slab_before + MAX_GROWTH_KB);
	TEST_RES(free_after, _ret + MAX_GROWTH_KB > free_before);
}
END_TEST()
