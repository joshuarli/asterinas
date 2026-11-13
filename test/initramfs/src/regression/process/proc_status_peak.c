// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define REGION (32UL << 20)

struct memory {
	unsigned long peak, size, hwm, rss;
};

static unsigned long field(const char *status, const char *name)
{
	size_t length = strlen(name);
	const char *line = status;

	while (line != NULL) {
		if (strncmp(line, name, length) == 0 && line[length] == ':') {
			unsigned long value;
			assert(sscanf(line + length + 1, " %lu kB", &value) == 1);
			return value;
		}
		line = strchr(line, '\n');
		if (line != NULL) {
			line++;
		}
	}
	fprintf(stderr, "missing %s\n", name);
	exit(1);
}

static struct memory read_memory(void)
{
	char buf[16384];
	int fd = open("/proc/self/status", O_RDONLY);
	assert(fd >= 0);
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	assert(n > 0);
	buf[n] = '\0';
	assert(close(fd) == 0);

	struct memory memory = {
		.peak = field(buf, "VmPeak"),
		.size = field(buf, "VmSize"),
		.hwm = field(buf, "VmHWM"),
		.rss = field(buf, "VmRSS"),
	};
	assert(memory.peak >= memory.size);
	assert(memory.hwm >= memory.rss);
	return memory;
}

int main(void)
{
	struct memory before = read_memory();

	char *region = mmap(NULL, REGION, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(region != MAP_FAILED);
	for (size_t offset = 0; offset < REGION; offset += 4096) {
		region[offset] = 1;
	}

	unsigned long grown = REGION / 1024;
	struct memory during = read_memory();
	assert(during.rss >= before.rss + grown * 9 / 10);
	assert(during.hwm >= during.rss);
	assert(during.peak >= before.size + grown);

	assert(munmap(region, REGION) == 0);

	struct memory after = read_memory();
	assert(after.rss + grown / 2 < during.rss);
	assert(after.hwm >= before.hwm + grown * 9 / 10);
	assert(after.peak >= during.peak);
	assert(after.size + grown / 2 < during.size);

	printf("proc_status_peak: ok\n");
	return 0;
}
