// SPDX-License-Identifier: MPL-2.0

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../common/test.h"

#define RECORD_LIMIT 8192
#define KERNEL_FACILITY 0

struct record_header {
	unsigned long priority;
	unsigned long long sequence;
};

static char line[RECORD_LIMIT];

static int read_record(int fd, struct record_header *header)
{
	ssize_t len = read(fd, line, sizeof(line) - 1);
	if (len < 0)
		return -1;
	line[len] = '\0';
	char *end;
	header->priority = strtoul(line, &end, 10);
	if (*end != ',')
		return -2;
	header->sequence = strtoull(end + 1, &end, 10);
	if (*end != ',')
		return -2;
	return 0;
}

FN_TEST(boot_leaves_kernel_records_in_one_sequence)
{
	int fd = TEST_SUCC(open("/dev/kmsg", O_RDONLY | O_NONBLOCK));
	struct record_header header;
	int kernel_records = 0;
	int gaps = 0;
	int first = 1;
	unsigned long long previous = 0;
	int status;
	int stop_errno = 0;
	while ((status = read_record(fd, &header)) == 0 ||
	       (status == -1 && errno == EPIPE)) {
		if (status != 0) {
			first = 1;
			continue;
		}
		if (!first && header.sequence != previous + 1)
			gaps++;
		if (header.priority >> 3 == KERNEL_FACILITY)
			kernel_records++;
		previous = header.sequence;
		first = 0;
	}
	if (status == -1)
		stop_errno = errno;
	TEST_RES(status == -1 ? stop_errno : status, _ret == EAGAIN);
	TEST_RES(kernel_records, _ret > 0);
	TEST_RES(gaps, _ret == 0);

	const char written[] = "<14>laputa-kmsg after the kernel records\n";
	int writer = TEST_SUCC(open("/dev/kmsg", O_WRONLY));
	TEST_RES(write(writer, written, sizeof(written) - 1),
		 _ret == sizeof(written) - 1);
	TEST_SUCC(close(writer));

	int found = 0;
	while (!found && read_record(fd, &header) == 0)
		found = header.priority == 14 && header.sequence > previous &&
			strstr(line, ";laputa-kmsg after the kernel records\n");
	TEST_RES(found, _ret == 1);
	TEST_SUCC(close(fd));
}
END_TEST()
