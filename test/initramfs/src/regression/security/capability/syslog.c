// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../../common/capability.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYSLOG_ACTION_CLOSE 0
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

static int dmesg_is_restricted(void)
{
	char value[8] = "";
	int fd = open("/proc/sys/kernel/dmesg_restrict", O_RDONLY);

	if (fd < 0) {
		return 1;
	}
	CHECK(read(fd, value, sizeof(value) - 1));
	CHECK(close(fd));
	return value[0] != '0';
}

static int holds_cap_syslog(void)
{
	struct __user_cap_data_struct cap_data[2] = {};

	read_cap_data(cap_data);
	return (cap_data[1].effective & (1U << (CAP_SYSLOG - 32))) != 0;
}

static long klogctl_raw(int action, char *buf, int len)
{
	return syscall(SYS_syslog, action, buf, len);
}

FN_TEST(unprivileged_reader_is_refused)
{
	int status;
	pid_t pid;

	SKIP_TEST_IF(!dmesg_is_restricted());

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		char buf[64];
		int fd, error;

		CHECK(setresgid(1000, 1000, 1000));
		CHECK(setresuid(1000, 1000, 1000));

		CHECK_WITH(klogctl_raw(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0),
			   _ret == -1 && errno == EPERM);
		CHECK_WITH(klogctl_raw(SYSLOG_ACTION_READ_ALL, buf, sizeof(buf)),
			   _ret == -1 && errno == EPERM);
		CHECK_WITH(klogctl_raw(SYSLOG_ACTION_CLOSE, NULL, 0),
			   _ret == -1 && errno == EPERM);
		CHECK_WITH(klogctl_raw(99, NULL, 0),
			   _ret == -1 && errno == EPERM);

		fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
		if (fd >= 0) {
			fprintf(stderr, "/dev/kmsg opened by an unprivileged reader\n");
			_exit(EXIT_FAILURE);
		}
		error = errno;
		if (error != EPERM && error != ENOENT) {
			fprintf(stderr, "/dev/kmsg failed with errno %d\n", error);
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
}
END_TEST()

FN_TEST(privileged_reader_reads_the_buffer)
{
	char *buf;
	long size;
	long length;

	SKIP_TEST_IF(!holds_cap_syslog());

	size = TEST_RES(klogctl_raw(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0),
			_ret > 0);
	buf = malloc(size);
	CHECK_WITH(buf != NULL, _ret == 1);
	length = TEST_RES(klogctl_raw(SYSLOG_ACTION_READ_ALL, buf, size),
			  _ret >= 0 && _ret <= size);
	if (length > 0) {
		TEST_RES(buf[0], _ret == '<');
		TEST_RES(buf[length - 1], _ret == '\n');
	}
	free(buf);

	TEST_ERRNO(klogctl_raw(99, NULL, 0), EINVAL);
	TEST_ERRNO(klogctl_raw(SYSLOG_ACTION_READ_ALL, NULL, 16), EINVAL);
}
END_TEST()
