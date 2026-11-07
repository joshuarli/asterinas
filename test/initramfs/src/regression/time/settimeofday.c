// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../common/test.h"

static struct timeval original;

FN_SETUP(save_time)
{
	CHECK(gettimeofday(&original, NULL));
	original.tv_sec += 3600;
}
END_SETUP()

FN_TEST(setting_the_time_updates_realtime)
{
	struct timeval target = original;
	target.tv_sec += 3;
	target.tv_usec = 123456;
	TEST_SUCC(syscall(SYS_settimeofday, &target, NULL));
	struct timeval observed;
	TEST_SUCC(gettimeofday(&observed, NULL));
	TEST_RES(observed.tv_sec, _ret >= target.tv_sec && _ret <= target.tv_sec + 1);
}
END_TEST()

FN_TEST(invalid_arguments_are_rejected)
{
	struct timeval value = original;
	value.tv_usec = -1;
	TEST_ERRNO(syscall(SYS_settimeofday, &value, NULL), EINVAL);
	value.tv_usec = 1000000;
	TEST_ERRNO(syscall(SYS_settimeofday, &value, NULL), EINVAL);
	value.tv_sec = 0;
	value.tv_usec = 0;
	TEST_ERRNO(syscall(SYS_settimeofday, &value, NULL), EINVAL);
	TEST_ERRNO(syscall(SYS_settimeofday, (void *)1, NULL), EFAULT);
	TEST_ERRNO(syscall(SYS_settimeofday, NULL, (void *)1), EFAULT);
	struct timezone invalid = { .tz_minuteswest = 901, .tz_dsttime = 0 };
	TEST_ERRNO(syscall(SYS_settimeofday, NULL, &invalid), EINVAL);
}
END_TEST()

FN_TEST(first_timezone_without_time_warps_the_clock)
{
	struct timeval before, after;
	struct timezone zone = { .tz_minuteswest = 1, .tz_dsttime = 0 };
	TEST_SUCC(gettimeofday(&before, NULL));
	TEST_SUCC(syscall(SYS_settimeofday, NULL, &zone));
	TEST_SUCC(gettimeofday(&after, NULL));
	TEST_RES(after.tv_sec - before.tv_sec, _ret >= 60 && _ret <= 61);
	zone.tz_minuteswest = 0;
	TEST_SUCC(syscall(SYS_settimeofday, NULL, &zone));
	TEST_SUCC(gettimeofday(&after, NULL));
	TEST_RES(after.tv_sec - before.tv_sec, _ret >= 60 && _ret <= 61);
}
END_TEST()

FN_TEST(timezone_is_read_back)
{
	struct timezone zone = { .tz_minuteswest = 37, .tz_dsttime = 2 };
	struct timezone observed = {};
	TEST_SUCC(syscall(SYS_settimeofday, &original, &zone));
	TEST_SUCC(syscall(SYS_gettimeofday, NULL, &observed));
	TEST_RES(observed.tz_minuteswest, _ret == zone.tz_minuteswest);
	TEST_RES(observed.tz_dsttime, _ret == zone.tz_dsttime);
	struct timeval now;
	observed.tz_minuteswest = 0;
	observed.tz_dsttime = 0;
	TEST_SUCC(gettimeofday(&now, &observed));
	TEST_RES(observed.tz_minuteswest, _ret == zone.tz_minuteswest);
	TEST_RES(observed.tz_dsttime, _ret == zone.tz_dsttime);
	zone.tz_minuteswest = 0;
	zone.tz_dsttime = 0;
	TEST_SUCC(syscall(SYS_settimeofday, &original, &zone));
}
END_TEST()

FN_TEST(unprivileged_time_changes_are_rejected)
{
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		if (setuid(123) != 0)
			_exit(2);
		errno = 0;
		_exit(syscall(SYS_settimeofday, &original, NULL) == -1 && errno == EPERM ? 0 : 3);
	}
	int status;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);
}
END_TEST()

FN_SETUP(restore_time)
{
	if (syscall(SYS_settimeofday, &original, NULL) != 0 && errno != ENOSYS)
		CHECK(-1);
}
END_SETUP()
