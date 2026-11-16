/* SPDX-License-Identifier: MPL-2.0 */
#define _GNU_SOURCE
#include "../common/test.h"
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

FN_TEST(set_and_read_back)
{
	struct timeval original, target, actual;
	CHECK(gettimeofday(&original, NULL));
	target = original;
	target.tv_sec += 5;
	TEST_SUCC(syscall(SYS_settimeofday, &target, NULL));
	TEST_SUCC(gettimeofday(&actual, NULL));
	TEST_RES(actual.tv_sec - target.tv_sec, _ret >= 0 && _ret <= 2);
	TEST_SUCC(syscall(SYS_settimeofday, &original, NULL));
}
END_TEST()

FN_TEST(timezone_is_set_and_returned)
{
	struct timeval tv;
	struct timezone original, target = { .tz_minuteswest = 60, .tz_dsttime = 1 }, actual;
	CHECK(syscall(SYS_gettimeofday, &tv, &original));
	TEST_SUCC(syscall(SYS_settimeofday, &tv, &target));
	TEST_SUCC(syscall(SYS_gettimeofday, NULL, &actual));
	TEST_RES(actual.tz_minuteswest, _ret == target.tz_minuteswest);
	TEST_RES(actual.tz_dsttime, _ret == target.tz_dsttime);
	TEST_SUCC(gettimeofday(&tv, &actual));
	TEST_RES(actual.tz_minuteswest, _ret == target.tz_minuteswest);
	TEST_RES(actual.tz_dsttime, _ret == target.tz_dsttime);
	target.tz_minuteswest = 901;
	TEST_ERRNO(syscall(SYS_settimeofday, NULL, &target), EINVAL);
	TEST_SUCC(syscall(SYS_settimeofday, NULL, &original));
}
END_TEST()

FN_TEST(invalid_microseconds)
{
	struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 1000000 };
	TEST_ERRNO(syscall(SYS_settimeofday, &tv, NULL), EINVAL);
	tv.tv_usec = -1;
	TEST_ERRNO(syscall(SYS_settimeofday, &tv, NULL), EINVAL);
}
END_TEST()

FN_TEST(unprivileged_cannot_set_time_or_timezone)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 0 };
		struct timezone tz = { .tz_minuteswest = 0, .tz_dsttime = 0 };
		if (setuid(1000) != 0)
			_exit(1);
		if (syscall(SYS_settimeofday, &tv, NULL) != -1 || errno != EPERM)
			_exit(2);
		if (syscall(SYS_settimeofday, NULL, &tz) != -1 || errno != EPERM)
			_exit(3);
		_exit(0);
	}
	int status;
	TEST_RES(waitpid(pid, &status, 0), _ret == pid);
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);
}
END_TEST()
