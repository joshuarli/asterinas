// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "../common/test.h"

FN_TEST(timezone_warp_before_epoch_is_ignored)
{
	struct timespec monotonic;
	TEST_SUCC(clock_gettime(CLOCK_MONOTONIC, &monotonic));
	struct timeval wall = { .tv_sec = monotonic.tv_sec + 1 };
	time_t original = wall.tv_sec;
	TEST_SUCC(syscall(SYS_settimeofday, &wall, NULL));
	struct timezone zone = { .tz_minuteswest = -900 };
	TEST_SUCC(syscall(SYS_settimeofday, NULL, &zone));
	TEST_SUCC(syscall(SYS_gettimeofday, &wall, NULL));
	TEST_RES(wall.tv_sec, _ret >= original && _ret <= original + 2);
}
END_TEST()
