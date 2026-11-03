// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <errno.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define NANOS 1000000000LL

static struct timespec resolution;

static long long resolution_ns(void)
{
	return (long long)resolution.tv_sec * NANOS + resolution.tv_nsec;
}

FN_TEST(clocks_with_nanosecond_readings_report_one_nanosecond)
{
	clockid_t clocks[] = { CLOCK_REALTIME,	      CLOCK_MONOTONIC,
			       CLOCK_MONOTONIC_RAW,   CLOCK_BOOTTIME,
			       CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID };

	for (size_t i = 0; i < sizeof(clocks) / sizeof(clocks[0]); i++) {
		TEST_SUCC(syscall(SYS_clock_getres, clocks[i], &resolution));
		TEST_RES(resolution_ns(), _ret == 1);
	}
}
END_TEST()

FN_TEST(coarse_clocks_report_a_timer_tick)
{
	clockid_t clocks[] = { CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE };

	for (size_t i = 0; i < sizeof(clocks) / sizeof(clocks[0]); i++) {
		TEST_SUCC(syscall(SYS_clock_getres, clocks[i], &resolution));
		TEST_RES(resolution_ns(),
			 _ret >= 1000000 && _ret <= 10000000);
	}
}
END_TEST()

FN_TEST(the_resolution_pointer_is_optional)
{
	TEST_SUCC(syscall(SYS_clock_getres, CLOCK_REALTIME, NULL));
}
END_TEST()

FN_TEST(an_unknown_clock_is_rejected)
{
	TEST_ERRNO(syscall(SYS_clock_getres, 12345, &resolution), EINVAL);
	TEST_ERRNO(syscall(SYS_clock_getres, -1, &resolution), EINVAL);
	TEST_ERRNO(syscall(SYS_clock_getres, 12345, NULL), EINVAL);
	TEST_ERRNO(syscall(SYS_clock_getres, CLOCK_REALTIME, (void *)1), EFAULT);
}
END_TEST()
