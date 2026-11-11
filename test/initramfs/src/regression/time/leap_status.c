// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <stdint.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_SECOND 1000000000LL
#define SECONDS_PER_DAY 86400LL

static long long clock_ns(clockid_t clock)
{
	struct timespec ts;

	if (clock_gettime(clock, &ts) != 0)
		return -1;
	return (long long)ts.tv_sec * NS_PER_SECOND + ts.tv_nsec;
}

static int set_status(int status)
{
	struct timex tx = { .modes = ADJ_STATUS, .status = status };

	return adjtimex(&tx);
}

static int set_maxerror(long maxerror)
{
	struct timex tx = { .modes = ADJ_MAXERROR, .maxerror = maxerror };

	return adjtimex(&tx);
}

static int read_timex(struct timex *tx)
{
	*tx = (struct timex){ .modes = 0 };
	return adjtimex(tx);
}

static void sleep_until(long long deadline)
{
	for (;;) {
		long long remaining = deadline - clock_ns(CLOCK_MONOTONIC);
		struct timespec request;

		if (remaining <= 0)
			return;
		request.tv_sec = remaining / NS_PER_SECOND;
		request.tv_nsec = remaining % NS_PER_SECOND;
		clock_nanosleep(CLOCK_MONOTONIC, 0, &request, NULL);
	}
}

FN_TEST(an_insertion_is_scheduled_and_repeats_the_last_second)
{
	long long now = clock_ns(CLOCK_REALTIME);
	long long midnight;
	struct timespec target;
	struct timex before;
	long long start;

	CHECK(now > 0);
	midnight = (now / NS_PER_SECOND / SECONDS_PER_DAY + 1) * SECONDS_PER_DAY;
	target.tv_sec = midnight - 3;
	target.tv_nsec = 0;
	TEST_SUCC(clock_settime(CLOCK_REALTIME, &target));
	TEST_SUCC(set_maxerror(1000));

	TEST_SUCC(read_timex(&before));
	TEST_SUCC(set_status(STA_INS));
	start = clock_ns(CLOCK_MONOTONIC);

	sleep_until(start + 2 * NS_PER_SECOND);
	struct timex during;
	TEST_RES(read_timex(&during), _ret == TIME_INS);
	TEST_RES(during.status & STA_INS, _ret != 0);
	TEST_RES(clock_ns(CLOCK_REALTIME) / NS_PER_SECOND,
		 _ret == midnight - 1);

	sleep_until(start + 7 * NS_PER_SECOND / 2);
	TEST_RES(clock_ns(CLOCK_REALTIME) / NS_PER_SECOND,
		 _ret == midnight - 1);

	sleep_until(start + 9 * NS_PER_SECOND / 2);
	TEST_RES(clock_ns(CLOCK_REALTIME) / NS_PER_SECOND, _ret == midnight);

	struct timex after;
	TEST_RES(read_timex(&after), _ret == TIME_WAIT);
	TEST_RES(after.tai, _ret == before.tai + 1);
	TEST_RES(after.status & STA_INS, _ret != 0);

	TEST_SUCC(set_status(0));
	sleep_until(start + 6 * NS_PER_SECOND);
	struct timex cleared;
	TEST_RES(read_timex(&cleared), _ret == TIME_OK);
}
END_TEST()

FN_TEST(a_deletion_is_scheduled_at_the_next_day_boundary)
{
	struct timex tx;
	long long start;

	TEST_SUCC(set_maxerror(1000));
	TEST_SUCC(set_status(STA_DEL));
	start = clock_ns(CLOCK_MONOTONIC);

	sleep_until(start + 3 * NS_PER_SECOND / 2);
	TEST_RES(read_timex(&tx), _ret == TIME_DEL);
	TEST_RES(tx.status & STA_DEL, _ret != 0);

	TEST_SUCC(set_status(0));
	sleep_until(start + 3 * NS_PER_SECOND);
	TEST_RES(read_timex(&tx), _ret == TIME_OK);
}
END_TEST()
