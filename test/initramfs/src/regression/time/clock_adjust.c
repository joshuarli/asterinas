// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <stdint.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NANOS 1000000000LL

static long long now_ns(clockid_t clock)
{
	struct timespec ts;

	if (clock_gettime(clock, &ts) != 0)
		return -1;
	return (long long)ts.tv_sec * NANOS + ts.tv_nsec;
}

static long long raw_clock_ns(clockid_t clock)
{
	struct timespec ts;

	if (syscall(SYS_clock_gettime, clock, &ts) != 0)
		return -1;
	return (long long)ts.tv_sec * NANOS + ts.tv_nsec;
}

static int step_by_ns(long long delta)
{
	struct timex tx = { .modes = ADJ_SETOFFSET | ADJ_NANO };

	tx.time.tv_sec = delta / NANOS;
	tx.time.tv_usec = delta % NANOS;
	if (tx.time.tv_usec < 0) {
		tx.time.tv_sec -= 1;
		tx.time.tv_usec += NANOS;
	}
	return adjtimex(&tx);
}

static int set_frequency(long scaled_ppm)
{
	struct timex tx = { .modes = ADJ_FREQUENCY, .freq = scaled_ppm };

	return adjtimex(&tx);
}

static long long abs_ll(long long value)
{
	return value < 0 ? -value : value;
}

FN_TEST(reading_reports_the_clock_state)
{
	struct timex tx = { .modes = 0 };
	long long before = now_ns(CLOCK_REALTIME);

	TEST_RES(adjtimex(&tx), _ret == TIME_OK || _ret == TIME_ERROR);
	TEST_RES(tx.tick, _ret == 10000);
	TEST_RES(tx.tolerance, _ret == 32768000);
	TEST_RES(tx.freq, _ret == 0);
	TEST_RES((long long)tx.time.tv_sec * NANOS, abs_ll(_ret - before) < 5 * NANOS);
}
END_TEST()

FN_TEST(the_syscall_reads_what_the_vdso_reads)
{
	long long vdso = now_ns(CLOCK_REALTIME);
	long long raw = raw_clock_ns(CLOCK_REALTIME);

	TEST_RES(raw - vdso, abs_ll(_ret) < 50000000LL);
}
END_TEST()

FN_TEST(a_nanosecond_step_moves_only_the_realtime_clock)
{
	long long monotonic = now_ns(CLOCK_MONOTONIC);
	long long real = now_ns(CLOCK_REALTIME);

	TEST_RES(step_by_ns(1500000000LL), _ret == TIME_OK || _ret == TIME_ERROR);
	TEST_RES(now_ns(CLOCK_REALTIME) - real,
		 _ret > 1400000000LL && _ret < 1700000000LL);
	TEST_RES(raw_clock_ns(CLOCK_REALTIME) - real,
		 _ret > 1400000000LL && _ret < 1700000000LL);
	TEST_RES(now_ns(CLOCK_MONOTONIC) - monotonic, _ret >= 0 && _ret < 100000000LL);

	real = now_ns(CLOCK_REALTIME);
	TEST_SUCC(step_by_ns(-1500000000LL));
	TEST_RES(real - now_ns(CLOCK_REALTIME),
		 _ret > 1400000000LL && _ret < 1700000000LL);
}
END_TEST()

FN_TEST(a_microsecond_step_uses_microsecond_units)
{
	struct timex tx = { .modes = ADJ_SETOFFSET | ADJ_MICRO };
	long long real = now_ns(CLOCK_REALTIME);

	tx.time.tv_sec = 2;
	tx.time.tv_usec = 250000;
	TEST_SUCC(adjtimex(&tx));
	TEST_RES(now_ns(CLOCK_REALTIME) - real,
		 _ret > 2150000000LL && _ret < 2450000000LL);
	TEST_SUCC(step_by_ns(-2250000000LL));
}
END_TEST()

FN_TEST(clock_settime_sets_the_realtime_clock)
{
	struct timespec target;
	long long before = now_ns(CLOCK_REALTIME);

	target.tv_sec = before / NANOS + 100;
	target.tv_nsec = 5;
	TEST_SUCC(clock_settime(CLOCK_REALTIME, &target));
	TEST_RES(now_ns(CLOCK_REALTIME) - before,
		 _ret > 99000000000LL && _ret < 101000000000LL);

	target.tv_sec -= 100;
	TEST_SUCC(clock_settime(CLOCK_REALTIME, &target));
	TEST_RES(abs_ll(now_ns(CLOCK_REALTIME) - before), _ret < 1000000000LL);
}
END_TEST()

FN_TEST(a_frequency_correction_changes_the_rate_with_the_requested_sign)
{
	static const long scaled[] = { 200L << 16, -200L << 16 };

	for (int index = 0; index < 2; index++) {
		struct timex tx = { .modes = 0 };
		long long real = now_ns(CLOCK_REALTIME);
		long long raw = now_ns(CLOCK_MONOTONIC_RAW);
		long long drift;

		TEST_SUCC(set_frequency(scaled[index]));
		TEST_SUCC(adjtimex(&tx));
		TEST_RES(tx.freq, _ret == scaled[index]);

		usleep(2000000);
		drift = (now_ns(CLOCK_REALTIME) - real) -
			(now_ns(CLOCK_MONOTONIC_RAW) - raw);
		TEST_RES(drift,
			 index == 0 ? (_ret > 200000LL && _ret < 700000LL) :
				      (_ret < -200000LL && _ret > -700000LL));
	}
	TEST_SUCC(set_frequency(0));
}
END_TEST()

struct raw_bracket {
	long long raw_before;
	long long clock;
	long long raw_after;
};

static struct raw_bracket bracket(clockid_t clock)
{
	struct raw_bracket sample;

	sample.raw_before = now_ns(CLOCK_MONOTONIC_RAW);
	sample.clock = now_ns(clock);
	sample.raw_after = now_ns(CLOCK_MONOTONIC_RAW);
	return sample;
}

static int slew_may_lie_within(struct raw_bracket start, struct raw_bracket end,
			       long long low, long long high)
{
	long long elapsed = end.clock - start.clock;
	long long least = elapsed - (end.raw_after - start.raw_before);
	long long most = elapsed - (end.raw_before - start.raw_after);

	return least < high && most > low;
}

FN_TEST(a_frequency_correction_slews_monotonic_and_boottime_but_not_raw)
{
	struct raw_bracket monotonic = bracket(CLOCK_MONOTONIC);
	struct raw_bracket boottime = bracket(CLOCK_BOOTTIME);
	long long before;
	long long vdso;

	TEST_SUCC(set_frequency(200L << 16));
	usleep(2000000);
	TEST_RES(slew_may_lie_within(monotonic, bracket(CLOCK_MONOTONIC), 200000LL, 700000LL),
		 _ret);
	TEST_RES(slew_may_lie_within(boottime, bracket(CLOCK_BOOTTIME), 200000LL, 700000LL),
		 _ret);
	TEST_SUCC(set_frequency(0));

	before = raw_clock_ns(CLOCK_MONOTONIC);
	vdso = now_ns(CLOCK_MONOTONIC);
	TEST_RES(raw_clock_ns(CLOCK_MONOTONIC), before <= vdso && vdso <= _ret);
}
END_TEST()

FN_TEST(invalid_requests_fail_without_changing_the_clock)
{
	struct timespec bad_nsec = { .tv_sec = 1, .tv_nsec = 1000000000L };
	struct timespec negative = { .tv_sec = -1, .tv_nsec = 0 };
	struct timespec fine = { .tv_sec = 1, .tv_nsec = 0 };
	struct timex tx = { .modes = ADJ_SETOFFSET | ADJ_NANO };
	long long before = now_ns(CLOCK_REALTIME);

	TEST_ERRNO(clock_settime(CLOCK_REALTIME, &bad_nsec), EINVAL);
	TEST_ERRNO(clock_settime(CLOCK_REALTIME, &negative), EINVAL);
	TEST_ERRNO(clock_settime(CLOCK_MONOTONIC, &fine), EINVAL);
	TEST_ERRNO(clock_settime(99, &fine), EINVAL);

	tx.time.tv_sec = 1;
	tx.time.tv_usec = NANOS;
	TEST_ERRNO(adjtimex(&tx), EINVAL);
	tx.time.tv_usec = -1;
	TEST_ERRNO(adjtimex(&tx), EINVAL);
	TEST_RES(abs_ll(now_ns(CLOCK_REALTIME) - before), _ret < 500000000LL);

	tx.modes = 0;
	TEST_ERRNO(clock_adjtime(CLOCK_MONOTONIC, &tx), EOPNOTSUPP);
	TEST_ERRNO(clock_adjtime(99, &tx), EINVAL);
	TEST_RES(clock_adjtime(CLOCK_REALTIME, &tx), _ret == TIME_OK || _ret == TIME_ERROR);
}
END_TEST()

#ifdef __asterinas__
FN_TEST(modes_the_clock_cannot_honor_are_rejected)
{
	static const unsigned int modes[] = { ADJ_OFFSET, ADJ_TICK,
					      ADJ_OFFSET_SINGLESHOT };
	struct timex tx;

	for (int index = 0; index < 3; index++) {
		tx = (struct timex){ .modes = modes[index] };
		TEST_ERRNO(adjtimex(&tx), EINVAL);
	}
	tx = (struct timex){ .modes = ADJ_STATUS, .status = STA_PLL };
	TEST_ERRNO(adjtimex(&tx), EINVAL);
}
END_TEST()
#endif

FN_TEST(changing_the_clock_needs_cap_sys_time)
{
	pid_t child = CHECK(fork());

	if (child == 0) {
		struct timespec now;
		struct timex read = { .modes = 0 };
		struct timex write = { .modes = ADJ_FREQUENCY, .freq = 0 };
		int failures = 0;

		if (setresgid(1000, 1000, 1000) != 0 ||
		    setresuid(1000, 1000, 1000) != 0)
			_exit(2);
		clock_gettime(CLOCK_REALTIME, &now);
		if (clock_settime(CLOCK_REALTIME, &now) != -1 || errno != EPERM)
			failures++;
		if (adjtimex(&write) != -1 || errno != EPERM)
			failures++;
		if (adjtimex(&read) == -1)
			failures++;
		_exit(failures);
	}
	int status;

	TEST_RES(waitpid(child, &status, 0), WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(restore_a_neutral_clock)
{
	struct timex tx = { .modes = ADJ_STATUS | ADJ_FREQUENCY, .freq = 0,
			    .status = STA_UNSYNC };

	TEST_SUCC(adjtimex(&tx));
}
END_TEST()
