/* SPDX-License-Identifier: MPL-2.0 */
#define _GNU_SOURCE
#include "../common/test.h"
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static long long ns(clockid_t id)
{
	struct timespec t;
	if (clock_gettime(id, &t)) return -1;
	return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static int step(int seconds)
{
	struct timespec t;
	if (clock_gettime(CLOCK_REALTIME, &t)) return -1;
	t.tv_sec += seconds;
	return clock_settime(CLOCK_REALTIME, &t);
}

static void *stepper(void *p)
{
	struct timespec delay = { .tv_nsec = 200000000 };
	nanosleep(&delay, NULL);
	return (void *)(intptr_t)step(*(int *)p);
}

static int scenario(int kind, int direction)
{
	struct timespec start_wall, deadline;
	struct itimerspec spec = { 0 };
	struct sigevent event = { .sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1 };
	sigset_t set, old;
	timer_t timer = 0;
	int fd = -1, result = -1, delta = direction * 2;
	pthread_t thread;
	long long start, elapsed;
	uint64_t ticks;
	clockid_t clock = kind >= 3 ? CLOCK_TAI : CLOCK_REALTIME;
	if (clock_gettime(clock, &start_wall)) return -1;
	deadline = start_wall;
	deadline.tv_sec += 3;
	spec.it_value = deadline;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	if (pthread_sigmask(SIG_BLOCK, &set, &old)) return -1;
	if ((kind == 1 || kind == 4) && (timer_create(clock, &event, &timer) ||
	    timer_settime(timer, TIMER_ABSTIME, &spec, NULL))) goto done;
	if (kind == 2) {
		fd = timerfd_create(CLOCK_REALTIME, 0);
		if (fd < 0 || timerfd_settime(fd, TFD_TIMER_ABSTIME, &spec, NULL)) goto done;
	}
	start = ns(CLOCK_MONOTONIC);
	if (pthread_create(&thread, NULL, stepper, &delta)) goto done;
	if (kind == 0 || kind == 3) result = clock_nanosleep(clock, TIMER_ABSTIME, &deadline, NULL);
	if (kind == 1 || kind == 4) {
		struct timespec timeout = { .tv_sec = 8 };
		result = sigtimedwait(&set, NULL, &timeout) == SIGUSR1 ? 0 : -1;
	}
	if (kind == 2) result = read(fd, &ticks, sizeof(ticks)) == sizeof(ticks) && ticks == 1 ? 0 : -1;
	elapsed = ns(CLOCK_MONOTONIC) - start;
	void *step_result;
	pthread_join(thread, &step_result);
	if ((intptr_t)step_result || step(-delta)) result = -1;
	if (direction > 0 && !(elapsed > 500000000LL && elapsed < 2400000000LL)) result = -1;
	if (direction < 0 && !(elapsed > 4000000000LL && elapsed < 7000000000LL)) result = -1;
done:
	if ((kind == 1 || kind == 4) && timer) timer_delete(timer);
	if (fd >= 0) close(fd);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	return result;
}

static int cancel_on_step(int direction)
{
	struct timespec now;
	struct itimerspec spec = { 0 };
	uint64_t ticks;
	int fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
	if (fd < 0 || clock_gettime(CLOCK_REALTIME, &now)) return -1;
	spec.it_value = now;
	spec.it_value.tv_sec += 30;
	if (timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &spec, NULL) || step(direction)) {
		close(fd);
		return -1;
	}
	int ok = read(fd, &ticks, sizeof(ticks)) == -1 && errno == ECANCELED;
	if (step(-direction)) ok = 0;
	close(fd);
	errno = 0;
	return ok ? 0 : -1;
}

static int relative_unaffected(clockid_t clock, int direction)
{
	struct itimerspec spec = { .it_value = { .tv_sec = 2 } };
	uint64_t ticks;
	int fd = timerfd_create(clock, 0);
	int delta = direction * 2;
	pthread_t thread;
	if (fd < 0 || timerfd_settime(fd, 0, &spec, NULL)) return -1;
	long long start = ns(CLOCK_MONOTONIC);
	if (pthread_create(&thread, NULL, stepper, &delta)) { close(fd); return -1; }
	int ok = read(fd, &ticks, sizeof(ticks)) == sizeof(ticks) && ticks == 1;
	long long elapsed = ns(CLOCK_MONOTONIC) - start;
	void *step_result;
	pthread_join(thread, &step_result);
	if ((intptr_t)step_result || step(-delta)) ok = 0;
	close(fd);
	return ok && elapsed > 1500000000LL && elapsed < 3500000000LL ? 0 : -1;
}

FN_TEST(relative_and_monotonic_timers_ignore_wall_steps)
{
	TEST_RES(relative_unaffected(CLOCK_REALTIME, 1), _ret == 0);
	TEST_RES(relative_unaffected(CLOCK_REALTIME, -1), _ret == 0);
	TEST_RES(relative_unaffected(CLOCK_MONOTONIC, 1), _ret == 0);
	TEST_RES(relative_unaffected(CLOCK_MONOTONIC, -1), _ret == 0);
}
END_TEST()

FN_TEST(absolute_realtime_deadlines_follow_both_step_directions)
{
	for (int kind = 0; kind < 5; kind++) {
		TEST_RES(scenario(kind, 1), _ret == 0);
		TEST_RES(scenario(kind, -1), _ret == 0);
	}
}
END_TEST()

FN_TEST(cancel_on_set_returns_ecanceled)
{
	TEST_RES(cancel_on_step(1), _ret == 0);
	TEST_RES(cancel_on_step(-1), _ret == 0);
}
END_TEST()
