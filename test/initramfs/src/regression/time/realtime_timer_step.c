// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../common/test.h"

static struct timespec original;

static void step_forward(void)
{
	struct timespec now;
	CHECK(clock_gettime(CLOCK_REALTIME, &now));
	now.tv_sec += 120;
	CHECK(clock_settime(CLOCK_REALTIME, &now));
}

FN_SETUP(save_clock)
{
	CHECK(clock_gettime(CLOCK_REALTIME, &original));
	original.tv_sec += 3600;
	CHECK(clock_settime(CLOCK_REALTIME, &original));
}
END_SETUP()

FN_TEST(absolute_realtime_timer_expires_after_forward_step)
{
	int fd = TEST_SUCC(timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK));
	struct timespec now;
	TEST_SUCC(clock_gettime(CLOCK_REALTIME, &now));
	struct itimerspec timer = { .it_value = { .tv_sec = now.tv_sec + 60, .tv_nsec = now.tv_nsec } };
	TEST_SUCC(timerfd_settime(fd, TFD_TIMER_ABSTIME, &timer, NULL));
	step_forward();
	struct pollfd ready = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
	uint64_t count;
	TEST_RES(read(fd, &count, sizeof(count)), _ret == sizeof(count) && count == 1);
	TEST_SUCC(close(fd));
}
END_TEST()

static int sleep_across_step(int absolute)
{
	int fds[2];
	CHECK(pipe(fds));
	struct timespec deadline;
	if (absolute) {
		CHECK(clock_gettime(CLOCK_REALTIME, &deadline));
		deadline.tv_sec += 60;
	} else {
		deadline = (struct timespec){ .tv_sec = 1 };
	}
	pid_t child = CHECK(fork());
	if (child == 0) {
		close(fds[0]);
		if (write(fds[1], "s", 1) != 1)
			_exit(2);
		if (clock_nanosleep(CLOCK_REALTIME, absolute ? TIMER_ABSTIME : 0, &deadline, NULL) != 0)
			_exit(3);
		if (write(fds[1], "d", 1) != 1)
			_exit(4);
		_exit(0);
	}
	CHECK(close(fds[1]));
	char marker;
	CHECK_WITH(read(fds[0], &marker, 1), _ret == 1 && marker == 's');
	struct pollfd ready = { .fd = fds[0], .events = POLLIN };
	CHECK_WITH(poll(&ready, 1, 50), _ret == 0);
	step_forward();
	int count = poll(&ready, 1, absolute ? 2000 : 100);
	int expected = absolute ? count == 1 : count == 0;
	if (absolute && count != 1)
		CHECK(kill(child, SIGKILL));
	int status;
	CHECK(waitpid(child, &status, 0));
	CHECK(close(fds[0]));
	return expected && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

FN_TEST(absolute_realtime_sleep_expires_after_forward_step)
{
	TEST_RES(sleep_across_step(1), _ret == 1);
}
END_TEST()

FN_TEST(relative_realtime_sleep_ignores_clock_steps)
{
	TEST_RES(sleep_across_step(0), _ret == 1);
}
END_TEST()

FN_TEST(relative_realtime_timer_ignores_clock_steps)
{
	int fd = TEST_SUCC(timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK));
	struct itimerspec timer = { .it_value = { .tv_sec = 1, .tv_nsec = 0 } };
	TEST_SUCC(timerfd_settime(fd, 0, &timer, NULL));
	step_forward();
	struct timespec delay = { .tv_nsec = 20000000 };
	TEST_SUCC(nanosleep(&delay, NULL));
	struct pollfd ready = { .fd = fd, .events = POLLIN };
	TEST_RES(poll(&ready, 1, 0), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(cancel_on_set_reports_a_clock_change)
{
	int fd = TEST_SUCC(timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK));
	struct timespec now;
	TEST_SUCC(clock_gettime(CLOCK_REALTIME, &now));
	struct itimerspec timer = { .it_value = { .tv_sec = now.tv_sec + 60, .tv_nsec = now.tv_nsec } };
	TEST_SUCC(timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &timer, NULL));
	step_forward();
	uint64_t count;
	TEST_ERRNO(read(fd, &count, sizeof(count)), ECANCELED);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_SETUP(restore_clock)
{
	CHECK(clock_settime(CLOCK_REALTIME, &original));
}
END_SETUP()
