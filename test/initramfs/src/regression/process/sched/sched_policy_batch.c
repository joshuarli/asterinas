// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <linux/sched.h>
#include <linux/sched/types.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif

static int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags)
{
	return syscall(SYS_sched_setattr, pid, attr, flags);
}

static int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size,
			 unsigned int flags)
{
	return syscall(SYS_sched_getattr, pid, attr, size, flags);
}

static struct sched_param param;
static struct sched_attr attr;

static long proc_stat_field(int field)
{
	char buf[4096];
	FILE *file = fopen("/proc/self/stat", "r");
	if (!file || !fgets(buf, sizeof(buf), file))
		return -1;
	fclose(file);
	char *end = strrchr(buf, ')');
	if (!end)
		return -1;
	char *save;
	char *token = strtok_r(end + 2, " ", &save);
	for (int current = 3; token && current < field; current++)
		token = strtok_r(NULL, " ", &save);
	return token ? strtol(token, NULL, 10) : -1;
}

FN_TEST(batch_policy_is_reported_as_set)
{
	TEST_SUCC(sched_setscheduler(0, SCHED_BATCH, &param));
	TEST_RES(sched_getscheduler(0), _ret == SCHED_BATCH);
	TEST_RES(proc_stat_field(41), _ret == SCHED_BATCH);

	TEST_RES(sched_getattr(0, &attr, sizeof(attr), 0),
		 attr.sched_policy == SCHED_BATCH && attr.sched_flags == 0 &&
			 attr.sched_priority == 0);
	pid_t child = TEST_SUCC(fork());
	if (child == 0)
		_exit(sched_getscheduler(0) == SCHED_BATCH ? 0 : 1);
	int status;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);

	TEST_SUCC(sched_setscheduler(0, SCHED_OTHER, &param));
	TEST_RES(sched_getscheduler(0), _ret == SCHED_OTHER);
}
END_TEST()

FN_TEST(unprivileged_process_cannot_change_another_users_policy)
{
	pid_t parent = getpid();
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		struct sched_param child_param = { .sched_priority = 0 };
		if (setuid(123) != 0)
			_exit(2);
		errno = 0;
		int result = sched_setscheduler(parent, SCHED_OTHER, &child_param);
		int error = errno;
		fprintf(stderr, "foreign policy result=%d errno=%d\n", result, error);
		if (result != -1 || error != EPERM)
			_exit(3);
		_exit(0);
	}
	int status;
	TEST_SUCC(waitpid(child, &status, 0));
	fprintf(stderr, "authorization child status=%d\n", status);
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);
}
END_TEST()

FN_TEST(unprivileged_process_cannot_enter_realtime_scheduling)
{
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		struct sched_param child_param = { .sched_priority = 1 };
		if (setuid(123) != 0)
			_exit(2);
		errno = 0;
		int result = sched_setscheduler(0, SCHED_FIFO, &child_param);
		int error = errno;
		fprintf(stderr, "realtime policy result=%d errno=%d\n", result, error);
		_exit(result == -1 && error == EPERM ? 0 : 3);
	}
	int status;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);
}
END_TEST()

FN_TEST(unprivileged_process_can_set_batch_but_cannot_clear_reset_on_fork)
{
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		struct sched_param child_param = { .sched_priority = 0 };
		if (setuid(123) != 0)
			_exit(2);
		if (sched_setscheduler(0, SCHED_BATCH | SCHED_RESET_ON_FORK, &child_param) != 0)
			_exit(3);
		errno = 0;
		int result = sched_setscheduler(0, SCHED_BATCH, &child_param);
		_exit(result == -1 && errno == EPERM ? 0 : 4);
	}
	int status;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);
}
END_TEST()

FN_TEST(batch_policy_takes_no_priority)
{
	param.sched_priority = 1;
	TEST_ERRNO(sched_setscheduler(0, SCHED_BATCH, &param), EINVAL);
	param.sched_priority = 0;
	TEST_RES(sched_getscheduler(0), _ret == SCHED_OTHER);
}
END_TEST()

FN_TEST(reset_on_fork_is_reported_as_set)
{
	TEST_SUCC(sched_setscheduler(0, SCHED_IDLE | SCHED_RESET_ON_FORK,
				     &param));
	TEST_RES(proc_stat_field(41), _ret == SCHED_IDLE);
	TEST_RES(proc_stat_field(18), _ret == 20 + getpriority(PRIO_PROCESS, 0));
	TEST_RES(sched_getscheduler(0),
		 _ret == (SCHED_IDLE | SCHED_RESET_ON_FORK));

	TEST_RES(sched_getattr(0, &attr, sizeof(attr), 0),
		 attr.sched_policy == SCHED_IDLE &&
			 (attr.sched_flags & SCHED_FLAG_RESET_ON_FORK) != 0);
	pid_t child = TEST_SUCC(fork());
	if (child == 0)
		_exit(sched_getscheduler(0) == SCHED_IDLE ? 0 : 1);
	int status;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);

	TEST_SUCC(sched_setscheduler(0, SCHED_OTHER, &param));
	TEST_RES(sched_getscheduler(0), _ret == SCHED_OTHER);
}
END_TEST()

FN_TEST(fair_time_slice_is_kept_until_the_policy_changes)
{
	memset(&attr, 0, sizeof(attr));
	TEST_SUCC(sched_getattr(0, &attr, sizeof(attr), 0));
	unsigned long long default_runtime = attr.sched_runtime;
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_BATCH;
	attr.sched_runtime = 3000000;
	TEST_SUCC(sched_setattr(0, &attr, 0));

	TEST_RES(sched_getattr(0, &attr, sizeof(attr), 0),
		 attr.sched_policy == SCHED_BATCH &&
			 attr.sched_runtime == 3000000);

	TEST_SUCC(sched_setscheduler(0, SCHED_OTHER, &param));
	TEST_SUCC(sched_getattr(0, &attr, sizeof(attr), 0));
	TEST_RES(attr.sched_runtime, _ret == 3000000);
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_BATCH;
	TEST_SUCC(sched_setattr(0, &attr, 0));
	TEST_RES(sched_getattr(0, &attr, sizeof(attr), 0),
		 attr.sched_policy == SCHED_BATCH && attr.sched_runtime == default_runtime);
}
END_TEST()

FN_TEST(reset_on_fork_restores_the_default_fair_time_slice)
{
	memset(&attr, 0, sizeof(attr));
	TEST_SUCC(sched_getattr(0, &attr, sizeof(attr), 0));
	unsigned long long default_runtime = attr.sched_runtime;
	unsigned long long custom_runtime = default_runtime == 3000000 ? 8000000 : 3000000;
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_BATCH;
	attr.sched_flags = SCHED_FLAG_RESET_ON_FORK;
	attr.sched_runtime = custom_runtime;
	TEST_SUCC(sched_setattr(0, &attr, 0));
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		struct sched_attr child_attr = {};
		if (sched_getattr(0, &child_attr, sizeof(child_attr), 0) != 0)
			_exit(2);
		_exit(child_attr.sched_policy == SCHED_BATCH && child_attr.sched_flags == 0 &&
		      child_attr.sched_runtime == default_runtime ? 0 : 3);
	}
	int status;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(_ret) && WEXITSTATUS(_ret) == 0);
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_OTHER;
	TEST_SUCC(sched_setattr(0, &attr, 0));
}
END_TEST()
