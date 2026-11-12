// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct affinity_test {
	int cpu;
	cpu_set_t available;
};

static void check_affinity(int cpu, const char *stage)
{
	cpu_set_t actual, expected;
	CPU_ZERO(&actual);
	CPU_ZERO(&expected);
	CPU_SET(cpu, &expected);
	assert(sched_getaffinity(0, sizeof(actual), &actual) == 0);
	printf("AFFINITY %s expected_cpu=%d actual_count=%d\n", stage, cpu,
	       CPU_COUNT(&actual));
	assert(CPU_EQUAL(&actual, &expected));
}

static void *check_thread(void *argument)
{
	struct affinity_test *test = argument;
	check_affinity(test->cpu, "thread");
	assert(sched_setaffinity(0, sizeof(test->available), &test->available) == 0);
	return NULL;
}

int main(int argc, char *argv[])
{
	assert(setvbuf(stdout, NULL, _IONBF, 0) == 0);
	if (argc == 3 && strcmp(argv[1], "--exec-check") == 0) {
		char *end;
		long cpu = strtol(argv[2], &end, 10);
		assert(*end == '\0' && cpu >= 0 && cpu < CPU_SETSIZE);
		check_affinity(cpu, "exec");
		return 0;
	}
	assert(argc == 1 || argc == 2);
	const char *mode = argc == 2 ? argv[1] : "all";
	assert(strcmp(mode, "all") == 0 || strcmp(mode, "fork") == 0 ||
	       strcmp(mode, "thread") == 0 || strcmp(mode, "exec") == 0);
	struct affinity_test test = { .cpu = -1 };
	CPU_ZERO(&test.available);
	assert(sched_getaffinity(0, sizeof(test.available), &test.available) == 0);
	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &test.available)) {
			test.cpu = cpu;
			break;
		}
	}
	assert(test.cpu >= 0);
	cpu_set_t restricted;
	CPU_ZERO(&restricted);
	CPU_SET(test.cpu, &restricted);
	assert(sched_setaffinity(0, sizeof(restricted), &restricted) == 0);
	check_affinity(test.cpu, "set");

	if (strcmp(mode, "all") == 0 || strcmp(mode, "fork") == 0) {
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			check_affinity(test.cpu, "fork");
			assert(sched_setaffinity(0, sizeof(test.available),
					 &test.available) == 0);
			_exit(0);
		}
		int status;
		assert(waitpid(child, &status, 0) == child);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		check_affinity(test.cpu, "parent-after-fork");
	}
	if (strcmp(mode, "all") == 0 || strcmp(mode, "thread") == 0) {
		pthread_t thread;
		assert(pthread_create(&thread, NULL, check_thread, &test) == 0);
		assert(pthread_join(thread, NULL) == 0);
		check_affinity(test.cpu, "parent-after-thread");
	}
	if (strcmp(mode, "all") == 0 || strcmp(mode, "exec") == 0) {
		char cpu[16];
		assert(snprintf(cpu, sizeof(cpu), "%d", test.cpu) > 0);
		char *arguments[] = { argv[0], "--exec-check", cpu, NULL };
		execv(argv[0], arguments);
		perror("execv");
		return 1;
	}
	return 0;
}
