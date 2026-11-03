// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <linux/sched/types.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../common/test.h"

static long run_pair(unsigned long long slice)
{
	int ready[2], go[2], result[2];
	if (pipe(ready) || pipe(go) || pipe(result)) return -1;
	for (int i = 0; i < 2; i++) {
		pid_t child = fork();
		if (child == 0) {
			cpu_set_t cpus;
			CPU_ZERO(&cpus);
			CPU_SET(0, &cpus);
			struct sched_attr attr = { .size = sizeof(attr), .sched_runtime = slice };
			if (sched_setaffinity(0, sizeof(cpus), &cpus) || syscall(SYS_sched_setattr, 0, &attr, 0)) _exit(2);
			char c = 1;
			if (write(ready[1], &c, 1) != 1 || read(go[0], &c, 1) != 1) _exit(3);
			struct timespec start, now, previous;
			clock_gettime(CLOCK_MONOTONIC, &start);
			previous = start;
			long switches = 0;
			do {
				clock_gettime(CLOCK_MONOTONIC, &now);
				long long gap = (now.tv_sec - previous.tv_sec) * 1000000000LL + now.tv_nsec - previous.tv_nsec;
				if (gap > 50000) switches++;
				previous = now;
			}
			while ((now.tv_sec - start.tv_sec) * 1000000000LL + now.tv_nsec - start.tv_nsec < 600000000LL);
			if (write(result[1], &switches, sizeof(switches)) != sizeof(switches)) _exit(4);
			_exit(0);
		}
		if (child < 0) return -1;
	}
	char c;
	if (read(ready[0], &c, 1) != 1 || read(ready[0], &c, 1) != 1 || write(go[1], "xx", 2) != 2) return -1;
	long first, second;
	if (read(result[0], &first, sizeof(first)) != sizeof(first) || read(result[0], &second, sizeof(second)) != sizeof(second)) return -1;
	int status;
	if (wait(&status) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) || wait(&status) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) return -1;
	close(ready[0]); close(ready[1]); close(go[0]); close(go[1]); close(result[0]); close(result[1]);
	return first + second;
}
FN_TEST(custom_fair_slice_changes_preemption)
{
	alarm(15);
	long short_switches = run_pair(100000);
	long long_switches = run_pair(100000000);
	alarm(0);
	fprintf(stderr, "short switches=%ld long switches=%ld\n", short_switches, long_switches);
	TEST_RES(short_switches, _ret > 0 && long_switches > 0 && _ret > long_switches * 2);
}
END_TEST()
