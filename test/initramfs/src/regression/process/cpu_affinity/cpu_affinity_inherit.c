// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
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

static void check_status(pid_t tid)
{
	cpu_set_t expected, mask, list;
	CPU_ZERO(&expected);
	CPU_ZERO(&mask);
	CPU_ZERO(&list);
	assert(sched_getaffinity(tid, sizeof(expected), &expected) == 0);
	char path[96];
	assert(snprintf(path, sizeof(path), "/proc/self/task/%d/status", tid) > 0);
	FILE *file = fopen(path, "r");
	assert(file != NULL);
	char *line = NULL;
	size_t capacity = 0;
	int found_mask = 0, found_list = 0;
	while (getline(&line, &capacity, file) >= 0) {
		if (strncmp(line, "Cpus_allowed:\t", 14) == 0) {
			found_mask++;
			size_t bit = 0;
			for (size_t i = strlen(line); i > 14;) {
				unsigned char ch = line[--i];
				if (ch == ',' || isspace(ch))
					continue;
				assert(isxdigit(ch));
				int value = isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
				for (int digit = 0; digit < 4; digit++, bit++) {
					if (!(value & (1 << digit)))
						continue;
					assert(bit < CPU_SETSIZE);
					CPU_SET(bit, &mask);
				}
			}
		} else if (strncmp(line, "Cpus_allowed_list:\t", 19) == 0) {
			found_list++;
			char *cursor = line + 19;
			while (*cursor && *cursor != '\n') {
				char *end;
				long first = strtol(cursor, &end, 10);
				assert(end > cursor && first >= 0 && first < CPU_SETSIZE);
				long last = first;
				cursor = end;
				if (*cursor == '-') {
					cursor++;
					last = strtol(cursor, &end, 10);
					assert(end > cursor && last >= first && last < CPU_SETSIZE);
					cursor = end;
				}
				for (long cpu = first; cpu <= last; cpu++)
					CPU_SET(cpu, &list);
				assert(*cursor == ',' || *cursor == '\n' || *cursor == '\0');
				if (*cursor == ',')
					cursor++;
			}
		}
	}
	assert(!ferror(file) && fclose(file) == 0);
	free(line);
	assert(found_mask == 1 && found_list == 1);
	assert(CPU_EQUAL(&mask, &expected));
	assert(CPU_EQUAL(&list, &expected));
	if (tid == getpid()) {
		char alias[4096], task[4096];
		FILE *leader = fopen("/proc/self/status", "r");
		FILE *thread = fopen(path, "r");
		assert(leader != NULL && thread != NULL);
		int aliases = 0;
		while (fgets(alias, sizeof(alias), leader)) {
			if (strncmp(alias, "Cpus_allowed", 12) != 0)
				continue;
			int found = 0;
			rewind(thread);
			while (fgets(task, sizeof(task), thread))
				if (strcmp(alias, task) == 0)
					found++;
			assert(found == 1);
			aliases++;
		}
		assert(aliases == 2 && fclose(leader) == 0 && fclose(thread) == 0);
	}
}

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
	check_status(gettid());
}

static void *check_thread(void *argument)
{
	struct affinity_test *test = argument;
	check_affinity(test->cpu, "thread");
	assert(sched_setaffinity(0, sizeof(test->available), &test->available) == 0);
	check_status(gettid());
	check_status(getpid());
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
	check_status(gettid());
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
