// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t read_mask(const char *path, const char *field)
{
	FILE *file = fopen(path, "r");
	char line[1024];
	unsigned long long value;

	assert(file != NULL);
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, field, strlen(field)) == 0 &&
		    line[strlen(field)] == ':') {
			assert(sscanf(line + strlen(field) + 1, "%llx", &value) == 1);
			assert(fclose(file) == 0);
			return value;
		}
	}
	assert(fclose(file) == 0);
	fprintf(stderr, "%s is missing from %s\n", field, path);
	exit(1);
}

static uint64_t signal_bit(int number)
{
	return UINT64_C(1) << (number - 1);
}

static void check_masks(const char *path)
{
	sigset_t blocked;
	uint64_t blocked_bits = 0, ignored = 0, caught = 0, queryable = 0;

	assert(pthread_sigmask(SIG_SETMASK, NULL, &blocked) == 0);
	for (int number = 1; number <= 64; number++) {
		struct sigaction action;

		if (sigismember(&blocked, number) == 1)
			blocked_bits |= signal_bit(number);
		if (sigaction(number, NULL, &action) != 0)
			continue;
		queryable |= signal_bit(number);
		if (action.sa_handler == SIG_IGN)
			ignored |= signal_bit(number);
		else if (action.sa_handler != SIG_DFL)
			caught |= signal_bit(number);
	}
	assert(read_mask(path, "SigBlk") == blocked_bits);
	assert((read_mask(path, "SigIgn") & queryable) == ignored);
	assert((read_mask(path, "SigCgt") & queryable) == caught);
}

static void handler(int number)
{
	(void)number;
}

static void *check_worker(void *unused)
{
	sigset_t additional;
	char path[128];

	(void)unused;
	assert(sigemptyset(&additional) == 0);
	assert(sigaddset(&additional, SIGUSR2) == 0);
	assert(pthread_sigmask(SIG_BLOCK, &additional, NULL) == 0);
	snprintf(path, sizeof(path), "/proc/self/task/%ld/status", syscall(SYS_gettid));
	check_masks(path);
	assert((read_mask(path, "SigBlk") & signal_bit(SIGUSR2)) != 0);
	assert((read_mask("/proc/self/status", "SigBlk") & signal_bit(SIGUSR2)) == 0);
	return NULL;
}

int main(int argc, char **argv)
{
	sigset_t blocked;
	struct sigaction action = {0};
	pthread_t worker;
	char path[128];
	int status;
	pid_t child;

	alarm(10);
	if (argc == 2 && strcmp(argv[1], "--exec") == 0) {
		check_masks("/proc/self/status");
		assert((read_mask("/proc/self/status", "SigIgn") & signal_bit(SIGUSR2)) != 0);
		assert((read_mask("/proc/self/status", "SigCgt") & signal_bit(SIGRTMAX)) == 0);
		return 0;
	}
	assert(sigemptyset(&blocked) == 0);
	assert(sigaddset(&blocked, SIGUSR1) == 0);
	assert(sigaddset(&blocked, SIGKILL) == 0);
	assert(sigaddset(&blocked, SIGSTOP) == 0);
	assert(pthread_sigmask(SIG_SETMASK, &blocked, NULL) == 0);
	assert(sigemptyset(&action.sa_mask) == 0);
	action.sa_handler = SIG_IGN;
	assert(sigaction(SIGUSR2, &action, NULL) == 0);
	action.sa_handler = handler;
	assert(sigaction(SIGRTMAX, &action, NULL) == 0);
	check_masks("/proc/self/status");
	snprintf(path, sizeof(path), "/proc/self/task/%ld/status", syscall(SYS_gettid));
	check_masks(path);
	assert((read_mask(path, "SigBlk") & (signal_bit(SIGKILL) | signal_bit(SIGSTOP))) == 0);
	assert((read_mask(path, "SigCgt") & signal_bit(SIGRTMAX)) != 0);
	assert(pthread_create(&worker, NULL, check_worker, NULL) == 0);
	assert(pthread_join(worker, NULL) == 0);
	check_masks("/proc/self/status");
	child = fork();
	assert(child >= 0);
	if (child == 0) {
		execl("/proc/self/exe", argv[0], "--exec", NULL);
		_exit(127);
	}
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	puts("proc signal masks: per-thread blocking, shared dispositions, realtime bits and exec inheritance passed");
	return 0;
}
