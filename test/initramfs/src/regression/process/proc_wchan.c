// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static ssize_t read_wchan(pid_t pid, char *buf, size_t capacity)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/wchan", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	ssize_t n = read(fd, buf, capacity - 1);
	assert(close(fd) == 0);
	if (n >= 0) {
		buf[n] = '\0';
	}
	return n;
}

int main(void)
{
	char buf[256];

	assert(read_wchan(getpid(), buf, sizeof(buf)) > 0);
	assert(strcmp(buf, "0") == 0);

	int hold[2];
	assert(pipe(hold) == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		char byte;
		close(hold[1]);
		_exit(read(hold[0], &byte, 1) == 0 ? 0 : 1);
	}
	close(hold[0]);

	int blocked = 0;
	for (int attempt = 0; attempt < 500 && !blocked; attempt++) {
		ssize_t n = read_wchan(child, buf, sizeof(buf));
		assert(n > 0);
		blocked = strcmp(buf, "0") != 0;
		if (!blocked) {
			nanosleep(&(struct timespec){ .tv_nsec = 10000000 }, NULL);
		}
	}
	assert(blocked);

	char status[4096];
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/status", child);
	int fd = open(path, O_RDONLY);
	assert(fd >= 0);
	ssize_t n = read(fd, status, sizeof(status) - 1);
	assert(n > 0);
	status[n] = '\0';
	assert(close(fd) == 0);
	assert(strstr(status, "State:\tS") != NULL);

	close(hold[1]);
	int wstatus;
	assert(waitpid(child, &wstatus, 0) == child);
	assert(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0);

	printf("proc_wchan: ok\n");
	return 0;
}
