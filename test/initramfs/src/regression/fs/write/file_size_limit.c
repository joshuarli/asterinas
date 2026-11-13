// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t limit_signals;

static void caught_limit(int signal)
{
	(void)signal;
	limit_signals++;
}

static ssize_t write_case(int file, int route, const char *data, size_t length, off_t offset)
{
	return route == 1 ? pwrite(file, data, length, offset) : write(file, data, length);
}

int main(void)
{
	char path[4096];
	const char *base = getenv("TMPDIR");
	if (!base)
		base = "/tmp";
	if (snprintf(path, sizeof(path), "%s/file-size-limit-XXXXXX", base) >= (int)sizeof(path))
		return 1;
	int file = mkstemp(path);
	if (file < 0)
		return 1;
	struct rlimit original;
	struct sigaction action = {.sa_handler = caught_limit};
	if (getrlimit(RLIMIT_FSIZE, &original) || sigemptyset(&action.sa_mask) ||
	    sigaction(SIGXFSZ, &action, NULL))
		return 1;
	struct rlimit limited = {.rlim_cur = 512, .rlim_max = original.rlim_max};
	char data[1024];
	memset(data, 'x', sizeof(data));
	int failed = 0;
	for (int route = 0; route < 3; route++) {
		if (setrlimit(RLIMIT_FSIZE, &original) || ftruncate(file, 0) || lseek(file, 0, SEEK_SET) != 0 ||
		    fcntl(file, F_SETFL, route == 2 ? O_APPEND : 0) || setrlimit(RLIMIT_FSIZE, &limited))
			return 1;
		limit_signals = 0;
		ssize_t first = write_case(file, route, data, 300, 0);
		ssize_t partial = write_case(file, route, data, sizeof(data), 300);
		struct stat metadata;
		if (first != 300 || partial != 212 || limit_signals || fstat(file, &metadata) || metadata.st_size != 512) {
			fprintf(stderr, "file limit route %d: first=%zd partial=%zd signals=%d\n",
				route, first, partial, (int)limit_signals);
			failed = 1;
		}
		if (route == 2 && lseek(file, 0, SEEK_SET) != 0)
			return 1;
		errno = 0;
		ssize_t rejected = write_case(file, route, data, 1, 512);
		int error = errno;
		if (rejected != -1 || error != EFBIG || limit_signals != 1 ||
		    lseek(file, 0, SEEK_CUR) != (route == 0 ? 512 : 0)) {
			fprintf(stderr, "file limit route %d: rejected=%zd errno=%d signals=%d\n",
				route, rejected, error, (int)limit_signals);
			failed = 1;
		}
		limit_signals = 0;
		ssize_t empty = write_case(file, route, data, 0, 512);
		if (empty != 0 || limit_signals) {
			fprintf(stderr, "file limit route %d: empty=%zd errno=%d signals=%d\n",
				route, empty, errno, (int)limit_signals);
			failed = 1;
		}
	}
	int pipe_fds[2];
	struct rlimit zero = {.rlim_cur = 0, .rlim_max = original.rlim_max};
	if (pipe(pipe_fds) || setrlimit(RLIMIT_FSIZE, &zero))
		return 1;
	char byte;
	ssize_t sent = write(pipe_fds[1], "p", 1);
	ssize_t received = sent == 1 ? read(pipe_fds[0], &byte, 1) : -1;
	if (sent != 1 || received != 1 || byte != 'p' || close(pipe_fds[0]) || close(pipe_fds[1])) {
		fprintf(stderr, "file limit pipe: sent=%zd received=%zd errno=%d\n", sent, received, errno);
		failed = 1;
	}
	if (setrlimit(RLIMIT_FSIZE, &original) || ftruncate(file, 0) || lseek(file, 0, SEEK_SET) != 0 ||
	    fcntl(file, F_SETFL, 0)) {
		perror("reset append descriptor");
		return 1;
	}
	pid_t child = fork();
	if (child == 0) {
		struct rlimit one = {.rlim_cur = 1, .rlim_max = original.rlim_max};
		if (signal(SIGXFSZ, SIG_DFL) == SIG_ERR || setrlimit(RLIMIT_FSIZE, &one) ||
		    write(file, "ab", 2) != 1)
			_exit(2);
		(void)write(file, "c", 1);
		_exit(3);
	}
	int status = -1;
	pid_t waited = child < 0 ? -1 : waitpid(child, &status, 0);
	if (child < 0 || waited != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGXFSZ) {
		fprintf(stderr, "file limit default signal: child=%d waited=%d status=%#x\n", child, waited, status);
		failed = 1;
	}
	if (close(file) || unlink(path))
		return 1;
	if (!failed)
		puts("file size limit: partial writes, EFBIG, SIGXFSZ, append positions and pipes passed");
	return failed;
}
