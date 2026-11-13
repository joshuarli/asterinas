// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define CHILD_MARKER "EXECVE_ARGS_CHILD"
#define HUGE_COUNT 300000
#define MODEST_COUNT 10000

FN_SETUP(child)
{
	if (getenv(CHILD_MARKER))
		_exit(0);
}
END_SETUP()

static char **filled_array(size_t count, const char *first)
{
	char **array = calloc(count + 2, sizeof(char *));

	array[0] = (char *)first;
	for (size_t i = 1; i <= count; i++)
		array[i] = "a";
	return array;
}

// Returns the errno of a failed execve, or 0 if the new program ran and exited successfully.
static int exec_self(char **argv, char **envp)
{
	int fds[2];
	int err = 0;
	int status;
	pid_t pid;

	CHECK(pipe2(fds, O_CLOEXEC));
	pid = CHECK(fork());
	if (pid == 0) {
		execve("/proc/self/exe", argv, envp);
		err = errno;
		if (write(fds[1], &err, sizeof(err)) != sizeof(err))
			_exit(2);
		_exit(1);
	}
	close(fds[1]);
	if (read(fds[0], &err, sizeof(err)) != sizeof(err))
		err = 0;
	close(fds[0]);
	CHECK(waitpid(pid, &status, 0));
	if (err == 0 && !(WIFEXITED(status) && WEXITSTATUS(status) == 0))
		err = -1;
	return err;
}

FN_TEST(huge_argv_is_rejected)
{
	char **argv = filled_array(HUGE_COUNT, "self");
	char *envp[] = { CHILD_MARKER "=1", NULL };

	TEST_RES(exec_self(argv, envp), _ret == E2BIG);
	free(argv);
}
END_TEST()

FN_TEST(huge_envp_is_rejected)
{
	char *argv[] = { "self", NULL };
	char **envp = filled_array(HUGE_COUNT, CHILD_MARKER "=1");

	TEST_RES(exec_self(argv, envp), _ret == E2BIG);
	free(envp);
}
END_TEST()

FN_TEST(modest_argv_is_accepted)
{
	char **argv = filled_array(MODEST_COUNT, "self");
	char *envp[] = { CHILD_MARKER "=1", NULL };

	TEST_RES(exec_self(argv, envp), _ret == 0);
	free(argv);
}
END_TEST()
