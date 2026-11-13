// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int send_byte(int fd, char value)
{
	return write(fd, &value, 1) == 1 ? 0 : -1;
}

static int receive_byte(int fd, char expected)
{
	char value;

	return read(fd, &value, 1) == 1 && value == expected ? 0 : -1;
}

static int helper(int ready, int control, int separate_session)
{
	if (separate_session) {
		if (setsid() < 0)
			return 1;
	} else if (setpgid(0, 0) < 0) {
		return 1;
	}
	if (send_byte(ready, 'E') < 0 || receive_byte(control, 'X') < 0)
		return 1;
	return 0;
}

static int run_case(int separate_session)
{
	int ready[2], control[2], status, result = 1;
	pid_t child, parent_group = getpgrp();
	const char *stage = "pipe or fork";

	if (pipe(ready) < 0)
		return 1;
	if (pipe(control) < 0) {
		close(ready[0]);
		close(ready[1]);
		return 1;
	}
	child = fork();
	if (child == 0) {
		char ready_arg[32], control_arg[32];
		char *const missing_argv[] = { "missing", NULL };
		char *const missing_env[] = { NULL };

		close(ready[0]);
		close(control[1]);
		execve("/this-path-must-not-exist-setpgid-test", missing_argv, missing_env);
		if (errno != ENOENT || send_byte(ready[1], 'F') < 0 ||
		    receive_byte(control[0], 'G') < 0)
			_exit(1);
		snprintf(ready_arg, sizeof(ready_arg), "%d", ready[1]);
		snprintf(control_arg, sizeof(control_arg), "%d", control[0]);
		execl("/proc/self/exe", "setpgid_exec", separate_session ? "session" : "group",
		      ready_arg, control_arg, (char *)NULL);
		_exit(1);
	}
	close(ready[1]);
	close(control[0]);
	if (child < 0)
		goto out;
	stage = "failed exec notification";
	if (receive_byte(ready[0], 'F') < 0)
		goto reap;
	stage = "move pre-exec child to own group";
	if (setpgid(child, child) < 0 || getpgid(child) != child)
		goto reap;
	stage = "move pre-exec child back";
	if (setpgid(child, parent_group) < 0 || getpgid(child) != parent_group)
		goto reap;
	stage = "exec helper notification";
	if (send_byte(control[1], 'G') < 0 || receive_byte(ready[0], 'E') < 0)
		goto reap;
	if (separate_session) {
		stage = "different session precedence";
		errno = 0;
		if (setpgid(child, child) != -1 || errno != EPERM || getpgid(child) != child)
			goto reap;
	} else {
		stage = "post-exec idempotent setpgid";
		errno = 0;
		if (setpgid(child, child) != -1 || errno != EACCES || getpgid(child) != child)
			goto reap;
		stage = "post-exec move to parent group";
		errno = 0;
		if (setpgid(child, parent_group) != -1 || errno != EACCES ||
		    getpgid(child) != child)
			goto reap;
	}
	stage = "release helper";
	if (send_byte(control[1], 'X') < 0)
		goto reap;
	result = 0;
reap:
	close(control[1]);
	control[1] = -1;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		if (!result)
			stage = "helper exit";
		result = 1;
	}
out:
	close(ready[0]);
	if (control[1] >= 0)
		close(control[1]);
	if (result)
		fprintf(stderr, "setpgid exec %s: %s failed (errno=%d)\n",
			separate_session ? "session" : "group", stage, errno);
	return result;
}

int main(int argc, char **argv)
{
	pid_t wrapper;
	int status;

	if (argc == 4 && (!strcmp(argv[1], "group") || !strcmp(argv[1], "session")))
		return helper(atoi(argv[2]), atoi(argv[3]), !strcmp(argv[1], "session"));
	if (argc != 1)
		return 1;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return 1;
	wrapper = fork();
	if (wrapper < 0)
		return 1;
	if (wrapper == 0) {
		if (setsid() < 0)
			_exit(1);
		_exit(run_case(0) || run_case(1));
	}
	if (waitpid(wrapper, &status, 0) != wrapper || !WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}
