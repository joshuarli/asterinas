// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static void assert_no_controlling_terminal(void)
{
	int fd = open("/dev/tty", O_RDWR | O_NOCTTY);
	assert(fd == -1);
	assert(errno == ENXIO);
}

static void test_controlling_terminal(void)
{
	assert(setsid() == getpid());
	assert_no_controlling_terminal();

	int master = posix_openpt(O_RDWR | O_NOCTTY);
	assert(master >= 0);
	assert(grantpt(master) == 0);
	assert(unlockpt(master) == 0);
	char *path = ptsname(master);
	assert(path != NULL);
	int replica = open(path, O_RDWR | O_NOCTTY);
	assert(replica >= 0);
	assert_no_controlling_terminal();

	assert(ioctl(replica, TIOCSCTTY, 0) == 0);
	int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
	assert(tty >= 0);
	assert(isatty(tty));
	assert(tcgetsid(tty) == getsid(0));
	assert(tcgetpgrp(tty) == getpgrp());
	assert(close(tty) == 0);

	assert(signal(SIGHUP, SIG_IGN) != SIG_ERR);
	assert(ioctl(replica, TIOCNOTTY) == 0);
	assert_no_controlling_terminal();
	assert(close(replica) == 0);
	assert(close(master) == 0);
}

int main(void)
{
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		test_controlling_terminal();
		_exit(0);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);
	return 0;
}
