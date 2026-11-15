// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { perror(#x); return 1; } } while (0)
int main(void)
{
	char dir[] = "socket-open-XXXXXX";
	struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = "sock" };
	CHECK(mkdtemp(dir));
	CHECK(chdir(dir) == 0);
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(fd >= 0 && bind(fd, (void *)&addr, sizeof(addr)) == 0);
	CHECK(open("sock", O_RDONLY) == -1 && errno == ENXIO);
	int pathfd = open("sock", O_PATH);
	CHECK(pathfd >= 0 && close(pathfd) == 0);
	CHECK(close(fd) == 0 && unlink("sock") == 0 && chdir("..") == 0 && rmdir(dir) == 0);
	puts("socket PASS");
	return 0;
}
