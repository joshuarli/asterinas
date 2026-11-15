// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { perror(#x); return 1; } } while (0)
int main(void)
{
	char dir[] = "link-precedence-XXXXXX";
	CHECK(mkdtemp(dir));
	CHECK(chdir(dir) == 0 && mkdir("d", 0700) == 0);
	int fd = open("f", O_CREAT | O_WRONLY, 0600);
	CHECK(fd >= 0 && close(fd) == 0);
	CHECK(link("d", "f") == -1 && errno == EEXIST);
	CHECK(link("d", "d") == -1 && errno == EEXIST);
	CHECK(link("d", "new") == -1 && errno == EPERM);
	CHECK(unlink("f") == 0 && rmdir("d") == 0 && chdir("..") == 0 && rmdir(dir) == 0);
	puts("link PASS");
	return 0;
}
