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
	char dir[] = "exchange-XXXXXX";
	struct stat a, b;
	CHECK(mkdtemp(dir));
	CHECK(chdir(dir) == 0);
	CHECK(mkdir("p", 0700) == 0 && mkdir("q", 0700) == 0);
	CHECK(mkdir("p/d", 0700) == 0);
	int fd = open("q/f", O_CREAT | O_WRONLY, 0600);
	CHECK(fd >= 0 && close(fd) == 0);
	CHECK(renameat2(AT_FDCWD, "p/d", AT_FDCWD, "q/f", RENAME_EXCHANGE) == 0);
	CHECK(stat("p/d", &a) == 0 && S_ISREG(a.st_mode));
	CHECK(stat("q/f", &a) == 0 && S_ISDIR(a.st_mode));
	CHECK(stat("q/f/..", &a) == 0 && stat("q", &b) == 0 && a.st_ino == b.st_ino && a.st_dev == b.st_dev);
	CHECK(renameat2(AT_FDCWD, "p/d", AT_FDCWD, "missing", RENAME_EXCHANGE) == -1 && errno == ENOENT);
	CHECK(renameat2(AT_FDCWD, "p/d", AT_FDCWD, "q/f", RENAME_EXCHANGE | RENAME_NOREPLACE) == -1 && errno == EINVAL);
	CHECK(unlink("p/d") == 0 && rmdir("q/f") == 0 && rmdir("p") == 0 && rmdir("q") == 0);
	CHECK(chdir("..") == 0 && rmdir(dir) == 0);
	puts("exchange PASS");
	return 0;
}
