// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct root_case {
	const char *options;
	mode_t mode;
	uid_t uid;
	gid_t gid;
};

static int check_root(const char *path, const struct root_case *test)
{
	struct stat metadata;
	if (mount("tmpfs", path, "tmpfs", 0, test->options) != 0) {
		perror("mount tmpfs");
		return 1;
	}
	int failed = stat(path, &metadata) != 0;
	if (!failed && ((metadata.st_mode & 07777) != test->mode ||
			 metadata.st_uid != test->uid || metadata.st_gid != test->gid)) {
		fprintf(stderr, "tmpfs %s: mode=%04o uid=%u gid=%u; expected %04o %u %u\n",
			test->options ? test->options : "defaults",
			metadata.st_mode & 07777, metadata.st_uid, metadata.st_gid,
			test->mode, test->uid, test->gid);
		failed = 1;
	}
	if (!failed && test->mode == 01777) {
		pid_t child = fork();
		if (child == 0) {
			if (setgroups(0, NULL) || setgid(1000) || setuid(1000) || chdir(path))
				_exit(1);
			int fd = open("owned", O_CREAT | O_EXCL | O_RDWR, 0600);
			if (fd < 0)
				_exit(2);
			struct stat created;
			int bad = fstat(fd, &created) || created.st_uid != 1000 ||
				  created.st_gid != 1000;
			bad |= close(fd) != 0;
			bad |= unlink("owned") != 0;
			_exit(bad ? 3 : 0);
		}
		int status;
		failed = child < 0 || waitpid(child, &status, 0) != child ||
			 !WIFEXITED(status) || WEXITSTATUS(status) != 0;
	}
	if (umount(path) != 0) {
		perror("umount tmpfs");
		return 1;
	}
	return failed;
}

int main(void)
{
	const char *base = getenv("TMPDIR");
	if (!base)
		base = "/tmp";
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/tmpfs-root-options-XXXXXX", base) >= (int)sizeof(path) ||
	    !mkdtemp(path)) {
		perror("tmpfs fixture directory");
		return 1;
	}
	if (chmod(path, 0755) != 0)
		return 1;
	const struct root_case cases[] = {
		{ NULL, 01777, 0, 0 },
		{ "mode=1777", 01777, 0, 0 },
		{ "mode=0700,uid=1000,gid=1000", 0700, 1000, 1000 },
		{ "mode=0,uid=1234,gid=5678", 0, 1234, 5678 },
		{ "mode=700,mode=1777", 01777, 0, 0 },
		{ "mode=7777", 07777, 0, 0 },
		{ "mode=100000", 0, 0, 0 },
		{ "mode=+1777,uid=+0,gid=+0", 01777, 0, 0 },
		{ "mode=0700,uid=0x10,gid=01000", 0700, 16, 512 },
	};
	int failed = 0;
	for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++)
		failed |= check_root(path, &cases[index]);
	const char *invalid[] = { "mode", "mode=", "mode=08", "mode=-1",
		"uid=-1", "gid=4294967295", "uid=4294967296", "uid=++1", "gid=0x+10" };
	for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
		errno = 0;
		if (mount("tmpfs", path, "tmpfs", 0, invalid[index]) == 0) {
			fprintf(stderr, "tmpfs accepted invalid options: %s\n", invalid[index]);
			failed = 1;
			if (umount(path) != 0)
				return 1;
		} else if (errno != EINVAL) {
			perror(invalid[index]);
			failed = 1;
		}
	}
	if (rmdir(path) != 0)
		return 1;
	if (!failed)
		puts("tmpfs root options and unprivileged creation passed");
	return failed;
}
