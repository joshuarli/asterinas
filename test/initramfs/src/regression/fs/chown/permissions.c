// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct ownership_case {
	uid_t owner;
	uid_t requested_owner;
	gid_t requested_group;
	int expected_errno;
};

static int change_owner(int interface, int directory, int file,
			uid_t owner, gid_t group)
{
	switch (interface) {
	case 0: return chown("file", owner, group);
	case 1: return lchown("file", owner, group);
	case 2: return fchown(file, owner, group);
	case 3: return fchownat(directory, "file", owner, group, 0);
	case 4: return fchownat(file, "", owner, group, AT_EMPTY_PATH);
	case 5: return fchownat(directory, "link", owner, group, AT_SYMLINK_NOFOLLOW);
	default: abort();
	}
}

int main(void)
{
	const char *base = getenv("TMPDIR");
	if (!base)
		base = "/tmp";
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/chown-permissions-XXXXXX", base) >= (int)sizeof(path) ||
	    !mkdtemp(path) || chmod(path, 0755) || chdir(path)) {
		perror("ownership fixture");
		return 1;
	}
	int directory = open(".", O_RDONLY | O_DIRECTORY);
	int file = open("file", O_CREAT | O_EXCL | O_RDWR, 0600);
	if (directory < 0 || file < 0 || symlink("file", "link"))
		return 1;
	const struct ownership_case cases[] = {
		{1000, 0, (gid_t)-1, EPERM},
		{1000, (uid_t)-1, 0, EPERM},
		{1000, 1000, 0, EPERM},
		{1000, 1000, 1000, 0},
		{1000, (uid_t)-1, 1001, 0},
		{1000, (uid_t)-1, 1002, EPERM},
		{1002, 1002, (gid_t)-1, EPERM},
		{1002, (uid_t)-1, 1000, EPERM},
		{1002, (uid_t)-1, (gid_t)-1, 0},
	};
	int failed = 0;
	for (int interface = 0; interface < 6; interface++) {
		for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
			const struct ownership_case *test = &cases[index];
			if (fchown(file, test->owner, 1000) || lchown("link", test->owner, 1000))
				return 1;
			pid_t child = fork();
			if (child == 0) {
				gid_t groups[] = {1001};
				if (setgroups(1, groups) || setgid(1000) || setuid(1000))
					_exit(2);
				errno = 0;
				int result = change_owner(interface, directory, file,
							  test->requested_owner, test->requested_group);
				int error = errno;
				if ((test->expected_errno == 0 && result != 0) ||
				    (test->expected_errno != 0 && (result != -1 || error != test->expected_errno))) {
					dprintf(2, "chown interface %d case %zu: result=%d errno=%d expected=%d\n",
						interface, index, result, error, test->expected_errno);
					_exit(1);
				}
				_exit(0);
			}
			int status;
			if (child < 0 || waitpid(child, &status, 0) != child ||
			    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
				failed = 1;
			struct stat metadata;
			if (fstatat(directory, interface == 5 ? "link" : "file", &metadata,
				    interface == 5 ? AT_SYMLINK_NOFOLLOW : 0))
				return 1;
			uid_t expected_owner = test->owner;
			gid_t expected_group = 1000;
			if (test->expected_errno == 0) {
				if (test->requested_owner != (uid_t)-1)
					expected_owner = test->requested_owner;
				if (test->requested_group != (gid_t)-1)
					expected_group = test->requested_group;
			}
			if (metadata.st_uid != expected_owner || metadata.st_gid != expected_group) {
				fprintf(stderr, "chown interface %d case %zu: ownership=%u:%u expected=%u:%u\n",
					interface, index, metadata.st_uid, metadata.st_gid,
					expected_owner, expected_group);
				failed = 1;
			}
		}
	}
	errno = 0;
	if (fchown(-1, (uid_t)-1, (gid_t)-1) != -1 || errno != EBADF)
		failed = 1;
	errno = 0;
	if (chown("missing", (uid_t)-1, (gid_t)-1) != -1 || errno != ENOENT)
		failed = 1;
	if (close(file) || close(directory) || unlink("link") || unlink("file") ||
	    chdir("/") || rmdir(path))
		return 1;
	if (!failed)
		puts("chown: 54 credential cases and invalid no-op targets passed");
	return failed;
}
