// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
	const char *base = getenv("TMPDIR");
	if (!base)
		base = "/tmp";
	char path[PATH_MAX], file_path[PATH_MAX];
	if (snprintf(path, sizeof(path), "%s/readlink-nonlink-XXXXXX", base) >= (int)sizeof(path) ||
	    !mkdtemp(path) || snprintf(file_path, sizeof(file_path), "%s/file", path) >= (int)sizeof(file_path))
		return 1;
	int directory = open(path, O_RDONLY | O_DIRECTORY);
	int file = openat(directory, "file", O_CREAT | O_EXCL | O_RDWR, 0600);
	if (directory < 0 || file < 0 || symlinkat("file", directory, "link"))
		return 1;
	const char *nonlinks[] = {"/", "/proc", "/proc/self/fd", "/dev", path, file_path};
	char target[PATH_MAX];
	int failed = 0;
	for (size_t index = 0; index < sizeof(nonlinks) / sizeof(nonlinks[0]); index++) {
		errno = 0;
		ssize_t result = readlink(nonlinks[index], target, sizeof(target));
		if (result != -1 || errno != EINVAL) {
			fprintf(stderr, "readlink %s: result=%zd errno=%d; expected EINVAL\n",
				nonlinks[index], result, errno);
			failed = 1;
		}
	}
	errno = 0;
	if (readlinkat(directory, "file", target, sizeof(target)) != -1 || errno != EINVAL)
		failed = 1;
	ssize_t length = readlinkat(directory, "link", target, sizeof(target));
	if (length != 4 || memcmp(target, "file", 4))
		failed = 1;
	char descriptor[64], resolved[PATH_MAX];
	if (snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", file) >= (int)sizeof(descriptor))
		return 1;
	length = readlink(descriptor, target, sizeof(target));
	if (length != (ssize_t)strlen(file_path) || memcmp(target, file_path, strlen(file_path)))
		failed = 1;
	if (!realpath(descriptor, resolved)) {
		perror("realpath descriptor");
		failed = 1;
	} else if (strcmp(resolved, file_path)) {
		fprintf(stderr, "realpath descriptor: %s; expected %s\n", resolved, file_path);
		failed = 1;
	}
	if (close(file) || unlinkat(directory, "link", 0) || unlinkat(directory, "file", 0) ||
	    close(directory) || rmdir(path))
		return 1;
	if (!failed)
		puts("readlink: nonlinks reject with EINVAL; ordinary and descriptor symlinks resolve");
	return failed;
}
