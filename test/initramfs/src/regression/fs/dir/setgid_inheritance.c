// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void check_metadata(const char *path, gid_t group, mode_t expected)
{
	struct stat metadata;
	assert(lstat(path, &metadata) == 0);
	if (metadata.st_uid != getuid() || metadata.st_gid != group ||
	    (metadata.st_mode & 07777) != expected)
		fprintf(stderr, "%s: uid=%u gid=%u mode=%o, expected uid=%u gid=%u mode=%o\n",
			path, metadata.st_uid, metadata.st_gid, metadata.st_mode & 07777,
			getuid(), group, expected);
	assert(metadata.st_uid == getuid());
	assert(metadata.st_gid == group);
	assert((metadata.st_mode & 07777) == expected);
}

static void create_children(gid_t group, mode_t directory_mode, int tmpfile, int root_has_fsetid)
{
	struct sockaddr_un address = {.sun_family = AF_UNIX, .sun_path = "socket"};
	int fd;
	gid_t supplementary;
	int group_count = getgroups(0, NULL);
	assert(group_count == 0 || group_count == 1);
	if (group_count == 1)
		assert(getgroups(1, &supplementary) == 1);
	int may_keep_setgid = (getuid() == 0 && root_has_fsetid) || group == getgid() ||
		(group_count == 1 && supplementary == group);
	for (int group_only = 0; group_only < 2; group_only++) {
		const char *name = group_only ? "group-readable" : "other-readable";
		int belongs = getgid() == 1001 || (group_count == 1 && supplementary == 1001);
		errno = 0;
		fd = open(name, O_RDONLY);
		if (getuid() == 0 || (group_only ? belongs : !belongs)) {
			assert(fd >= 0 && close(fd) == 0);
		} else {
			assert(fd == -1 && errno == EACCES);
		}
		assert(unlink(name) == 0);
	}
	umask(0027);
	fd = open("file", O_CREAT | O_EXCL | O_RDWR, 0666);
	assert(fd >= 0 && close(fd) == 0);
	check_metadata("file", group, 0640);
	fd = open("file", O_PATH);
	assert(fd >= 0);
	errno = 0;
	assert(fchmod(fd, 0600) == -1 && errno == EBADF);
	assert(close(fd) == 0);
	check_metadata("file", group, 0640);
	fd = open("requested-setgid", O_CREAT | O_EXCL | O_RDWR, 02777);
	assert(fd >= 0 && close(fd) == 0);
	check_metadata("requested-setgid", group,
		may_keep_setgid ? 02750 : 0750);
	fd = open("requested-setgid-noexec", O_CREAT | O_EXCL | O_RDWR, 02666);
	assert(fd >= 0 && close(fd) == 0);
	check_metadata("requested-setgid-noexec", group, 02640);
	assert(chmod("requested-setgid", 02777) == 0);
	check_metadata("requested-setgid", group, may_keep_setgid ? 02777 : 0777);
	fd = open("requested-setgid", O_RDONLY);
	assert(fd >= 0 && fchmod(fd, 02666) == 0 && close(fd) == 0);
	check_metadata("requested-setgid", group, may_keep_setgid ? 02666 : 0666);
	assert(fchmodat(AT_FDCWD, "requested-setgid-noexec", 02777, 0) == 0);
	check_metadata("requested-setgid-noexec", group, may_keep_setgid ? 02777 : 0777);
	assert(mkdir("directory", 0777) == 0);
	check_metadata("directory", group, directory_mode);
	assert(mkdir("directory/nested", 0777) == 0);
	check_metadata("directory/nested", group, directory_mode);
	assert(chmod("directory", 02777) == 0);
	check_metadata("directory", group, may_keep_setgid ? 02777 : 0777);
	assert(symlink("target", "link") == 0);
	check_metadata("link", group, 0777);
	assert(mkfifo("fifo", 0666) == 0);
	check_metadata("fifo", group, 0640);
	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	assert(fd >= 0);
	assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	check_metadata("socket", group, 0750);
	assert(close(fd) == 0);
	if (getuid() == 0) {
		assert(mknod("char", S_IFCHR | 0666, makedev(1, 3)) == 0);
		assert(mknod("block", S_IFBLK | 0666, makedev(7, 0)) == 0);
		check_metadata("char", group, 0640);
		check_metadata("block", group, 0640);
		assert(unlink("char") == 0 && unlink("block") == 0);
	}
	if (tmpfile) {
		struct stat metadata;
		fd = open(".", O_TMPFILE | O_RDWR, 0666);
		assert(fd >= 0 && fstat(fd, &metadata) == 0);
		assert(metadata.st_uid == getuid() && metadata.st_gid == group);
		assert((metadata.st_mode & 07777) == 0640 && metadata.st_nlink == 0);
		assert(close(fd) == 0);
	}
	fd = open("foreign", O_RDONLY);
	assert(fd >= 0);
	for (int route = 0; route < 3; route++) {
		errno = 0;
		int changed = route == 0 ? chmod("foreign", 0600) :
			route == 1 ? fchmod(fd, 0600) : fchmodat(AT_FDCWD, "foreign", 0600, 0);
		if (getuid() != 0)
			assert(changed == -1 && errno == EPERM);
		else
			assert(changed == 0 && chmod("foreign", 0666) == 0);
		struct stat metadata;
		assert(fstat(fd, &metadata) == 0);
		assert(metadata.st_uid == 2000 && (metadata.st_mode & 07777) == 0666);
	}
	assert(close(fd) == 0 && unlink("foreign") == 0);
	assert(unlink("file") == 0 && unlink("fifo") == 0);
	assert(unlink("requested-setgid") == 0);
	assert(unlink("requested-setgid-noexec") == 0);
	assert(unlink("link") == 0 && unlink("socket") == 0);
	assert(rmdir("directory/nested") == 0 && rmdir("directory") == 0);
}

int main(int argc, char **argv)
{
	const char *temporary = getenv("TMPDIR");
	char root[PATH_MAX], path[PATH_MAX];
	int status;
	int tmpfile = argc == 2 && strcmp(argv[1], "--tmpfile") == 0;

	assert(getuid() == 0);
	if (temporary == NULL || *temporary == '\0')
		temporary = "/tmp";
	assert(snprintf(root, sizeof(root), "%s/setgid-inherit-XXXXXX", temporary) < (int)sizeof(root));
	assert(mkdtemp(root) != NULL && chmod(root, 0755) == 0);
	for (int unprivileged = 0; unprivileged < 4; unprivileged++) {
		for (int inherited = 0; inherited < 2; inherited++) {
			assert(snprintf(path, sizeof(path), "%s/%d-%d", root, unprivileged, inherited) < (int)sizeof(path));
			assert(mkdir(path, 0700) == 0);
			assert(chown(path, 1000, 1001) == 0);
			assert(chmod(path, inherited ? 02777 : 0777) == 0);
			int directory = open(path, O_RDONLY | O_DIRECTORY);
			assert(directory >= 0);
			int foreign = openat(directory, "foreign", O_CREAT | O_EXCL | O_RDWR, 0666);
			assert(foreign >= 0 && fchmod(foreign, 0666) == 0);
			assert(fchown(foreign, 2000, 1001) == 0);
			assert(close(foreign) == 0 && close(directory) == 0);
			directory = open(path, O_RDONLY | O_DIRECTORY);
			assert(directory >= 0);
			for (int group_only = 0; group_only < 2; group_only++) {
				const char *name = group_only ? "group-readable" : "other-readable";
				int file = openat(directory, name, O_CREAT | O_EXCL | O_RDWR, 0600);
				assert(file >= 0 && fchown(file, 2000, 1001) == 0);
				assert(fchmod(file, group_only ? 0040 : 0004) == 0 && close(file) == 0);
			}
			assert(close(directory) == 0);
			pid_t child = fork();
			assert(child >= 0);
			if (child == 0) {
				alarm(10);
				assert(setgroups(0, NULL) == 0);
				if (unprivileged == 2) {
					gid_t supplementary = 1001;
					assert(setgroups(1, &supplementary) == 0);
				}
				if (unprivileged == 1 || unprivileged == 2)
					assert(setgid(1000) == 0 && setuid(1000) == 0);
				if (unprivileged == 3) {
					struct __user_cap_header_struct header = {
						.version = _LINUX_CAPABILITY_VERSION_3,
					};
					struct __user_cap_data_struct capabilities[2];
					assert(syscall(SYS_capget, &header, capabilities) == 0);
					capabilities[0].effective &= ~(1U << CAP_FSETID);
					assert(syscall(SYS_capset, &header, capabilities) == 0);
					assert(syscall(SYS_capget, &header, capabilities) == 0);
					assert((capabilities[0].effective & (1U << CAP_FSETID)) == 0);
				}
				assert(chdir(path) == 0);
				create_children(inherited ? 1001 : getgid(), inherited ? 02750 : 0750, tmpfile, unprivileged != 3);
				_exit(0);
			}
			assert(waitpid(child, &status, 0) == child);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			assert(rmdir(path) == 0);
		}
	}
	assert(rmdir(root) == 0);
	puts("setgid inheritance: root and unprivileged children inherit group, directories retain setgid, ordinary parents use caller group");
	return 0;
}
