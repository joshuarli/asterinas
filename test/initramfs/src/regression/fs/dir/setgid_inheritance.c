// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <assert.h>
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
	umask(0027);
	fd = open("file", O_CREAT | O_EXCL | O_RDWR, 0666);
	assert(fd >= 0 && close(fd) == 0);
	check_metadata("file", group, 0640);
	fd = open("requested-setgid", O_CREAT | O_EXCL | O_RDWR, 02777);
	assert(fd >= 0 && close(fd) == 0);
	check_metadata("requested-setgid", group,
		may_keep_setgid ? 02750 : 0750);
	fd = open("requested-setgid-noexec", O_CREAT | O_EXCL | O_RDWR, 02666);
	assert(fd >= 0 && close(fd) == 0);
	check_metadata("requested-setgid-noexec", group, 02640);
	assert(mkdir("directory", 0777) == 0);
	check_metadata("directory", group, directory_mode);
	assert(mkdir("directory/nested", 0777) == 0);
	check_metadata("directory/nested", group, directory_mode);
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
