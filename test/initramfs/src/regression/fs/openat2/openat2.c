// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#define TEST_DIR "/ext2/openat2_test"
#define OUTSIDE_DIR "/ext2/openat2_outside"
#define TEST_FILE TEST_DIR "/inside/secret"
#define TEST_LINK TEST_DIR "/inside_link"
#define ESCAPE_LINK TEST_DIR "/escape_link"

static struct open_how beneath_how = {
	.flags = O_RDONLY,
	.resolve = RESOLVE_BENEATH,
};

static int openat2_with_size(int dirfd, const char *path,
			     const struct open_how *how, size_t size)
{
	return syscall(SYS_openat2, dirfd, path, how, size);
}

static int openat2_with_how(int dirfd, const char *path,
			   const struct open_how *how)
{
	return openat2_with_size(dirfd, path, how, sizeof(*how));
}

FN_SETUP(prepare)
{
	CHECK_WITH(mkdir(TEST_DIR, 0755), _ret >= 0 || errno == EEXIST);
	CHECK_WITH(mkdir(TEST_DIR "/inside", 0755), _ret >= 0 || errno == EEXIST);
	CHECK_WITH(mkdir(OUTSIDE_DIR, 0755), _ret >= 0 || errno == EEXIST);

	int fd = CHECK(open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600));
	CHECK(write(fd, "inside", 6));
	CHECK(close(fd));

	fd = CHECK(open(OUTSIDE_DIR "/secret", O_CREAT | O_RDWR | O_TRUNC, 0600));
	CHECK(write(fd, "outside", 7));
	CHECK(close(fd));

	CHECK_WITH(symlink("inside/secret", TEST_LINK), _ret >= 0 || errno == EEXIST);
	CHECK_WITH(symlink("../openat2_outside/secret", ESCAPE_LINK),
		   _ret >= 0 || errno == EEXIST);
}
END_SETUP()

FN_TEST(openat2_beneath_accepts_internal_paths_and_links)
{
	int dirfd = TEST_SUCC(open(TEST_DIR, O_PATH | O_DIRECTORY));
	int fd = TEST_SUCC(openat2_with_how(dirfd, "inside/secret", &beneath_how));
	TEST_SUCC(close(fd));

	fd = TEST_SUCC(openat2_with_how(dirfd, "inside_link", &beneath_how));
	TEST_SUCC(close(fd));
	TEST_SUCC(close(dirfd));
}
END_TEST()

FN_TEST(openat2_beneath_rejects_dotdot_and_absolute_paths)
{
	int dirfd = TEST_SUCC(open(TEST_DIR, O_PATH | O_DIRECTORY));
	TEST_ERRNO(openat2_with_how(dirfd, "../openat2_outside/secret", &beneath_how),
		   EXDEV);
	TEST_ERRNO(openat2_with_how(dirfd, "/etc/passwd", &beneath_how), EXDEV);
	TEST_ERRNO(openat2_with_how(dirfd, "escape_link", &beneath_how), EXDEV);
	TEST_SUCC(close(dirfd));
}
END_TEST()

FN_TEST(openat2_in_root_rebases_absolute_paths_and_dotdot)
{
	int dirfd = TEST_SUCC(open(TEST_DIR, O_PATH | O_DIRECTORY));
	struct open_how how = {
		.flags = O_RDONLY,
		.resolve = RESOLVE_IN_ROOT,
	};
	int fd = TEST_SUCC(openat2_with_how(dirfd, "/inside/secret", &how));
	TEST_SUCC(close(fd));
	TEST_ERRNO(openat2_with_how(dirfd, "../openat2_outside/secret", &how), ENOENT);
	TEST_SUCC(close(dirfd));
}
END_TEST()

FN_TEST(openat2_resolution_flags_reject_links_and_mounts)
{
	int dirfd = TEST_SUCC(open(TEST_DIR, O_PATH | O_DIRECTORY));
	struct open_how how = {
		.flags = O_RDONLY,
		.resolve = RESOLVE_NO_SYMLINKS,
	};
	TEST_ERRNO(openat2_with_how(dirfd, "inside_link", &how), ELOOP);

	how.resolve = RESOLVE_NO_MAGICLINKS;
	TEST_ERRNO(openat2_with_how(AT_FDCWD, "/proc/self/exe", &how), ELOOP);

	how.resolve = RESOLVE_NO_XDEV;
	TEST_ERRNO(openat2_with_how(AT_FDCWD, "/proc/self/cmdline", &how), EXDEV);
	TEST_SUCC(close(dirfd));
}
END_TEST()

FN_TEST(openat2_validates_how_size_flags_and_mode)
{
	int dirfd = TEST_SUCC(open(TEST_DIR, O_PATH | O_DIRECTORY));
	struct open_how how = {
		.flags = O_RDONLY,
	};
	TEST_ERRNO(openat2_with_size(dirfd, "inside/secret", &how,
				     sizeof(how) - sizeof(uint64_t)),
		   EINVAL);

	struct {
		struct open_how how;
		uint64_t extra;
	} extended = { .how = how };
	int fd = TEST_SUCC(openat2_with_size(dirfd, "inside/secret", &extended.how,
					     sizeof(extended)));
	TEST_SUCC(close(fd));

	extended.extra = 1;
	TEST_ERRNO(openat2_with_size(dirfd, "inside/secret", &extended.how,
				     sizeof(extended)), E2BIG);

	how.resolve = RESOLVE_BENEATH | RESOLVE_IN_ROOT;
	TEST_ERRNO(openat2_with_how(dirfd, "inside/secret", &how), EINVAL);
	how.resolve = 1ULL << 63;
	TEST_ERRNO(openat2_with_how(dirfd, "inside/secret", &how), EINVAL);
	how.resolve = 0;
	how.flags = 1ULL << 31;
	TEST_ERRNO(openat2_with_how(dirfd, "inside/secret", &how), EINVAL);
	how.flags = O_RDONLY;
	how.mode = 0600;
	TEST_ERRNO(openat2_with_how(dirfd, "inside/secret", &how), EINVAL);
	how.flags = O_CREAT | O_RDONLY;
	how.mode = 010000;
	TEST_ERRNO(openat2_with_how(dirfd, "mode", &how), EINVAL);
	how.flags = O_CREAT | O_DIRECTORY | O_RDONLY;
	how.mode = 0600;
	TEST_ERRNO(openat2_with_how(dirfd, "mode", &how), EINVAL);
	how.flags = O_PATH | O_CREAT;
	how.mode = 0;
	TEST_ERRNO(openat2_with_how(dirfd, "mode", &how), EINVAL);
	TEST_SUCC(close(dirfd));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(unlink(ESCAPE_LINK));
	CHECK(unlink(TEST_LINK));
	CHECK(unlink(TEST_FILE));
	CHECK(rmdir(TEST_DIR "/inside"));
	CHECK(rmdir(TEST_DIR));
	CHECK(unlink(OUTSIDE_DIR "/secret"));
	CHECK(rmdir(OUTSIDE_DIR));
}
END_SETUP()
