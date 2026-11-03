// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../common/test.h"

#define MOUNT_POINT "/tmp/tmpfs_sparse_blocks"
#define TEST_FILE MOUNT_POINT "/file"
#define MEGABYTE (1 << 20)

static int fd;

static long long allocated_bytes(void)
{
	struct stat st;

	if (fstat(fd, &st) != 0)
		return -1;
	return (long long)st.st_blocks * 512;
}

FN_SETUP(mount_tmpfs)
{
	CHECK_WITH(mkdir(MOUNT_POINT, 0700), _ret == 0 || errno == EEXIST);
	CHECK(mount("tmpfs", MOUNT_POINT, "tmpfs", 0, NULL));
	fd = CHECK(open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600));
}
END_SETUP()

FN_TEST(a_file_extended_by_truncation_holds_no_blocks)
{
	TEST_SUCC(ftruncate(fd, MEGABYTE));
	TEST_RES(allocated_bytes(), _ret == 0);
}
END_TEST()

FN_TEST(reading_holes_and_mapping_them_have_distinct_allocation)
{
	char data[4096];
	TEST_RES(pread(fd, data, sizeof(data), 0), _ret == sizeof(data));
	TEST_RES(allocated_bytes(), _ret == 0);
	void *mapping = mmap(NULL, sizeof(data), PROT_READ, MAP_SHARED, fd, 0);
	TEST_RES(mapping, _ret != MAP_FAILED);
	if (mapping != MAP_FAILED) {
		volatile char byte = *(volatile char *)mapping;
		TEST_RES(byte, _ret == 0);
		TEST_SUCC(munmap(mapping, sizeof(data)));
	}
	TEST_RES(allocated_bytes(), _ret == 4096);
	TEST_SUCC(ftruncate(fd, 0));
	TEST_SUCC(ftruncate(fd, MEGABYTE));
}
END_TEST()

FN_TEST(a_write_in_a_hole_holds_only_the_pages_written)
{
	TEST_RES(pwrite(fd, "x", 1, MEGABYTE / 2), _ret == 1);
	TEST_RES(allocated_bytes(), _ret == 4096);

	TEST_RES(pwrite(fd, "y", 1, MEGABYTE - 1), _ret == 1);
	TEST_RES(allocated_bytes(), _ret == 8192);
}
END_TEST()

FN_TEST(a_file_written_through_holds_all_its_blocks)
{
	static char chunk[4096];

	for (int i = 0; i < MEGABYTE / (int)sizeof(chunk); i++)
		TEST_RES(pwrite(fd, chunk, sizeof(chunk), (off_t)i * sizeof(chunk)),
			 _ret == sizeof(chunk));
	TEST_RES(allocated_bytes(), _ret == MEGABYTE);
}
END_TEST()

FN_TEST(truncation_releases_the_blocks_beyond_the_end)
{
	TEST_SUCC(ftruncate(fd, 4096));
	TEST_RES(allocated_bytes(), _ret == 4096);
	TEST_SUCC(ftruncate(fd, 0));
	TEST_RES(allocated_bytes(), _ret == 0);
}
END_TEST()

FN_SETUP(unmount_tmpfs)
{
	CHECK(close(fd));
	CHECK(unlink(TEST_FILE));
	CHECK(umount(MOUNT_POINT));
	CHECK(rmdir(MOUNT_POINT));
}
END_SETUP()
