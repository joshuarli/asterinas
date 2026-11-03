// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

#define SOURCE_FILE "/tmp/copy_file_range_source"
#define DESTINATION_FILE "/tmp/copy_file_range_destination"
#define DATA "0123456789abcdef"

static int source;
static int destination;

static long copy(int in, long long *in_off, int out, long long *out_off,
		 size_t len, unsigned int flags)
{
	return syscall(SYS_copy_file_range, in, in_off, out, out_off, len,
		       flags);
}

static int destination_holds(const char *expected, size_t len)
{
	char buffer[64] = {};

	if (pread(destination, buffer, sizeof(buffer), 0) != (ssize_t)len)
		return 0;
	return memcmp(buffer, expected, len) == 0;
}

FN_SETUP(open_files)
{
	source = CHECK(open(SOURCE_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600));
	destination =
		CHECK(open(DESTINATION_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600));
	CHECK(write(source, DATA, 16));
}
END_SETUP()

FN_TEST(explicit_offsets_select_and_report_the_range)
{
	long long in_off = 4;
	long long out_off = 2;

	TEST_RES(copy(source, &in_off, destination, &out_off, 8, 0), _ret == 8);
	TEST_RES(in_off, _ret == 12);
	TEST_RES(out_off, _ret == 10);
	TEST_RES(lseek(source, 0, SEEK_CUR), _ret == 16);
	TEST_RES(lseek(destination, 0, SEEK_CUR), _ret == 0);
	TEST_RES(destination_holds("\0\0" "456789ab", 10), _ret == 1);
}
END_TEST()

FN_TEST(file_offsets_are_used_and_advanced_without_pointers)
{
	TEST_SUCC(ftruncate(destination, 0));
	TEST_SUCC(lseek(source, 10, SEEK_SET));
	TEST_SUCC(lseek(destination, 0, SEEK_SET));

	TEST_RES(copy(source, NULL, destination, NULL, 100, 0), _ret == 6);
	TEST_RES(lseek(source, 0, SEEK_CUR), _ret == 16);
	TEST_RES(lseek(destination, 0, SEEK_CUR), _ret == 6);
	TEST_RES(destination_holds("abcdef", 6), _ret == 1);

	TEST_RES(copy(source, NULL, destination, NULL, 100, 0), _ret == 0);
}
END_TEST()

FN_TEST(a_start_past_the_end_copies_nothing)
{
	long long in_off = 16;
	long long out_off = 0;

	TEST_RES(copy(source, &in_off, destination, &out_off, 4, 0), _ret == 0);
	TEST_RES(in_off, _ret == 16);
}
END_TEST()

FN_TEST(flags_are_rejected)
{
	TEST_ERRNO(copy(source, NULL, destination, NULL, 1, 1), EINVAL);
}
END_TEST()

FN_TEST(a_negative_offset_is_rejected)
{
	long long in_off = -1;

	TEST_ERRNO(copy(source, &in_off, destination, NULL, 1, 0), EOVERFLOW);
}
END_TEST()

FN_TEST(files_must_be_open_in_the_right_mode)
{
	int reader = TEST_SUCC(open(DESTINATION_FILE, O_RDONLY));
	int writer = TEST_SUCC(open(SOURCE_FILE, O_WRONLY));
	int appender = TEST_SUCC(open(DESTINATION_FILE, O_WRONLY | O_APPEND));

	TEST_ERRNO(copy(source, NULL, reader, NULL, 1, 0), EBADF);
	TEST_ERRNO(copy(writer, NULL, destination, NULL, 1, 0), EBADF);
	TEST_ERRNO(copy(source, NULL, appender, NULL, 1, 0), EBADF);
	TEST_ERRNO(copy(9999, NULL, destination, NULL, 1, 0), EBADF);

	TEST_SUCC(close(reader));
	TEST_SUCC(close(writer));
	TEST_SUCC(close(appender));
}
END_TEST()

FN_TEST(only_regular_files_are_copied)
{
	int directory = TEST_SUCC(open("/tmp", O_RDONLY));
	int fds[2];

	TEST_SUCC(pipe(fds));
	TEST_ERRNO(copy(directory, NULL, destination, NULL, 1, 0), EISDIR);
	TEST_ERRNO(copy(source, NULL, fds[1], NULL, 1, 0), EINVAL);
	TEST_ERRNO(copy(fds[0], NULL, destination, NULL, 1, 0), EINVAL);

	TEST_SUCC(close(directory));
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(files_on_different_file_systems_are_rejected)
{
	int other = TEST_SUCC(open("/dev/shm/copy_file_range_other", O_CREAT | O_RDWR | O_TRUNC, 0600));
	TEST_ERRNO(copy(source, NULL, other, NULL, 1, 0), EXDEV);
	TEST_SUCC(close(other));
	TEST_SUCC(unlink("/dev/shm/copy_file_range_other"));
}
END_TEST()

static void *copy_to_shared_offset(void *unused)
{
	(void)unused;
	for (int i = 0; i < 100; i++) {
		long long in_off = 0;
		if (copy(source, &in_off, destination, NULL, 16, 0) != 16)
			return (void *)1;
	}
	return NULL;
}

FN_TEST(concurrent_copies_advance_the_shared_output_offset)
{
	TEST_SUCC(ftruncate(destination, 0));
	TEST_SUCC(lseek(destination, 0, SEEK_SET));
	pthread_t first, second;
	CHECK_WITH(pthread_create(&first, NULL, copy_to_shared_offset, NULL), _ret == 0);
	CHECK_WITH(pthread_create(&second, NULL, copy_to_shared_offset, NULL), _ret == 0);
	void *first_result, *second_result;
	CHECK_WITH(pthread_join(first, &first_result), _ret == 0);
	CHECK_WITH(pthread_join(second, &second_result), _ret == 0);
	TEST_RES(first_result, _ret == NULL);
	TEST_RES(second_result, _ret == NULL);
	struct stat st;
	TEST_SUCC(fstat(destination, &st));
	TEST_RES(st.st_size, _ret == 3200);
	TEST_RES(lseek(destination, 0, SEEK_CUR), _ret == 3200);
}
END_TEST()

FN_TEST(ranges_of_one_file_must_not_overlap)
{
	long long in_off = 0;
	long long out_off = 8;
	int again = TEST_SUCC(open(SOURCE_FILE, O_RDWR));

	TEST_ERRNO(copy(source, &in_off, again, &out_off, 16, 0), EINVAL);
	out_off = 16;
	TEST_RES(copy(source, &in_off, again, &out_off, 16, 0), _ret == 16);
	TEST_SUCC(close(again));
}
END_TEST()

FN_SETUP(clean_up)
{
	CHECK(close(source));
	CHECK(close(destination));
	CHECK(unlink(SOURCE_FILE));
	CHECK(unlink(DESTINATION_FILE));
}
END_SETUP()
