// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../../common/test.h"

#define SOURCE_FILE "/tmp/ficlone_source"
#define DESTINATION_FILE "/tmp/ficlone_destination"

static int source;
static int destination;

FN_SETUP(open_files)
{
	source = CHECK(open(SOURCE_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600));
	destination =
		CHECK(open(DESTINATION_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600));
	CHECK(write(source, "data", 4));
}
END_SETUP()

FN_TEST(a_file_system_without_cloning_reports_it)
{
	TEST_ERRNO(ioctl(destination, FICLONE, source), EOPNOTSUPP);
}
END_TEST()

FN_TEST(an_unopened_source_is_rejected)
{
	TEST_ERRNO(ioctl(destination, FICLONE, 9999), EBADF);
}
END_TEST()

FN_TEST(a_source_on_another_file_system_is_rejected)
{
	int other = TEST_SUCC(open("/proc/self/status", O_RDONLY));

	TEST_ERRNO(ioctl(destination, FICLONE, other), EXDEV);
	TEST_SUCC(close(other));
}
END_TEST()

FN_TEST(a_destination_open_for_reading_only_is_rejected)
{
	int reader = TEST_SUCC(open(DESTINATION_FILE, O_RDONLY));

	TEST_ERRNO(ioctl(reader, FICLONE, source), EBADF);
	TEST_SUCC(close(reader));
}
END_TEST()

FN_TEST(path_only_descriptors_cannot_be_cloned)
{
	int source_path = TEST_SUCC(open(SOURCE_FILE, O_PATH));
	int destination_path = TEST_SUCC(open(DESTINATION_FILE, O_PATH));
	TEST_ERRNO(ioctl(destination, FICLONE, source_path), EBADF);
	TEST_ERRNO(ioctl(destination_path, FICLONE, source), EBADF);
	TEST_SUCC(close(source_path));
	TEST_SUCC(close(destination_path));
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
