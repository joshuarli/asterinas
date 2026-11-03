// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "../../common/test.h"

#define TEST_FILE "./sync_writeback_test_file"
#define CHUNK_SIZE (1 << 20)
#define NR_CHUNKS 8

static char chunk[CHUNK_SIZE];

FN_TEST(sync_writes_back_a_large_dirty_file)
{
	int fd = TEST_SUCC(open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600));

	memset(chunk, 'a', sizeof(chunk));
	for (int i = 0; i < NR_CHUNKS; i++) {
		TEST_RES(write(fd, chunk, sizeof(chunk)), _ret == CHUNK_SIZE);
	}

	sync();
	TEST_SUCC(fsync(fd));
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(TEST_FILE));
}
END_TEST()
