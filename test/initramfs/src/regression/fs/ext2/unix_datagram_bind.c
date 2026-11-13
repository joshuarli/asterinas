// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "../../common/test.h"

#ifndef EXT2_DIR
#define EXT2_DIR "/ext2"
#endif

#define TEST_DIR EXT2_DIR "/unix_datagram_bind"
#define NR_SOCKETS 4096

static int bind_one(int index)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	int ret;

	if (fd < 0)
		return -1;
	snprintf(addr.sun_path, sizeof(addr.sun_path), TEST_DIR "/s%d", index);
	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);
	return ret;
}

static void unlink_one(int index)
{
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];

	snprintf(path, sizeof(path), TEST_DIR "/s%d", index);
	unlink(path);
}

FN_SETUP(mkdir)
{
	CHECK(mkdir(TEST_DIR, 0755));
}
END_SETUP()

FN_TEST(bind_creates_socket_files_whose_inode_pages_need_io)
{
	int failed = 0;

	for (int i = 0; i < NR_SOCKETS; i++) {
		if (bind_one(i) < 0) {
			failed = 1;
			break;
		}
	}
	TEST_RES(failed, _ret == 0);
}
END_TEST()

FN_SETUP(cleanup)
{
	for (int i = 0; i < NR_SOCKETS; i++)
		unlink_one(i);
	CHECK(rmdir(TEST_DIR));
}
END_SETUP()
