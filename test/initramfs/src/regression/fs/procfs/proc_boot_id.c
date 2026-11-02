// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "../../common/test.h"

#define BOOT_ID_PATH "/proc/sys/kernel/random/boot_id"
#define UUID_TEXT_LEN 36

static int read_boot_id(char *buf, size_t size)
{
	int fd = open(BOOT_ID_PATH, O_RDONLY);
	ssize_t len;

	if (fd < 0)
		return -1;
	len = read(fd, buf, size - 1);
	close(fd);
	if (len < 0)
		return -1;
	buf[len] = '\0';
	return len;
}

static int is_version_4_uuid_line(const char *text)
{
	for (int i = 0; i < UUID_TEXT_LEN; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (text[i] != '-')
				return 0;
		} else if (!isxdigit((unsigned char)text[i]) ||
			   isupper((unsigned char)text[i])) {
			return 0;
		}
	}
	return text[14] == '4' && strchr("89ab", text[19]) &&
	       text[UUID_TEXT_LEN] == '\n' && text[UUID_TEXT_LEN + 1] == '\0';
}

FN_TEST(boot_id_is_a_lowercase_version_4_uuid_line)
{
	char text[64];

	TEST_RES(read_boot_id(text, sizeof(text)),
		 _ret == UUID_TEXT_LEN + 1 && is_version_4_uuid_line(text));
}
END_TEST()

FN_TEST(boot_id_does_not_change_while_the_system_runs)
{
	char first[64], second[64];

	TEST_RES(read_boot_id(first, sizeof(first)), _ret > 0);
	TEST_RES(read_boot_id(second, sizeof(second)),
		 _ret > 0 && strcmp(first, second) == 0);
}
END_TEST()
