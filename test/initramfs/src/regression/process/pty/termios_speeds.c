// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <asm/ioctls.h>
#include <asm/termbits.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int speeds(int fd, unsigned input, unsigned output)
{
	struct termios2 attrs;
	if (ioctl(fd, TCGETS2, &attrs)) {
		perror("get terminal speeds");
		return 1;
	}
	if (attrs.c_ispeed != input || attrs.c_ospeed != output) {
		fprintf(stderr, "terminal speeds: input=%u output=%u; expected %u %u\n",
			attrs.c_ispeed, attrs.c_ospeed, input, output);
		return 1;
	}
	return 0;
}

int main(void)
{
	int master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	int number, unlock = 0;
	if (master < 0 || ioctl(master, TIOCGPTN, &number) || ioctl(master, TIOCSPTLCK, &unlock)) {
		perror("open terminal master");
		return 1;
	}
	char path[128];
	if (snprintf(path, sizeof(path), "/dev/pts/%d", number) >= (int)sizeof(path))
		return 1;
	int slave = open(path, O_RDWR | O_NOCTTY);
	struct termios2 original;
	if (slave < 0 || ioctl(slave, TCGETS2, &original)) {
		perror("open terminal slave");
		close(master);
		return 1;
	}
	struct termios2 attrs = original;
	attrs.c_cflag = (attrs.c_cflag & ~(CBAUD | CIBAUD)) | B9600;
	attrs.c_ispeed = original.c_ispeed;
	attrs.c_ospeed = 9600;
	int failed = 0;
	if (ioctl(slave, TCSETS2, &attrs) || speeds(slave, 9600, 9600))
		failed = 1;
	attrs.c_cflag = (attrs.c_cflag & ~(CBAUD | CIBAUD)) | BOTHER | (BOTHER << IBSHIFT);
	attrs.c_ispeed = 23456;
	attrs.c_ospeed = 12345;
	if (ioctl(slave, TCSETS2, &attrs) || speeds(slave, 23456, 12345))
		failed = 1;
	struct termios legacy;
	memcpy(&legacy, &attrs, sizeof(legacy));
	legacy.c_cflag = (legacy.c_cflag & ~(CBAUD | CIBAUD)) | B115200;
	if (ioctl(slave, TCSETS, &legacy) || speeds(slave, 115200, 115200))
		failed = 1;
	if (ioctl(slave, TCSETS2, &original) || close(slave) || close(master))
		return 1;
	if (!failed)
		puts("termios: inherited, explicit and legacy terminal speeds passed");
	return failed;
}
