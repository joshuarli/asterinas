// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../common/test.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define KERNEL_GROUP 1
#define FORWARDED_GROUP 4

static char disk[256];
static char uevent_path[512];
static char dev_path[512];

static int read_file(const char *path, char *buffer, size_t size)
{
	int fd = open(path, O_RDONLY);
	ssize_t len;

	if (fd < 0)
		return -1;
	len = read(fd, buffer, size - 1);
	close(fd);
	if (len < 0)
		return -1;
	buffer[len] = '\0';
	return (int)len;
}

static int open_listener(unsigned int groups)
{
	struct sockaddr_nl address = { .nl_family = AF_NETLINK,
				       .nl_groups = groups };
	int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC,
			NETLINK_KOBJECT_UEVENT);

	if (fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
		return -1;
	return fd;
}

static int receive(int fd, char *buffer, size_t size)
{
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
	ssize_t len;

	if (poll(&poll_fd, 1, 5000) != 1)
		return -1;
	len = recv(fd, buffer, size - 1, 0);
	if (len < 0)
		return -1;
	buffer[len] = '\0';
	return (int)len;
}

static int has_field(const char *message, size_t len, const char *field)
{
	size_t field_len = strlen(field);

	for (size_t offset = 0; offset < len; offset += strlen(message + offset) + 1) {
		if (strncmp(message + offset, field, field_len) == 0)
			return 1;
	}
	return 0;
}

FN_SETUP(find_disk)
{
	DIR *class = CHECK_WITH(opendir("/sys/class/block"), _ret != NULL);
	struct dirent *entry;

	while ((entry = readdir(class)) != NULL) {
		char path[512], text[512];

		if (entry->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "/sys/class/block/%s/uevent",
			 entry->d_name);
		if (read_file(path, text, sizeof(text)) < 0)
			continue;
		if (strstr(text, "DEVTYPE=disk\n") == NULL)
			continue;
		snprintf(disk, sizeof(disk), "%s", entry->d_name);
		break;
	}
	closedir(class);

	CHECK_WITH(strlen(disk), _ret > 0);
	snprintf(uevent_path, sizeof(uevent_path), "/sys/class/block/%s/uevent",
		 disk);
	snprintf(dev_path, sizeof(dev_path), "/sys/class/block/%s/dev", disk);
}
END_SETUP()

FN_TEST(uevent_file_describes_the_device)
{
	char uevent[512], dev[64], expected[512];
	struct stat node;
	char node_path[320];

	snprintf(node_path, sizeof(node_path), "/dev/%s", disk);
	TEST_SUCC(stat(node_path, &node));
	TEST_RES(read_file(dev_path, dev, sizeof(dev)), _ret > 0);
	snprintf(expected, sizeof(expected), "%u:%u\n", major(node.st_rdev),
		 minor(node.st_rdev));
	TEST_RES(strcmp(dev, expected), _ret == 0);
	TEST_RES(S_ISBLK(node.st_mode), _ret != 0);

	TEST_RES(read_file(uevent_path, uevent, sizeof(uevent)), _ret > 0);
	snprintf(expected, sizeof(expected), "MAJOR=%u\n", major(node.st_rdev));
	TEST_RES(strstr(uevent, expected) != NULL, _ret);
	snprintf(expected, sizeof(expected), "MINOR=%u\n", minor(node.st_rdev));
	TEST_RES(strstr(uevent, expected) != NULL, _ret);
	snprintf(expected, sizeof(expected), "DEVNAME=%s\n", disk);
	TEST_RES(strstr(uevent, expected) != NULL, _ret);
	TEST_RES(strstr(uevent, "DEVTYPE=disk\n") != NULL, _ret);
}
END_TEST()

FN_TEST(writing_add_broadcasts_a_kernel_uevent)
{
	char message[2048], expected[512];
	int listener = CHECK(open_listener(KERNEL_GROUP));
	int fd = CHECK(open(uevent_path, O_WRONLY));
	int len;

	TEST_SUCC(write(fd, "add\n", 4));
	TEST_RES(len = receive(listener, message, sizeof(message)), _ret > 0);
	close(fd);
	close(listener);
	if (len <= 0)
		return;

	TEST_RES(has_field(message, len, "ACTION=add"), _ret);
	TEST_RES(has_field(message, len, "SUBSYSTEM=block"), _ret);
	TEST_RES(has_field(message, len, "DEVTYPE=disk"), _ret);
	TEST_RES(has_field(message, len, "MAJOR="), _ret);
	TEST_RES(has_field(message, len, "MINOR="), _ret);
	TEST_RES(has_field(message, len, "SEQNUM="), _ret);
	snprintf(expected, sizeof(expected), "DEVNAME=%s", disk);
	TEST_RES(has_field(message, len, expected), _ret);
	snprintf(expected, sizeof(expected), "/block/%s", disk);
	TEST_RES(strstr(message, expected) != NULL, _ret);
	TEST_RES(strncmp(message, "add@/devices/", 13), _ret == 0);
}
END_TEST()

FN_TEST(writing_an_unknown_action_is_rejected)
{
	int fd = CHECK(open(uevent_path, O_WRONLY));

	TEST_ERRNO(write(fd, "bogus\n", 6), EINVAL);
	close(fd);
}
END_TEST()

FN_TEST(a_socket_can_forward_an_event_to_a_group)
{
	const char text[] = "add@/devices/forwarded";
	struct sockaddr_nl target = { .nl_family = AF_NETLINK,
				      .nl_groups = FORWARDED_GROUP };
	char message[256];
	int listener = CHECK(open_listener(FORWARDED_GROUP));
	int sender = CHECK(socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC,
				  NETLINK_KOBJECT_UEVENT));

	TEST_RES(sendto(sender, text, sizeof(text), 0,
			(struct sockaddr *)&target, sizeof(target)),
		 _ret == sizeof(text));
	TEST_RES(receive(listener, message, sizeof(message)),
		 _ret == sizeof(text) && memcmp(message, text, sizeof(text)) == 0);
	close(sender);
	close(listener);
}
END_TEST()
