// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define STATE_DEVICE "/dev/vdb"
#define MOUNT_POINT "/run/laputa-storage"
#define MODE_FILE "/usr/lib/asterinas/storage.mode"
#define PAYLOAD_PATH MOUNT_POINT "/payload"
#define PAYLOAD_SIZE (256 * 1024)
#define PAYLOAD_MODE 0640
#define CHURN_CHUNK (64 * 1024 * 1024)

static unsigned char payload[PAYLOAD_SIZE];
static unsigned char *churn;

static void fill_payload(void)
{
	for (size_t i = 0; i < PAYLOAD_SIZE; i++)
		payload[i] = (unsigned char)((i * 131 + 17) & 0xff);
}

static uint64_t hash_bytes(const void *data, size_t len)
{
	const unsigned char *bytes = data;
	uint64_t hash = 0xcbf29ce484222325ULL;

	for (size_t i = 0; i < len; i++) {
		hash ^= bytes[i];
		hash *= 0x100000001b3ULL;
	}
	return hash;
}

static int fail(const char *phase)
{
	fprintf(stderr, "STORAGE_FAILED %s errno=%d\n", phase, errno);
	fflush(stderr);
	return 1;
}

static int read_mode(char *buffer, size_t size)
{
	int fd = open(MODE_FILE, O_RDONLY);
	ssize_t length;

	if (fd < 0)
		return -1;
	length = read(fd, buffer, size - 1);
	close(fd);
	if (length <= 0)
		return -1;
	buffer[length] = '\0';
	while (length > 0 &&
	       (buffer[length - 1] == '\n' || buffer[length - 1] == '\r'))
		buffer[--length] = '\0';
	return 0;
}

static int write_all(int fd, const void *data, size_t length)
{
	const unsigned char *cursor = data;

	while (length > 0) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0)
			return errno;
		cursor += written;
		length -= written;
	}
	return 0;
}

static int read_all(int fd, void *data, size_t length)
{
	unsigned char *cursor = data;

	while (length > 0) {
		ssize_t taken = read(fd, cursor, length);

		if (taken <= 0)
			return -1;
		cursor += taken;
		length -= taken;
	}
	return 0;
}

static int sync_directory(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY);
	int result;

	if (fd < 0)
		return -1;
	result = fsync(fd);
	close(fd);
	return result;
}

static int mount_state(void)
{
	if (mkdir(MOUNT_POINT, 0755) != 0 && errno != EEXIST)
		return -1;
	return mount(STATE_DEVICE, MOUNT_POINT, "ext2", 0, NULL);
}

static int write_payload(void)
{
	struct stat status;
	int fd = open(PAYLOAD_PATH, O_CREAT | O_WRONLY | O_TRUNC, PAYLOAD_MODE);
	int error;

	if (fd < 0)
		return -1;
	error = write_all(fd, payload, sizeof(payload));
	if (error != 0) {
		errno = error;
		close(fd);
		return -1;
	}
	if (fsync(fd) != 0 || close(fd) != 0)
		return -1;
	if (sync_directory(MOUNT_POINT) != 0)
		return -1;
	if (stat(PAYLOAD_PATH, &status) != 0)
		return -1;
	fprintf(stderr, "STORAGE_PAYLOAD %016llx %04o %zu\n",
		(unsigned long long)hash_bytes(payload, sizeof(payload)),
		(unsigned)(status.st_mode & 07777), sizeof(payload));
	fflush(stderr);
	return 0;
}

static int stage(void)
{
	int fd;

	fill_payload();
	if (mount_state() != 0)
		return fail("stage-mount");
	if (write_payload() != 0)
		return fail("stage-payload");
	fprintf(stderr, "STORAGE_SYNCED\n");
	fflush(stderr);

	fd = open(MOUNT_POINT "/churn", O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0)
		return fail("stage-churn-open");
	churn = malloc(CHURN_CHUNK);
	if (churn == NULL)
		return fail("stage-churn-alloc");
	memset(churn, 0xa5, CHURN_CHUNK);

	for (unsigned iteration = 0;; iteration++) {
		size_t offset = 0;
		int error;

		fprintf(stderr, "STORAGE_WRITING %u\n", iteration);
		fflush(stderr);
		while (offset < CHURN_CHUNK) {
			ssize_t written =
				write(fd, churn + offset, CHURN_CHUNK - offset);

			if (written < 0) {
				error = errno;
				fprintf(stderr, "STORAGE_CHURN_ERROR %d\n", error);
				fflush(stderr);
				for (;;)
					pause();
			}
			offset += written;
		}
		if (iteration % 2 == 1)
			fsync(fd);
	}
}

static int stage_clean(void)
{
	int fd;

	fill_payload();
	if (mount_state() != 0)
		return fail("stage-clean-mount");
	if (write_payload() != 0)
		return fail("stage-clean-payload");
	sync();
	fprintf(stderr, "STORAGE_SYNCED\n");
	fflush(stderr);
	fd = open(MOUNT_POINT "/churn", O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0)
		return fail("stage-clean-churn-open");
	fprintf(stderr, "STORAGE_READY\n");
	fflush(stderr);
	for (;;) {
		if (write(fd, payload, sizeof(payload)) < 0)
			pause();
	}
}

static int prepare(void)
{
	fill_payload();
	if (mount_state() != 0)
		return fail("prepare-mount");
	if (write_payload() != 0)
		return fail("prepare-payload");
	if (umount(MOUNT_POINT) != 0)
		return fail("prepare-umount");
	fprintf(stderr, "STORAGE_PREPARED\n");
	fflush(stderr);
	return 0;
}

static int verify(void)
{
	struct stat status;
	unsigned char *readback;
	uint64_t hash;
	int fd;

	fill_payload();
	if (mount_state() != 0)
		return fail("verify-mount");
	fd = open(PAYLOAD_PATH, O_RDONLY);
	if (fd < 0)
		return fail("verify-open");
	if (fstat(fd, &status) != 0)
		return fail("verify-stat");
	readback = malloc(sizeof(payload));
	if (readback == NULL)
		return fail("verify-alloc");
	if (read_all(fd, readback, sizeof(payload)) != 0)
		return fail("verify-read");
	if (close(fd) != 0)
		return fail("verify-close");
	hash = hash_bytes(readback, sizeof(payload));
	free(readback);
	fprintf(stderr, "STORAGE_VERIFY %016llx %04o %zu\n",
		(unsigned long long)hash, (unsigned)(status.st_mode & 07777),
		(size_t)status.st_size);
	fflush(stderr);
	if (hash != hash_bytes(payload, sizeof(payload)))
		return fail("verify-hash");
	if ((status.st_mode & 07777) != PAYLOAD_MODE)
		return fail("verify-mode");
	if (status.st_size != (off_t)sizeof(payload))
		return fail("verify-size");

	fd = open(MOUNT_POINT "/verified", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		if (errno != ENOSPC)
			return fail("verify-note-open");
	} else {
		int error = write_all(fd, "verified\n", 9);

		if (error == ENOSPC) {
			if (close(fd) != 0)
				return fail("verify-note-close");
		} else if (error != 0) {
			errno = error;
			return fail("verify-note-write");
		} else {
			if (fsync(fd) != 0 || close(fd) != 0)
				return fail("verify-note-sync");
			if (sync_directory(MOUNT_POINT) != 0)
				return fail("verify-note-dir-sync");
		}
	}
	if (umount(MOUNT_POINT) != 0)
		return fail("verify-umount");
	fprintf(stderr, "STORAGE_VERIFY_OK\n");
	fflush(stderr);
	return 0;
}

static int full(void)
{
	size_t chunk_size = 1024 * 1024;
	unsigned char *buffer;
	unsigned long long written_total = 0;
	int fd;

	fill_payload();
	if (mount_state() != 0)
		return fail("full-mount");
	if (write_payload() != 0)
		return fail("full-payload");

	buffer = malloc(chunk_size);
	if (buffer == NULL)
		return fail("full-alloc");
	memset(buffer, 0x5a, chunk_size);
	fd = open(MOUNT_POINT "/fill", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0)
		return fail("full-open");
	for (;;) {
		ssize_t result = write(fd, buffer, chunk_size);

		if (result < 0) {
			int error = errno;

			if (error != ENOSPC) {
				fprintf(stderr, "STORAGE_FULL_WRONG_ERRNO %d\n",
					error);
				fflush(stderr);
				return 1;
			}
			fprintf(stderr, "STORAGE_FULL_ENOSPC %d\n", error);
			fflush(stderr);
			break;
		}
		written_total += (unsigned long long)result;
	}
	if (fsync(fd) != 0 || close(fd) != 0)
		return fail("full-fsync");
	if (sync_directory(MOUNT_POINT) != 0)
		return fail("full-dir-sync");
	if (umount(MOUNT_POINT) != 0)
		return fail("full-umount");
	fprintf(stderr, "STORAGE_FULL_DONE %llu\n", written_total);
	fflush(stderr);
	return 0;
}

static int corrupt(void)
{
	if (mount_state() == 0) {
		fprintf(stderr, "STORAGE_CORRUPT_MOUNTED\n");
		fflush(stderr);
		umount(MOUNT_POINT);
		return 1;
	}
	fprintf(stderr, "STORAGE_CORRUPT_REFUSED %d\n", errno);
	fflush(stderr);
	return 0;
}

int main(void)
{
	char mode[32];

	umask(0);
	if (read_mode(mode, sizeof(mode)) != 0)
		return fail("mode");
	if (strcmp(mode, "stage") == 0)
		return stage();
	if (strcmp(mode, "stage-clean") == 0)
		return stage_clean();
	if (strcmp(mode, "prepare") == 0)
		return prepare();
	if (strcmp(mode, "verify") == 0)
		return verify();
	if (strcmp(mode, "full") == 0)
		return full();
	if (strcmp(mode, "corrupt") == 0)
		return corrupt();
	fprintf(stderr, "STORAGE_FAILED unknown-mode %s\n", mode);
	fflush(stderr);
	return 1;
}
