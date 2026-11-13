// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "../../common/test.h"

#define EXT2_DIR_DEFAULT "/work/.work/tmp/native/tmp"
#define TMPFS_DIR_DEFAULT "/tmp"

#define YEAR_ZERO_SEC (-62167219200LL)
#define ONE_YEAR_SEC (86400LL * 365)

static int failures;

static void fail(const char *dir, const char *what, long long got,
		 long long want)
{
	fprintf(stderr, "FAIL [%s] %s: got %lld, want %lld\n", dir, what, got,
		want);
	failures++;
}

static void expect_eq(const char *dir, const char *what, long long got,
		      long long want)
{
	if (got != want)
		fail(dir, what, got, want);
}

static long long clamp_ext2(long long sec)
{
	if (sec < INT32_MIN)
		return INT32_MIN;
	if (sec > INT32_MAX)
		return INT32_MAX;
	return sec;
}

static void expect_sec(const char *dir, int ext2, const char *what,
		       long long got, long long set)
{
	if (got == set)
		return;
	if (ext2 && got == clamp_ext2(set))
		return;
	fail(dir, what, got, set);
}

static int stat_both(const char *path, struct stat *st, struct statx *sx)
{
	if (stat(path, st) != 0)
		return -1;
	return syscall(SYS_statx, AT_FDCWD, path, 0, STATX_BASIC_STATS, sx);
}

static void check_times(const char *dir, int ext2, const char *path,
			const char *label, long long asec, long long ansec,
			long long msec, long long mnsec)
{
	struct timespec times[2] = {
		{ .tv_sec = asec, .tv_nsec = ansec },
		{ .tv_sec = msec, .tv_nsec = mnsec },
	};
	struct stat st;
	struct statx sx;
	struct timespec now;
	char what[160];

	if (utimensat(AT_FDCWD, path, times, 0) != 0) {
		snprintf(what, sizeof(what), "%s utimensat errno=%d", label,
			 errno);
		fail(dir, what, -1, 0);
		return;
	}
	if (stat_both(path, &st, &sx) != 0) {
		fail(dir, "stat", -1, 0);
		return;
	}

	snprintf(what, sizeof(what), "%s stat atime sec", label);
	expect_sec(dir, ext2, what, st.st_atim.tv_sec, asec);
	snprintf(what, sizeof(what), "%s stat mtime sec", label);
	expect_sec(dir, ext2, what, st.st_mtim.tv_sec, msec);
	snprintf(what, sizeof(what), "%s statx atime sec", label);
	expect_sec(dir, ext2, what, sx.stx_atime.tv_sec, asec);
	snprintf(what, sizeof(what), "%s statx mtime sec", label);
	expect_sec(dir, ext2, what, sx.stx_mtime.tv_sec, msec);
	if (st.st_atim.tv_sec != sx.stx_atime.tv_sec ||
	    st.st_mtim.tv_sec != sx.stx_mtime.tv_sec)
		fail(dir, "stat and statx disagree", st.st_atim.tv_sec,
		     sx.stx_atime.tv_sec);

	if (!ext2) {
		snprintf(what, sizeof(what), "%s stat atime nsec", label);
		expect_eq(dir, what, st.st_atim.tv_nsec, ansec);
		snprintf(what, sizeof(what), "%s stat mtime nsec", label);
		expect_eq(dir, what, st.st_mtim.tv_nsec, mnsec);
		snprintf(what, sizeof(what), "%s statx atime nsec", label);
		expect_eq(dir, what, sx.stx_atime.tv_nsec, ansec);
		snprintf(what, sizeof(what), "%s statx mtime nsec", label);
		expect_eq(dir, what, sx.stx_mtime.tv_nsec, mnsec);
	}

	clock_gettime(CLOCK_REALTIME, &now);
	snprintf(what, sizeof(what), "%s ctime is recent", label);
	expect_eq(dir, what,
		  st.st_ctim.tv_sec > now.tv_sec - 3600 &&
			  st.st_ctim.tv_sec <= now.tv_sec + 3600,
		  1);
}

static int run_suite(const char *dir, int ext2)
{
	char path[256];
	struct stat st;
	struct statx sx;
	struct timespec times[2];
	struct timeval tv[2];
	struct utimbuf ub;
	long long bad_nsec[] = { -1, 1000000000, 2000000000, -1000000000 };
	int fd;
	int r;

	failures = 0;
	snprintf(path, sizeof(path), "%s/pre_epoch_witness", dir);
	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0) {
		fail(dir, "create", -1, 0);
		return failures;
	}
	close(fd);

	check_times(dir, ext2, path, "minus one", -1, 0, -1, 0);
	check_times(dir, ext2, path, "minus one year", -ONE_YEAR_SEC, 0,
		    -ONE_YEAR_SEC, 0);
	check_times(dir, ext2, path, "year zero", YEAR_ZERO_SEC, 0,
		    YEAR_ZERO_SEC, 0);
	check_times(dir, ext2, path, "split", -2, 500000000, -ONE_YEAR_SEC,
		    999999999);
	check_times(dir, ext2, path, "int32 min", INT32_MIN, 0, INT32_MIN, 0);
	check_times(dir, ext2, path, "below int32 min",
		    (long long)INT32_MIN - 1, 0, (long long)INT32_MIN - 1, 0);
	check_times(dir, ext2, path, "above int32 max",
		    (long long)INT32_MAX + 1, 0, (long long)INT32_MAX + 1, 0);
	check_times(dir, ext2, path, "mixed", YEAR_ZERO_SEC, 0, 1700000000, 0);

	times[0] = (struct timespec){ .tv_sec = -5, .tv_nsec = 0 };
	times[1] = (struct timespec){ .tv_sec = -6, .tv_nsec = 0 };
	if (utimensat(AT_FDCWD, path, times, 0) != 0)
		fail(dir, "set -5/-6", -1, 0);
	times[0] = (struct timespec){ .tv_sec = 0, .tv_nsec = UTIME_OMIT };
	times[1] = (struct timespec){ .tv_sec = 10, .tv_nsec = 0 };
	if (utimensat(AT_FDCWD, path, times, 0) != 0)
		fail(dir, "omit atime", -1, 0);
	if (stat_both(path, &st, &sx) != 0)
		fail(dir, "stat after omit", -1, 0);
	expect_eq(dir, "omit keeps negative atime", st.st_atim.tv_sec, -5);
	expect_eq(dir, "omit sets mtime", st.st_mtim.tv_sec, 10);
	times[0] = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	times[1] = (struct timespec){ .tv_sec = 0, .tv_nsec = UTIME_OMIT };
	if (utimensat(AT_FDCWD, path, times, 0) != 0)
		fail(dir, "omit mtime", -1, 0);
	if (stat(path, &st) != 0)
		fail(dir, "stat after omit mtime", -1, 0);
	expect_eq(dir, "omit mtime keeps mtime", st.st_mtim.tv_sec, 10);
	expect_eq(dir, "set atime zero", st.st_atim.tv_sec, 0);

	for (size_t i = 0; i < sizeof(bad_nsec) / sizeof(bad_nsec[0]); i++) {
		times[0] = (struct timespec){ .tv_sec = -7,
					      .tv_nsec = bad_nsec[i] };
		times[1] = (struct timespec){ .tv_sec = -7, .tv_nsec = 0 };
		errno = 0;
		r = utimensat(AT_FDCWD, path, times, 0);
		expect_eq(dir, "bad atime nsec returns -1", r, -1);
		expect_eq(dir, "bad atime nsec errno", errno, EINVAL);
		times[0] = (struct timespec){ .tv_sec = -7, .tv_nsec = 0 };
		times[1] = (struct timespec){ .tv_sec = -7,
					      .tv_nsec = bad_nsec[i] };
		errno = 0;
		r = utimensat(AT_FDCWD, path, times, 0);
		expect_eq(dir, "bad mtime nsec returns -1", r, -1);
		expect_eq(dir, "bad mtime nsec errno", errno, EINVAL);
	}
	if (stat(path, &st) != 0)
		fail(dir, "stat after bad nsec", -1, 0);
	expect_eq(dir, "bad nsec leaves atime", st.st_atim.tv_sec, 0);

	tv[0] = (struct timeval){ .tv_sec = -100, .tv_usec = 250000 };
	tv[1] = (struct timeval){ .tv_sec = -200, .tv_usec = 0 };
	if (utimes(path, tv) != 0)
		fail(dir, "utimes negative", -1, 0);
	if (stat(path, &st) != 0)
		fail(dir, "stat after utimes", -1, 0);
	expect_eq(dir, "utimes atime", st.st_atim.tv_sec, -100);
	expect_eq(dir, "utimes mtime", st.st_mtim.tv_sec, -200);
	if (!ext2)
		expect_eq(dir, "utimes atime nsec", st.st_atim.tv_nsec,
			  250000000);

	tv[0] = (struct timeval){ .tv_sec = 0, .tv_usec = 1000000 };
	errno = 0;
	r = utimes(path, tv);
	expect_eq(dir, "utimes bad usec", r, -1);
	expect_eq(dir, "utimes bad usec errno", errno, EINVAL);

	ub.actime = -300;
	ub.modtime = -400;
	if (utime(path, &ub) != 0)
		fail(dir, "utime negative", -1, 0);
	if (stat(path, &st) != 0)
		fail(dir, "stat after utime", -1, 0);
	expect_eq(dir, "utime atime", st.st_atim.tv_sec, -300);
	expect_eq(dir, "utime mtime", st.st_mtim.tv_sec, -400);

	fd = open(path, O_RDWR);
	times[0] = (struct timespec){ .tv_sec = -9, .tv_nsec = 0 };
	times[1] = (struct timespec){ .tv_sec = -10, .tv_nsec = 0 };
	if (futimens(fd, times) != 0)
		fail(dir, "futimens negative", -1, 0);
	if (fstat(fd, &st) != 0)
		fail(dir, "fstat after futimens", -1, 0);
	expect_eq(dir, "futimens atime", st.st_atim.tv_sec, -9);
	expect_eq(dir, "futimens mtime", st.st_mtim.tv_sec, -10);
	close(fd);

	unlink(path);
	errno = 0;
	return failures;
}

FN_TEST(pre_epoch_times_on_ext2)
{
	const char *dir = getenv("WITNESS_EXT2_DIR");
	TEST_RES(run_suite(dir ? dir : EXT2_DIR_DEFAULT, 1), _ret == 0);
}
END_TEST()

FN_TEST(pre_epoch_times_on_tmpfs)
{
	const char *dir = getenv("WITNESS_TMPFS_DIR");
	TEST_RES(run_suite(dir ? dir : TMPFS_DIR_DEFAULT, 0), _ret == 0);
}
END_TEST()
