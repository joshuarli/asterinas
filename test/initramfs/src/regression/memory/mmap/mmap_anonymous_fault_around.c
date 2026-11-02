// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../../common/test.h"

#include <setjmp.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE_SIZE 4096

static sigjmp_buf fault_jump;

static void on_segv(int signal)
{
	siglongjmp(fault_jump, 1);
}

static int touch_faults(volatile char *address)
{
	if (sigsetjmp(fault_jump, 1) != 0)
		return 1;
	*address = 1;
	return 0;
}

static int all_zero(const char *start, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		if (start[i] != 0)
			return 0;
	}
	return 1;
}

#ifdef __asterinas__
static long anonymous_rss_kb(void)
{
	char line[256];
	long rss_kb = -1;
	FILE *status = CHECK_WITH(fopen("/proc/self/status", "r"), _ret != NULL);

	while (fgets(line, sizeof(line), status)) {
		if (sscanf(line, "RssAnon: %ld", &rss_kb) == 1)
			break;
	}
	fclose(status);
	return rss_kb;
}
#endif

FN_SETUP(install_segv_handler)
{
	struct sigaction action = { .sa_handler = on_segv };

	CHECK(sigaction(SIGSEGV, &action, NULL));
}
END_SETUP()

FN_TEST(pages_next_to_a_touched_page_read_as_zero_and_stay_writable)
{
	char *mem = TEST_SUCC(mmap(NULL, 64 * PAGE_SIZE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

	mem[20 * PAGE_SIZE + 7] = 42;

	TEST_RES(all_zero(mem + 16 * PAGE_SIZE, 4 * PAGE_SIZE), _ret);
	TEST_RES(mem[20 * PAGE_SIZE + 7], _ret == 42);
	TEST_RES(all_zero(mem + 21 * PAGE_SIZE, 11 * PAGE_SIZE), _ret);
	TEST_RES(memset(mem + 16 * PAGE_SIZE, 7, 16 * PAGE_SIZE) != NULL, _ret);
	TEST_RES(mem[31 * PAGE_SIZE + PAGE_SIZE - 1], _ret == 7);
	TEST_RES(all_zero(mem, 16 * PAGE_SIZE), _ret);
	TEST_RES(all_zero(mem + 32 * PAGE_SIZE, 32 * PAGE_SIZE), _ret);

	TEST_SUCC(munmap(mem, 64 * PAGE_SIZE));
}
END_TEST()

FN_TEST(a_short_mapping_ends_where_it_ends)
{
	char *mem = TEST_SUCC(mmap(NULL, 5 * PAGE_SIZE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

	mem[4 * PAGE_SIZE] = 1;

	TEST_RES(all_zero(mem, 4 * PAGE_SIZE), _ret);
	TEST_SUCC(munmap(mem, 5 * PAGE_SIZE));
}
END_TEST()

FN_TEST(a_fault_does_not_reach_across_a_protection_boundary)
{
	char *mem = TEST_SUCC(mmap(NULL, 16 * PAGE_SIZE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

	TEST_SUCC(mprotect(mem + 8 * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
	mem[3 * PAGE_SIZE] = 1;

	TEST_RES(touch_faults((volatile char *)mem + 8 * PAGE_SIZE), _ret == 1);
	TEST_RES(touch_faults((volatile char *)mem + 9 * PAGE_SIZE), _ret == 0);
	TEST_SUCC(munmap(mem, 16 * PAGE_SIZE));
}
END_TEST()

FN_TEST(a_read_only_mapping_becomes_writable_after_a_read_fault)
{
	char *mem = TEST_SUCC(mmap(NULL, 32 * PAGE_SIZE, PROT_READ,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

	TEST_RES(mem[3 * PAGE_SIZE], _ret == 0);
	TEST_RES(touch_faults((volatile char *)mem + 4 * PAGE_SIZE), _ret == 1);
	TEST_SUCC(mprotect(mem, 32 * PAGE_SIZE, PROT_READ | PROT_WRITE));
	mem[3 * PAGE_SIZE] = 5;
	mem[4 * PAGE_SIZE] = 6;
	TEST_RES(mem[3 * PAGE_SIZE] + mem[4 * PAGE_SIZE], _ret == 11);
	TEST_SUCC(munmap(mem, 32 * PAGE_SIZE));
}
END_TEST()

FN_TEST(a_forked_child_writes_its_own_copy_of_the_pages_around_a_fault)
{
	char *mem = TEST_SUCC(mmap(NULL, 32 * PAGE_SIZE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	int status = -1;
	pid_t child;

	mem[3 * PAGE_SIZE] = 9;
	child = TEST_SUCC(fork());
	if (child == 0) {
		mem[3 * PAGE_SIZE] = 1;
		mem[4 * PAGE_SIZE] = 2;
		_exit(mem[3 * PAGE_SIZE] == 1 && mem[4 * PAGE_SIZE] == 2 ? 0 : 1);
	}

	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret);
	TEST_RES(mem[3 * PAGE_SIZE], _ret == 9);
	TEST_RES(mem[4 * PAGE_SIZE], _ret == 0);
	TEST_SUCC(munmap(mem, 32 * PAGE_SIZE));
}
END_TEST()

FN_TEST(unmapping_pages_beside_a_fault_leaves_the_rest_usable)
{
	char *mem = TEST_SUCC(mmap(NULL, 32 * PAGE_SIZE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

	mem[3 * PAGE_SIZE] = 3;
	TEST_SUCC(munmap(mem + 4 * PAGE_SIZE, 4 * PAGE_SIZE));
	TEST_RES(mem[3 * PAGE_SIZE], _ret == 3);
	TEST_RES(touch_faults((volatile char *)mem + 5 * PAGE_SIZE), _ret == 1);
	TEST_RES(touch_faults((volatile char *)mem + 8 * PAGE_SIZE), _ret == 0);
	TEST_SUCC(munmap(mem, 4 * PAGE_SIZE));
	TEST_SUCC(munmap(mem + 8 * PAGE_SIZE, 24 * PAGE_SIZE));
}
END_TEST()

#ifdef __asterinas__
FN_TEST(touching_one_page_maps_its_aligned_window)
{
	char *mem = TEST_SUCC(mmap(NULL, 128 * PAGE_SIZE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	long before = anonymous_rss_kb();

	mem[64 * PAGE_SIZE] = 1;

	TEST_RES(anonymous_rss_kb() - before, _ret == 16 * PAGE_SIZE / 1024);
	TEST_SUCC(munmap(mem, 128 * PAGE_SIZE));
}
END_TEST()
#endif
