// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../../common/test.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096UL
#define KERNEL_STACK_BYTES (512UL * 1024)
#define RESERVE_BYTES (16UL * 1024 * 1024)
#define GROUP_PAGES 128UL
#define MAX_THREADS 400UL
#define THREAD_STACK_BYTES (64UL * 1024)

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_open = PTHREAD_COND_INITIALIZER;
static int released;
static unsigned long thread_count;

static unsigned long free_memory_bytes(void)
{
	FILE *meminfo = fopen("/proc/meminfo", "r");
	char line[128];
	unsigned long kib = 0;

	if (!meminfo)
		return 0;
	while (fgets(line, sizeof(line), meminfo)) {
		if (sscanf(line, "MemFree: %lu kB", &kib) == 1)
			break;
	}
	fclose(meminfo);
	return kib * 1024;
}

static void *wait_for_release(void *arg)
{
	pthread_mutex_lock(&gate);
	while (!released)
		pthread_cond_wait(&gate_open, &gate);
	pthread_mutex_unlock(&gate);
	return arg;
}

FN_SETUP(fragment_free_memory)
{
	unsigned long free_bytes = CHECK_WITH(free_memory_bytes(), _ret > 0);
	unsigned long held_pages = (free_bytes - RESERVE_BYTES) / PAGE_SIZE;
	unsigned long freed_pages = 0;
	unsigned char *held;

	held = CHECK_WITH(mmap(NULL, held_pages * PAGE_SIZE,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
			  _ret != MAP_FAILED);
	for (unsigned long page = 0; page < held_pages; page++)
		held[page * PAGE_SIZE] = 1;
	for (unsigned long group = 0; group + GROUP_PAGES <= held_pages;
	     group += GROUP_PAGES) {
		CHECK(madvise(held + (group + GROUP_PAGES / 2) * PAGE_SIZE,
			      GROUP_PAGES / 2 * PAGE_SIZE, MADV_DONTNEED));
		freed_pages += GROUP_PAGES / 2;
	}

	thread_count = freed_pages * PAGE_SIZE / 4 / KERNEL_STACK_BYTES;
	if (thread_count > MAX_THREADS)
		thread_count = MAX_THREADS;
}
END_SETUP()

FN_TEST(create_more_threads_than_contiguous_memory_allows)
{
	pthread_attr_t attr;
	pthread_t *threads = calloc(thread_count, sizeof(*threads));
	unsigned long created = 0;

	CHECK_WITH(threads, _ret != NULL);
	CHECK(pthread_attr_init(&attr));
	CHECK(pthread_attr_setstacksize(&attr, THREAD_STACK_BYTES));

	for (; created < thread_count; created++) {
		if (pthread_create(&threads[created], &attr, wait_for_release,
				   NULL) != 0)
			break;
	}
	TEST_RES(created, _ret == thread_count);

	pthread_mutex_lock(&gate);
	released = 1;
	pthread_cond_broadcast(&gate_open);
	pthread_mutex_unlock(&gate);
	for (unsigned long index = 0; index < created; index++)
		pthread_join(threads[index], NULL);
	free(threads);
}
END_TEST()
