// SPDX-License-Identifier: MPL-2.0

#include "../common/test.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <time.h>
#include <unistd.h>

FN_TEST(the_auxiliary_vector_carries_the_clock_tick_frequency)
{
	TEST_RES(getauxval(AT_CLKTCK), _ret == 100);
	TEST_RES(sysconf(_SC_CLK_TCK), _ret == 100);
}
END_TEST()

static unsigned long long stat_field(int field)
{
	char buf[4096];
	FILE *file = fopen("/proc/self/stat", "r");
	CHECK_WITH(file, _ret != NULL);
	CHECK_WITH(fgets(buf, sizeof(buf), file), _ret != NULL);
	CHECK(fclose(file));
	char *tail = strrchr(buf, ')');
	CHECK_WITH(tail, _ret != NULL);
	char *save;
	char *token = strtok_r(tail + 2, " ", &save);
	for (int n = 3; n < field; n++) {
		CHECK_WITH(token, _ret != NULL);
		token = strtok_r(NULL, " ", &save);
	}
	CHECK_WITH(token, _ret != NULL);
	return strtoull(token, NULL, 10);
}

FN_TEST(process_start_time_uses_auxiliary_clock_ticks)
{
	struct timespec now;
	TEST_SUCC(clock_gettime(CLOCK_BOOTTIME, &now));
	unsigned long hz = sysconf(_SC_CLK_TCK);
	unsigned long long ticks = stat_field(22);
	unsigned long long current = (unsigned long long)now.tv_sec * hz + now.tv_nsec * hz / 1000000000;
	TEST_RES(ticks, _ret <= current + hz && current <= _ret + 10 * hz);
}
END_TEST()

FN_TEST(process_cpu_time_uses_auxiliary_clock_ticks)
{
	struct timespec start, now;
	unsigned long hz = sysconf(_SC_CLK_TCK);
	unsigned long long before = stat_field(14) + stat_field(15);
	TEST_SUCC(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start));
	do {
		CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now));
	} while ((now.tv_sec - start.tv_sec) * 1000000000LL + now.tv_nsec - start.tv_nsec < 300000000LL);
	unsigned long long delta = stat_field(14) + stat_field(15) - before;
	TEST_RES(delta, _ret >= hz / 10 && _ret <= hz);
}
END_TEST()

static unsigned long long cpu_ticks(const char *wanted)
{
	char buf[4096], name[16];
	unsigned long long fields[10];
	FILE *file = fopen("/proc/stat", "r");
	CHECK_WITH(file, _ret != NULL);
	while (fgets(buf, sizeof(buf), file)) {
		if (sscanf(buf, "%15s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			   name, &fields[0], &fields[1], &fields[2], &fields[3], &fields[4],
			   &fields[5], &fields[6], &fields[7], &fields[8], &fields[9]) != 11)
			continue;
		if (strcmp(name, wanted) != 0)
			continue;
		CHECK(fclose(file));
		unsigned long long total = 0;
		for (int i = 0; i < 8; i++)
			total += fields[i];
		return total;
	}
	CHECK(fclose(file));
	CHECK_WITH(-1, _ret >= 0);
	return 0;
}

FN_TEST(system_cpu_time_uses_auxiliary_clock_ticks)
{
	long hz = sysconf(_SC_CLK_TCK);
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	unsigned long long total_before = cpu_ticks("cpu");
	unsigned long long cpu_before = cpu_ticks("cpu0");
	TEST_SUCC(sleep(1));
	unsigned long long total_delta = cpu_ticks("cpu") - total_before;
	unsigned long long cpu_delta = cpu_ticks("cpu0") - cpu_before;
	TEST_RES(total_delta, _ret > 0 && _ret < (unsigned long long)(3 * hz * cpus));
	TEST_RES(cpu_delta, _ret > 0 && _ret < (unsigned long long)(3 * hz));
}
END_TEST()

FN_TEST(the_auxiliary_vector_carries_the_page_size)
{
	TEST_RES(getauxval(AT_PAGESZ), _ret == (unsigned long)sysconf(_SC_PAGESIZE));
}
END_TEST()
