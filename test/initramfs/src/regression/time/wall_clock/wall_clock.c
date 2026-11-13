// SPDX-License-Identifier: MPL-2.0

#include <stdio.h>
#include <time.h>

int main(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		perror("clock_gettime");
		return 1;
	}
	printf("CLOCK_REALTIME=%lld.%09ld\n", (long long)now.tv_sec, now.tv_nsec);
	return now.tv_sec > 1767225600 ? 0 : 1;
}
