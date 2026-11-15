// SPDX-License-Identifier: MPL-2.0

#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>

#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif

int main(void)
{
    unsigned long auxv[128] = {0};
    long size = prctl(PR_GET_AUXV, auxv, sizeof(auxv), 0UL, 0UL);
    if (size <= 0 || (unsigned long)size > sizeof(auxv)) {
        perror("PR_GET_AUXV");
        return 1;
    }
    int pagesz = 0, random = 0, end = 0;
    for (long i = 0; i + 1 < size / (long)sizeof(auxv[0]); i += 2) {
        if (auxv[i] == AT_NULL) { end = 1; break; }
        if (auxv[i] == AT_PAGESZ && auxv[i + 1] == getauxval(AT_PAGESZ)) pagesz = 1;
        if (auxv[i] == AT_RANDOM && auxv[i + 1] == getauxval(AT_RANDOM)) random = 1;
    }
    unsigned long prefix[2] = {0};
    long short_size = prctl(PR_GET_AUXV, prefix, sizeof(prefix), 0UL, 0UL);
    errno = 0;
    long invalid = prctl(PR_GET_AUXV, auxv, sizeof(auxv), 1UL, 0UL);
    if (!pagesz || !random || !end || short_size != size || memcmp(prefix, auxv, sizeof(prefix)) || invalid != -1 || errno != EINVAL) {
        printf("auxv validation failed: size=%ld short=%ld pagesz=%d random=%d end=%d invalid=%ld errno=%d\n", size, short_size, pagesz, random, end, invalid, errno);
        return 1;
    }
    printf("PR_GET_AUXV PASS size=%ld\n", size);
    return 0;
}
