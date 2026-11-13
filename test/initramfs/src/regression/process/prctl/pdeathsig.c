// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>

int main(void)
{
    int sig = -1;
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) ||
        prctl(PR_GET_PDEATHSIG, &sig) || sig != SIGTERM ||
        prctl(PR_SET_PDEATHSIG, 0) ||
        prctl(PR_GET_PDEATHSIG, &sig) || sig != 0) {
        perror("parent death signal");
        return 1;
    }
    errno = 0;
    if (prctl(PR_SET_PDEATHSIG, 256) != -1 || errno != EINVAL) {
        fprintf(stderr, "invalid parent death signal accepted\n");
        return 1;
    }
    return 0;
}
