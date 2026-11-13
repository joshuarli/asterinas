// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

FN_TEST(unshare_namespaces_without_privilege)
{
	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresgid(1000, 1000, 1000));
		CHECK(setresuid(1000, 1000, 1000));

		CHECK_WITH(unshare(CLONE_NEWUTS), _ret == -1 && errno == EPERM);
		CHECK_WITH(unshare(CLONE_NEWIPC), _ret == -1 && errno == EPERM);
		CHECK_WITH(unshare(CLONE_NEWNET), _ret == -1 && errno == EPERM);
		CHECK_WITH(unshare(CLONE_NEWNET | CLONE_NEWUTS),
			   _ret == -1 && errno == EPERM);

		_exit(EXIT_SUCCESS);
	}

	int status;
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
}
END_TEST()
