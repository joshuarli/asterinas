// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/test.h"

FN_TEST(debug_option_requires_privilege_to_enable)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0)); if (fd < 0) { __TEST_SUMMARY(); return; }
 int value = -1; socklen_t len = sizeof(value);
 TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_DEBUG, &value, &len)); TEST_RES(value, _ret == 0);
 value = 1; TEST_SUCC(setsockopt(fd, SOL_SOCKET, SO_DEBUG, &value, sizeof(value)));
 value = 0; TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_DEBUG, &value, &len)); TEST_RES(value, _ret == 1);
 pid_t child = TEST_SUCC(fork());
 if (child == 0) {
  if (setgroups(0, NULL) || setresgid(65534,65534,65534) || setresuid(65534,65534,65534)) _exit(2);
  int off = 0, on = 1;
  if (setsockopt(fd,SOL_SOCKET,SO_DEBUG,&off,sizeof(off))) _exit(3);
  if (setsockopt(fd,SOL_SOCKET,SO_DEBUG,&on,sizeof(on)) != -1 || errno != EACCES) _exit(4);
  _exit(0);
 }
 if (child > 0) { int status = 0; TEST_RES(waitpid(child, &status, 0), _ret == child); TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret == 1); }
 value = -1; TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_DEBUG, &value, &len)); TEST_RES(value, _ret == 0);
 TEST_SUCC(close(fd));
}
END_TEST()
