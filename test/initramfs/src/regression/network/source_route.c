// SPDX-License-Identifier: MPL-2.0
#include "source_route_test.h"

FN_TEST(loose_source_route_reaches_the_first_gateway)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0)); if (fd < 0) { __TEST_SUMMARY(); return; }
 unsigned char options[8] = { 1, 131, 7, 4, 192, 0, 2, 1 }, readback[40] = {}; socklen_t option_len = sizeof(readback);
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options)));
 TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_OPTIONS, readback, &option_len));
 TEST_RES(option_len, _ret == sizeof(options)); TEST_RES(memcmp(readback, options, sizeof(options)), _ret == 0);
 unsigned char invalid[8]; memcpy(invalid,options,sizeof(invalid));invalid[3]=3;
 TEST_ERRNO(setsockopt(fd,IPPROTO_IP,IP_OPTIONS,invalid,sizeof(invalid)),EINVAL);
 memset(readback,0,sizeof(readback));option_len=sizeof(readback);
 TEST_SUCC(getsockopt(fd,IPPROTO_IP,IP_OPTIONS,readback,&option_len));
 TEST_RES(option_len,_ret==sizeof(options));TEST_RES(memcmp(readback,options,sizeof(options)),_ret==0);
 struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(42567), .sin_addr.s_addr = htonl(INADDR_ANY) };
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons(42568) }; inet_pton(AF_INET, "198.51.100.9", &peer.sin_addr);
 TEST_SUCC(bind(fd, (struct sockaddr *)&local, sizeof(local)));
 TEST_RES(sendto(fd, "lsrr-wire", 9, 0, (struct sockaddr *)&peer, sizeof(peer)), _ret == 9);
 struct pollfd ready = { .fd = fd, .events = POLLIN }; int result = TEST_RES(poll(&ready, 1, 4000), _ret == 1);
 if (result == 1) { char buf[32] = {}; TEST_RES(recv(fd, buf, sizeof(buf), 0), _ret == 10); TEST_RES(memcmp(buf, "lsrr-valid", 10), _ret == 0); }
 TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(unprivileged_socket_cannot_set_loose_source_route)
{
 pid_t child = TEST_SUCC(fork());
 if (child == 0) {
  if (setgroups(0, NULL) || setresgid(65534,65534,65534) || setresuid(65534,65534,65534)) _exit(2);
  int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) _exit(3);
  unsigned char options[8] = { 1,131,7,4,192,0,2,1 };
  if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options)) != -1 || errno != EPERM) _exit(4);
  close(fd); _exit(0);
 }
 if (child > 0) { int status = 0; TEST_RES(waitpid(child, &status, 0), _ret == child); TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret == 1); }
}
END_TEST()

FN_TEST(source_route_broadcast_gateway_requires_broadcast_permission)
{
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));if(fd<0){__TEST_SUMMARY();return;}
 unsigned char options[8]={1,131,7,4,255,255,255,255};
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_OPTIONS,options,sizeof(options)));
 struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"198.51.100.9",&dst.sin_addr);
 TEST_SUCC(connect(fd,(struct sockaddr *)&dst,sizeof(dst)));
 TEST_ERRNO(sendto(fd,"route",5,0,(struct sockaddr *)&dst,sizeof(dst)),EACCES);
 TEST_SUCC(close(fd));
}
END_TEST()
