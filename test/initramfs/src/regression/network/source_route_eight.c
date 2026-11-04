// SPDX-License-Identifier: MPL-2.0
#include "source_route_test.h"

FN_TEST(loose_source_route_reaches_the_first_gateway)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0)); if (fd < 0) { __TEST_SUMMARY(); return; }
 unsigned char options[36] = { 1, 131, 35, 4 }, readback[40] = {}; socklen_t option_len = sizeof(readback);
 for (int i=0;i<8;i++) { options[4+i*4]=192; options[6+i*4]=2; options[7+i*4]=1; }
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options)));
 TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_OPTIONS, readback, &option_len));
 TEST_RES(option_len, _ret == sizeof(options)); TEST_RES(memcmp(readback, options, sizeof(options)), _ret == 0);
 struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(42567), .sin_addr.s_addr = htonl(INADDR_ANY) };
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons(42568) }; inet_pton(AF_INET, "198.51.100.9", &peer.sin_addr);
 TEST_SUCC(bind(fd, (struct sockaddr *)&local, sizeof(local)));
 TEST_RES(sendto(fd, "lsrr-wire", 9, 0, (struct sockaddr *)&peer, sizeof(peer)), _ret == 9);
 struct pollfd ready = { .fd = fd, .events = POLLIN }; int result = TEST_RES(poll(&ready, 1, 4000), _ret == 1);
 if (result == 1) { char buf[32] = {}; TEST_RES(recv(fd, buf, sizeof(buf), 0), _ret == 10); TEST_RES(memcmp(buf, "lsrr-valid", 10), _ret == 0); }
 TEST_SUCC(close(fd));
}
END_TEST()
