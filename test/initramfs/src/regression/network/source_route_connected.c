// SPDX-License-Identifier: MPL-2.0
#include "source_route_test.h"

FN_TEST(connected_source_route_does_not_report_gateway_error)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)); if (fd < 0) { __TEST_SUMMARY(); return; }
 unsigned char options[8] = { 1,131,7,4,192,0,2,1 }; int enabled=1;
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options)));
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 struct sockaddr_in local = { .sin_family=AF_INET, .sin_port=htons(42567), .sin_addr.s_addr=htonl(INADDR_ANY) };
 struct sockaddr_in dst = { .sin_family=AF_INET, .sin_port=htons(42568) }; inet_pton(AF_INET, "198.51.100.9", &dst.sin_addr);
 TEST_SUCC(bind(fd,(struct sockaddr *)&local,sizeof(local)));
 TEST_SUCC(connect(fd,(struct sockaddr *)&dst,sizeof(dst)));
 TEST_RES(send(fd,"lsrr-wire",9,0), _ret == 9);
 struct pollfd p = { .fd=fd, .events=POLLIN };
 TEST_RES(poll(&p,1,1200), _ret == 0);
 TEST_SUCC(close(fd));
}
END_TEST()
