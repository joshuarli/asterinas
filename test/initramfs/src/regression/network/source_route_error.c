// SPDX-License-Identifier: MPL-2.0
#include "source_route_test.h"

FN_TEST(loose_source_route_reports_quoted_gateway_error)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)); if (fd < 0) { __TEST_SUMMARY(); return; }
 unsigned char options[8] = { 1,131,7,4,192,0,2,1 }; int enabled=1;
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options)));
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 struct sockaddr_in local = { .sin_family=AF_INET, .sin_port=htons(42567), .sin_addr.s_addr=htonl(INADDR_ANY) };
 struct sockaddr_in dst = { .sin_family=AF_INET, .sin_port=htons(42568) }; inet_pton(AF_INET, "198.51.100.9", &dst.sin_addr);
 TEST_SUCC(bind(fd,(struct sockaddr *)&local,sizeof(local)));
 TEST_RES(sendto(fd,"lsrr-wire",9,0,(struct sockaddr *)&dst,sizeof(dst)), _ret == 9);
 struct pollfd p = { .fd=fd, .events=POLLIN }; int ready=TEST_RES(poll(&p,1,4000), _ret == 1 && (p.revents & POLLERR));
 if (ready == 1) {
  char payload[64] = {}; union { struct cmsghdr align; char bytes[128]; } c = {};
  struct sockaddr_in reported = {}; struct iovec io = { .iov_base=payload, .iov_len=sizeof(payload) };
  struct msghdr msg = { .msg_name=&reported,.msg_namelen=sizeof(reported),.msg_iov=&io,.msg_iovlen=1,.msg_control=c.bytes,.msg_controllen=sizeof(c.bytes) };
  TEST_RES(recvmsg(fd,&msg,MSG_ERRQUEUE), _ret == 9 && !memcmp(payload,"lsrr-wire",9));
  TEST_RES(reported.sin_addr.s_addr, _ret == inet_addr("192.0.2.1"));
  struct cmsghdr *h=CMSG_FIRSTHDR(&msg); TEST_RES(h, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
  if (h && h->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
   struct sock_extended_err e; memcpy(&e,CMSG_DATA(h),sizeof(e));
   TEST_RES(e.ee_errno, _ret == EHOSTUNREACH); TEST_RES(e.ee_origin, _ret == SO_EE_ORIGIN_ICMP);
   TEST_RES(e.ee_type, _ret == ICMP_TIME_EXCEEDED && e.ee_code == ICMP_EXC_TTL);
  }
 }
 TEST_SUCC(close(fd));
}
END_TEST()
