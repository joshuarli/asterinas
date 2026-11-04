// SPDX-License-Identifier: MPL-2.0
#include "source_route_test.h"

FN_TEST(source_route_neighbor_failure_reports_first_hop)
{
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0));if(fd<0){__TEST_SUMMARY();return;}
 unsigned char options[8]={1,131,7,4,192,0,2,252};int enabled=1;
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_OPTIONS,options,sizeof(options)));
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_RECVERR,&enabled,sizeof(enabled)));
 struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"198.51.100.9",&dst.sin_addr);
 TEST_RES(sendto(fd,"probe",5,0,(struct sockaddr *)&dst,sizeof(dst)),_ret==5);
 struct pollfd event={.fd=fd,.events=POLLIN};int ready=TEST_RES(poll(&event,1,8000),_ret==1&&(event.revents&POLLERR));
 if(ready==1){
  char data[32]={};union{struct cmsghdr align;char bytes[128];}c={};struct sockaddr_in actual={};
  struct iovec io={.iov_base=data,.iov_len=sizeof(data)};struct msghdr msg={.msg_name=&actual,.msg_namelen=sizeof(actual),.msg_iov=&io,.msg_iovlen=1,.msg_control=c.bytes,.msg_controllen=sizeof(c.bytes)};
  TEST_RES(recvmsg(fd,&msg,MSG_ERRQUEUE),_ret==5&&!memcmp(data,"probe",5));
  TEST_RES(actual.sin_addr.s_addr,_ret==inet_addr("192.0.2.252"));TEST_RES(actual.sin_port,_ret==dst.sin_port);
  struct cmsghdr *h=CMSG_FIRSTHDR(&msg);TEST_RES(h,_ret&&_ret->cmsg_level==IPPROTO_IP&&_ret->cmsg_type==IP_RECVERR);
  if(h&&h->cmsg_len>=CMSG_LEN(sizeof(struct sock_extended_err))){struct sock_extended_err e;memcpy(&e,CMSG_DATA(h),sizeof(e));TEST_RES(e.ee_errno,_ret==EHOSTUNREACH&&e.ee_origin==SO_EE_ORIGIN_ICMP&&e.ee_type==3&&e.ee_code==1);}
 }
 TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(connected_source_route_does_not_report_neighbor_failure)
{
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0));if(fd<0){__TEST_SUMMARY();return;}
 unsigned char options[8]={1,131,7,4,192,0,2,253};int enabled=1;
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_OPTIONS,options,sizeof(options)));
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_RECVERR,&enabled,sizeof(enabled)));
 struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"198.51.100.9",&dst.sin_addr);
 TEST_SUCC(connect(fd,(struct sockaddr *)&dst,sizeof(dst)));TEST_RES(send(fd,"probe",5,0),_ret==5);
 struct pollfd event={.fd=fd,.events=POLLIN};TEST_RES(poll(&event,1,5000),_ret==0);
 TEST_SUCC(close(fd));
}
END_TEST()
