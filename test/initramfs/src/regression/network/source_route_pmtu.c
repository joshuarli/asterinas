// SPDX-License-Identifier: MPL-2.0
#include "source_route_test.h"

FN_TEST(source_route_uses_gateway_path_mtu)
{
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0));if(fd<0){__TEST_SUMMARY();return;}
 unsigned char options[8]={1,131,7,4,192,0,2,1};int enabled=1,mode=IP_PMTUDISC_DO;
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_OPTIONS,options,sizeof(options)));
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_RECVERR,&enabled,sizeof(enabled)));
 TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_MTU_DISCOVER,&mode,sizeof(mode)));
 struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(42567),.sin_addr.s_addr=htonl(INADDR_ANY)};
 struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"198.51.100.9",&dst.sin_addr);
 TEST_SUCC(bind(fd,(struct sockaddr *)&local,sizeof(local)));
 unsigned char data[900]={};memcpy(data,"lsrr-wire",9);
 TEST_RES(sendto(fd,data,sizeof(data),0,(struct sockaddr *)&dst,sizeof(dst)),_ret==sizeof(data));
 struct pollfd p={.fd=fd,.events=POLLIN};int ready=TEST_RES(poll(&p,1,4000),_ret==1&&(p.revents&POLLERR));
 if(ready==1){
  unsigned char out[900]={};union{struct cmsghdr align;char bytes[128];}c={};
  struct sockaddr_in reported={};struct iovec io={.iov_base=out,.iov_len=sizeof(out)};
  struct msghdr msg={.msg_name=&reported,.msg_namelen=sizeof(reported),.msg_iov=&io,.msg_iovlen=1,.msg_control=c.bytes,.msg_controllen=sizeof(c.bytes)};
  TEST_RES(recvmsg(fd,&msg,MSG_ERRQUEUE),_ret==sizeof(data)&&!memcmp(out,data,sizeof(data)));
  struct cmsghdr *h=CMSG_FIRSTHDR(&msg);TEST_RES(h,_ret&&_ret->cmsg_level==IPPROTO_IP&&_ret->cmsg_type==IP_RECVERR);
  if(h&&h->cmsg_len>=CMSG_LEN(sizeof(struct sock_extended_err))){struct sock_extended_err e;memcpy(&e,CMSG_DATA(h),sizeof(e));TEST_RES(e.ee_errno,_ret==EMSGSIZE&&e.ee_info==600);}
  int observer=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));
  if(observer>=0){
   TEST_SUCC(setsockopt(observer,IPPROTO_IP,IP_OPTIONS,options,sizeof(options)));
   TEST_SUCC(connect(observer,(struct sockaddr *)&dst,sizeof(dst)));
   int mtu=0;socklen_t len=sizeof(mtu);TEST_SUCC(getsockopt(observer,IPPROTO_IP,IP_MTU,&mtu,&len));TEST_RES(mtu,_ret==1500);
   TEST_SUCC(close(observer));
  }
  TEST_ERRNO(sendto(fd,data,700,0,(struct sockaddr *)&dst,sizeof(dst)),EMSGSIZE);
 }
 TEST_SUCC(close(fd));
}
END_TEST()
