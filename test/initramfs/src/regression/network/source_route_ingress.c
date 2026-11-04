// SPDX-License-Identifier: MPL-2.0
#include "source_route_test.h"

FN_TEST(unprocessed_source_route_is_not_delivered)
{
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));if(fd<0){__TEST_SUMMARY();return;}
 struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(42567),.sin_addr.s_addr=htonl(INADDR_ANY)};
 struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"192.0.2.1",&peer.sin_addr);
 TEST_SUCC(bind(fd,(struct sockaddr *)&local,sizeof(local)));TEST_RES(sendto(fd,"start",5,0,(struct sockaddr *)&peer,sizeof(peer)),_ret==5);
 struct pollfd p={.fd=fd,.events=POLLIN};int r=TEST_RES(poll(&p,1,4000),_ret==1);
 if(r==1){char bytes[64]={};TEST_RES(recv(fd,bytes,sizeof(bytes),0),_ret==4&&!memcmp(bytes,"done",4));}
 TEST_RES(poll(&p,1,200),_ret==0);TEST_SUCC(close(fd));
}
END_TEST()
