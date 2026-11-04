// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "test.h"
FN_TEST(tcp_loopback_mark_preserves_route_mtu)
{
 int listener=TEST_SUCC(socket(AF_INET,SOCK_STREAM,0));struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};TEST_SUCC(bind(listener,(void *)&addr,sizeof(addr)));socklen_t len=sizeof(addr);TEST_SUCC(getsockname(listener,(void *)&addr,&len));TEST_SUCC(listen(listener,1));
 int sender=TEST_SUCC(socket(AF_INET,SOCK_STREAM,0));TEST_SUCC(connect(sender,(void *)&addr,sizeof(addr)));int receiver=TEST_SUCC(accept(listener,NULL,NULL));int mtu=0;socklen_t mtu_len=sizeof(mtu);TEST_SUCC(getsockopt(sender,IPPROTO_IP,IP_MTU,&mtu,&mtu_len));TEST_RES(mtu,_ret==65535);
 unsigned int mark=7;TEST_SUCC(setsockopt(sender,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)));mtu_len=sizeof(mtu);TEST_ERRNO(getsockopt(sender,IPPROTO_IP,IP_MTU,&mtu,&mtu_len),ENOTCONN);TEST_RES(send(sender,"x",1,0),_ret==1);char c=0;TEST_RES(recv(receiver,&c,1,0),_ret==1&&c=='x');mtu_len=sizeof(mtu);TEST_SUCC(getsockopt(sender,IPPROTO_IP,IP_MTU,&mtu,&mtu_len));TEST_RES(mtu,_ret==65535);TEST_SUCC(close(receiver));TEST_SUCC(close(sender));TEST_SUCC(close(listener));
}
END_TEST()
