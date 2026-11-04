// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/test.h"
#include "rtnl_common.h"

static void exercise(const char *name, const char *source, const char *peer, const char *message)
{
 int __tests_passed=0,__tests_failed=0;
 int ctl=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0)); struct ifreq request={}; strncpy(request.ifr_name,name,IFNAMSIZ-1); TEST_SUCC(ioctl(ctl,SIOCGIFFLAGS,&request)); request.ifr_flags|=IFF_UP; TEST_SUCC(ioctl(ctl,SIOCSIFFLAGS,&request)); TEST_SUCC(close(ctl));
 unsigned int index=TEST_RES(if_nametoindex(name),_ret!=0); if(!index)return;
 struct in_addr address; inet_pton(AF_INET,source,&address); int nl=TEST_SUCC(rtnl_open(0));struct rtnl_reply reply;
 struct {struct ifaddrmsg body;uint8_t attrs[64];} msg={.body={.ifa_family=AF_INET,.ifa_prefixlen=24,.ifa_scope=RT_SCOPE_UNIVERSE,.ifa_index=index}};size_t len=sizeof(msg.body);len=rtnl_put(&msg,len,IFA_LOCAL,&address,4);len=rtnl_put(&msg,len,IFA_ADDRESS,&address,4);
 TEST_SUCC(rtnl_send(nl,RTM_NEWADDR,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,71,&msg,len));TEST_SUCC(rtnl_receive(nl,&reply,71));TEST_RES(reply.saw_error&&!reply.error,_ret!=0);TEST_SUCC(close(nl));
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,peer,&dst.sin_addr);TEST_RES(sendto(fd,message,8,0,(struct sockaddr *)&dst,sizeof(dst)),_ret==8);struct pollfd p={.fd=fd,.events=POLLIN};int ready=TEST_RES(poll(&p,1,3000),_ret==1);if(ready==1){char data[8];TEST_RES(recv(fd,data,sizeof(data),0),_ret==8&&!memcmp(data,message,8));}TEST_SUCC(close(fd));
 __TEST_SUMMARY();
}
FN_TEST(two_interfaces_are_independent)
{
 TEST_RES(if_nametoindex("eth0"),_ret!=0);TEST_RES(if_nametoindex("eth1"),_ret!=0);
 if(if_nametoindex("eth0")&&if_nametoindex("eth1")){exercise("eth0","192.0.2.100","192.0.2.1","firstnic");exercise("eth1","192.0.3.100","192.0.3.1","secondni");}
}
END_TEST()
