// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <grp.h>
#include <errno.h>
#include <time.h>
#include <linux/errqueue.h>
#include <linux/fib_rules.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/if_addr.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/test.h"
#include "rtnl_common.h"

FN_SETUP(configure_ethernet_and_gateway)
{
	int control = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	struct ifreq request = {};
	strncpy(request.ifr_name, "eth0", IFNAMSIZ - 1);
	CHECK(ioctl(control, SIOCGIFFLAGS, &request));
	request.ifr_flags |= IFF_UP;
	CHECK(ioctl(control, SIOCSIFFLAGS, &request));
	CHECK(close(control));
	unsigned int index = CHECK_WITH(if_nametoindex("eth0"), _ret != 0);
	struct in_addr local, gateway;
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.100", &local), _ret == 1);
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.3", &gateway), _ret == 1);
	int fd = CHECK(rtnl_open(0));
	struct rtnl_reply reply;
	struct { struct ifaddrmsg body; uint8_t attributes[64]; } address = {
		.body = { .ifa_family = AF_INET, .ifa_prefixlen = 24, .ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = index }
	};
	size_t len = sizeof(address.body);
	len = rtnl_put(&address, len, IFA_LOCAL, &local, sizeof(local));
	len = rtnl_put(&address, len, IFA_ADDRESS, &local, sizeof(local));
	CHECK(rtnl_send(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			71, &address, len));
	CHECK(rtnl_receive(fd, &reply, 71));
	CHECK_WITH(reply.saw_error && !reply.error, _ret != 0);
	struct { struct rtmsg body; uint8_t attributes[64]; } route = {
		.body = { .rtm_family = AF_INET, .rtm_table = RT_TABLE_MAIN, .rtm_protocol = RTPROT_STATIC,
			.rtm_scope = RT_SCOPE_UNIVERSE, .rtm_type = RTN_UNICAST }
	};
	len = sizeof(route.body);
	len = rtnl_put(&route, len, RTA_GATEWAY, &gateway, sizeof(gateway));
	len = rtnl_put(&route, len, RTA_OIF, &index, sizeof(index));
	CHECK(rtnl_send(fd, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			72, &route, len));
	CHECK(rtnl_receive(fd, &reply, 72));
	CHECK_WITH(reply.saw_error && !reply.error, _ret != 0);
	CHECK(close(fd));
 int second = CHECK(socket(AF_INET, SOCK_DGRAM, 0)); struct ifreq second_request={}; strncpy(second_request.ifr_name,"eth1",IFNAMSIZ-1); CHECK(ioctl(second,SIOCGIFFLAGS,&second_request)); second_request.ifr_flags|=IFF_UP; CHECK(ioctl(second,SIOCSIFFLAGS,&second_request)); CHECK(close(second));
 unsigned int second_index=CHECK_WITH(if_nametoindex("eth1"),_ret!=0);struct in_addr second_local; CHECK_WITH(inet_pton(AF_INET,"192.0.3.100",&second_local),_ret==1); int second_nl=CHECK(rtnl_open(0)); struct rtnl_reply second_reply;
 struct {struct ifaddrmsg body;uint8_t attrs[64];} second_addr={.body={.ifa_family=AF_INET,.ifa_prefixlen=24,.ifa_scope=RT_SCOPE_UNIVERSE,.ifa_index=second_index}};size_t second_len=sizeof(second_addr.body);second_len=rtnl_put(&second_addr,second_len,IFA_LOCAL,&second_local,4);second_len=rtnl_put(&second_addr,second_len,IFA_ADDRESS,&second_local,4);
 CHECK(rtnl_send(second_nl,RTM_NEWADDR,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,73,&second_addr,second_len));CHECK(rtnl_receive(second_nl,&second_reply,73));CHECK_WITH(second_reply.saw_error&&!second_reply.error,_ret!=0);CHECK(close(second_nl));
}
END_SETUP()

FN_TEST(udp_mark_changes_interface_and_receives_pmtu)
{
 unsigned int index=if_nametoindex("eth1");struct in_addr network,gateway;inet_pton(AF_INET,"198.51.100.0",&network);inet_pton(AF_INET,"192.0.3.2",&gateway);
 int nl=TEST_SUCC(rtnl_open(0));if(nl<0){__TEST_SUMMARY();return;}struct rtnl_reply reply;
 struct{struct rtmsg body;uint8_t attrs[64];} route={.body={.rtm_family=AF_INET,.rtm_dst_len=24,.rtm_table=100,.rtm_protocol=RTPROT_STATIC,.rtm_scope=RT_SCOPE_UNIVERSE,.rtm_type=RTN_UNICAST}};
 size_t len=sizeof(route.body);len=rtnl_put(&route,len,RTA_DST,&network,4);len=rtnl_put(&route,len,RTA_GATEWAY,&gateway,4);len=rtnl_put(&route,len,RTA_OIF,&index,4);
 TEST_SUCC(rtnl_send(nl,RTM_NEWROUTE,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,130,&route,len));TEST_SUCC(rtnl_receive(nl,&reply,130));TEST_RES(reply.saw_error&&!reply.error,_ret!=0);
 struct{struct fib_rule_hdr body;uint8_t attrs[64];} rule={.body={.family=AF_INET,.table=100,.action=FR_ACT_TO_TBL}};uint32_t priority=100,mark=7,mask=255;len=sizeof(rule.body);
 len=rtnl_put(&rule,len,FRA_PRIORITY,&priority,4);len=rtnl_put(&rule,len,FRA_FWMARK,&mark,4);len=rtnl_put(&rule,len,FRA_FWMASK,&mask,4);
 TEST_SUCC(rtnl_send(nl,RTM_NEWRULE,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,131,&rule,len));TEST_SUCC(rtnl_receive(nl,&reply,131));TEST_RES(reply.saw_error&&!reply.error,_ret!=0);TEST_SUCC(close(nl));
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));if(fd<0){__TEST_SUMMARY();return;}
 struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"198.51.100.9",&dst.sin_addr);TEST_SUCC(connect(fd,(struct sockaddr *)&dst,sizeof(dst)));
 int mode=IP_PMTUDISC_DO,enabled=1,mtu=0;socklen_t len2=sizeof(mtu);TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_MTU_DISCOVER,&mode,sizeof(mode)));TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_RECVERR,&enabled,sizeof(enabled)));TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_PKTINFO,&enabled,sizeof(enabled)));
 int bound0=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0)),bound1=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));TEST_SUCC(setsockopt(bound0,SOL_SOCKET,SO_REUSEADDR,&enabled,sizeof(enabled)));TEST_SUCC(setsockopt(bound1,SOL_SOCKET,SO_REUSEADDR,&enabled,sizeof(enabled)));TEST_SUCC(setsockopt(bound0,SOL_SOCKET,SO_BINDTODEVICE,"eth0",5));TEST_SUCC(setsockopt(bound1,SOL_SOCKET,SO_BINDTODEVICE,"eth1",5));struct sockaddr_in bound={.sin_family=AF_INET,.sin_port=htons(42569),.sin_addr.s_addr=htonl(INADDR_ANY)};TEST_SUCC(bind(bound0,(void *)&bound,sizeof(bound)));TEST_SUCC(bind(bound1,(void *)&bound,sizeof(bound)));TEST_SUCC(setsockopt(bound1,IPPROTO_IP,IP_PKTINFO,&enabled,sizeof(enabled)));
 TEST_RES(send(fd,"ordinary",8,0),_ret==8);struct pollfd p={.fd=fd,.events=POLLIN};int ready=TEST_RES(poll(&p,1,3000),_ret==1);if(ready==1){char b[8];TEST_RES(recv(fd,b,sizeof(b),0),_ret==8&&!memcmp(b,"ordinary",8));}
 mark=0x107;TEST_SUCC(setsockopt(fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)));TEST_RES(send(fd,"changed!",8,0),_ret==8);ready=TEST_RES(poll(&p,1,3000),_ret==1);if(ready==1){char b[8],control[128];struct iovec iov={b,sizeof(b)};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};TEST_RES(recvmsg(fd,&msg,0),_ret==8&&!memcmp(b,"changed!",8));struct cmsghdr *c=CMSG_FIRSTHDR(&msg);TEST_RES(c,_ret&&_ret->cmsg_level==IPPROTO_IP&&_ret->cmsg_type==IP_PKTINFO);if(c){struct in_pktinfo *info=(void *)CMSG_DATA(c);TEST_RES(info->ipi_ifindex,_ret==(int)if_nametoindex("eth1"));TEST_RES(info->ipi_addr.s_addr,_ret==inet_addr("192.0.2.100"));TEST_RES(info->ipi_spec_dst.s_addr,_ret==inet_addr("192.0.2.100"));}}
 struct pollfd bp[2]={{.fd=bound0,.events=POLLIN},{.fd=bound1,.events=POLLIN}};TEST_RES(poll(bp,2,3000),_ret==1);TEST_RES((bp[0].revents&POLLIN)==0&&(bp[1].revents&POLLIN)!=0,_ret!=0);if(bp[1].revents&POLLIN){char b[8],control[128];struct iovec iov={b,sizeof(b)};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};TEST_RES(recvmsg(bound1,&msg,0),_ret==8&&!memcmp(b,"boundif!",8));struct cmsghdr *c=CMSG_FIRSTHDR(&msg);TEST_RES(c,_ret&&_ret->cmsg_type==IP_PKTINFO);if(c)TEST_RES(((struct in_pktinfo *)CMSG_DATA(c))->ipi_ifindex,_ret==(int)if_nametoindex("eth1"));}
 bp[0].revents=bp[1].revents=0;TEST_RES(poll(bp,2,3000),_ret==1);TEST_RES((bp[0].revents&POLLIN)==0&&(bp[1].revents&POLLIN)!=0,_ret!=0);if(bp[1].revents&POLLIN){char b[2000],control[128];struct iovec iov={b,sizeof(b)};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};TEST_RES(recvmsg(bound1,&msg,0),_ret==2000&&!memcmp(b,"fragtest",8));struct cmsghdr *c=CMSG_FIRSTHDR(&msg);TEST_RES(c,_ret&&_ret->cmsg_type==IP_PKTINFO);if(c)TEST_RES(((struct in_pktinfo *)CMSG_DATA(c))->ipi_ifindex,_ret==(int)if_nametoindex("eth1"));}TEST_SUCC(close(bound0));TEST_SUCC(close(bound1));
 p.events=POLLIN;ready=TEST_RES(poll(&p,1,3000),_ret==1);if(ready==1){char b[8];TEST_RES(recv(fd,b,sizeof(b),0),_ret==8&&!memcmp(b,"barrier!",8));}p.events=POLLERR;p.revents=0;TEST_RES(poll(&p,1,0),_ret==0);len2=sizeof(mtu);TEST_SUCC(getsockopt(fd,IPPROTO_IP,IP_MTU,&mtu,&len2));TEST_RES(mtu,_ret==1500);
 char data[900]={};memcpy(data,"mtu-test",8);TEST_RES(send(fd,data,sizeof(data),0),_ret==sizeof(data));p.events=POLLERR;ready=TEST_RES(poll(&p,1,3000),_ret==1);
 if(ready==1){char control[256],b[32];struct iovec iov={b,sizeof(b)};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};TEST_RES(recvmsg(fd,&msg,MSG_ERRQUEUE),_ret==8&&!memcmp(b,"mtu-test",8));struct cmsghdr *c=CMSG_FIRSTHDR(&msg);while(c&&(c->cmsg_level!=IPPROTO_IP||c->cmsg_type!=IP_RECVERR))c=CMSG_NXTHDR(&msg,c);TEST_RES(c,_ret!=NULL);if(c){struct sock_extended_err *e=(void *)CMSG_DATA(c);TEST_RES(e->ee_errno==EMSGSIZE&&e->ee_origin==SO_EE_ORIGIN_ICMP&&e->ee_type==3&&e->ee_code==4&&e->ee_info==600,_ret!=0);}}
 TEST_SUCC(getsockopt(fd,IPPROTO_IP,IP_MTU,&mtu,&len2));TEST_RES(mtu,_ret==600);int pending=0;socklen_t plen=sizeof(pending);TEST_SUCC(getsockopt(fd,SOL_SOCKET,SO_ERROR,&pending,&plen));TEST_ERRNO(send(fd,data,700,0),EMSGSIZE);
 mark=0;TEST_SUCC(setsockopt(fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)));TEST_RES(send(fd,"restored",8,0),_ret==8);p.events=POLLIN;ready=TEST_RES(poll(&p,1,3000),_ret==1);if(ready==1){char b[8];TEST_RES(recv(fd,b,sizeof(b),0),_ret==8&&!memcmp(b,"restored",8));}len2=sizeof(mtu);TEST_SUCC(getsockopt(fd,IPPROTO_IP,IP_MTU,&mtu,&len2));TEST_RES(mtu,_ret==1500);TEST_SUCC(close(fd));
}
END_TEST()
