// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <grp.h>
#include <errno.h>
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
	CHECK_WITH(inet_pton(AF_INET, "192.0.2.1", &gateway), _ret == 1);
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
}
END_SETUP()

FN_TEST(policy_route_learns_path_mtu_from_feedback)
{
 unsigned int index=if_nametoindex("eth0");struct in_addr network,gateway;inet_pton(AF_INET,"198.51.100.0",&network);inet_pton(AF_INET,"192.0.2.2",&gateway);
 int nl=TEST_SUCC(rtnl_open(0));if(nl<0){__TEST_SUMMARY();return;}struct rtnl_reply reply;
 struct{struct rtmsg body;uint8_t attrs[64];} route={.body={.rtm_family=AF_INET,.rtm_dst_len=24,.rtm_table=100,.rtm_protocol=RTPROT_STATIC,.rtm_scope=RT_SCOPE_UNIVERSE,.rtm_type=RTN_UNICAST}};
 size_t len=sizeof(route.body);len=rtnl_put(&route,len,RTA_DST,&network,4);len=rtnl_put(&route,len,RTA_GATEWAY,&gateway,4);len=rtnl_put(&route,len,RTA_OIF,&index,4);
 TEST_SUCC(rtnl_send(nl,RTM_NEWROUTE,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,130,&route,len));TEST_SUCC(rtnl_receive(nl,&reply,130));TEST_RES(reply.saw_error&&!reply.error,_ret!=0);
 struct{struct fib_rule_hdr body;uint8_t attrs[64];} rule={.body={.family=AF_INET,.table=100,.action=FR_ACT_TO_TBL}};uint32_t priority=100,mark=0,mask=255;len=sizeof(rule.body);
 len=rtnl_put(&rule,len,FRA_PRIORITY,&priority,4);len=rtnl_put(&rule,len,FRA_FWMARK,&mark,4);len=rtnl_put(&rule,len,FRA_FWMASK,&mask,4);
 TEST_SUCC(rtnl_send(nl,RTM_NEWRULE,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,131,&rule,len));TEST_SUCC(rtnl_receive(nl,&reply,131));TEST_RES(reply.saw_error&&!reply.error,_ret!=0);TEST_SUCC(close(nl));
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));if(fd<0){__TEST_SUMMARY();return;}
 struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(42567),.sin_addr.s_addr=htonl(INADDR_ANY)},dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"198.51.100.9",&dst.sin_addr);
 int enabled=1, mode=IP_PMTUDISC_DO, mtu=0; socklen_t mlen=sizeof(mtu); char data[900]={};
 TEST_SUCC(bind(fd,(struct sockaddr *)&local,sizeof(local))); TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_RECVERR,&enabled,sizeof(enabled))); TEST_SUCC(setsockopt(fd,IPPROTO_IP,IP_MTU_DISCOVER,&mode,sizeof(mode))); TEST_SUCC(connect(fd,(struct sockaddr *)&dst,sizeof(dst)));
 TEST_SUCC(getsockopt(fd,IPPROTO_IP,IP_MTU,&mtu,&mlen)); TEST_RES(mtu,_ret==1500);
 TEST_RES(send(fd,data,sizeof(data),0),_ret==sizeof(data)); struct pollfd p={.fd=fd,.events=POLLERR}; int ready=TEST_RES(poll(&p,1,3000),_ret==1);
 if(ready==1){char c[256],b[900];struct iovec iov={b,sizeof(b)};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=c,.msg_controllen=sizeof(c)};TEST_RES(recvmsg(fd,&msg,MSG_ERRQUEUE),_ret>0);}
 mlen=sizeof(mtu); TEST_SUCC(getsockopt(fd,IPPROTO_IP,IP_MTU,&mtu,&mlen)); TEST_RES(mtu,_ret==600);
 TEST_ERRNO(send(fd,data,700,0),EMSGSIZE); TEST_SUCC(close(fd));
}
END_TEST()
