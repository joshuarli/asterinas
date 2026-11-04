// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <grp.h>
#include <errno.h>
#include <fcntl.h>
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

static unsigned short checksum(const unsigned char *data, size_t len)
{
 unsigned int sum=0; while(len>=2){sum+=(data[0]<<8)|data[1];data+=2;len-=2;} if(len)sum+=data[0]<<8; while(sum>>16)sum=(sum&65535)+(sum>>16); return ~sum;
}

FN_TEST(ping_mark_changes_interface_and_receives_reply)
{
 unsigned int index=if_nametoindex("eth1");struct in_addr network,gateway;inet_pton(AF_INET,"198.51.100.0",&network);inet_pton(AF_INET,"192.0.3.2",&gateway);
 int nl=TEST_SUCC(rtnl_open(0));if(nl<0){__TEST_SUMMARY();return;}struct rtnl_reply reply;
 struct{struct rtmsg body;uint8_t attrs[64];} route={.body={.rtm_family=AF_INET,.rtm_dst_len=24,.rtm_table=100,.rtm_protocol=RTPROT_STATIC,.rtm_scope=RT_SCOPE_UNIVERSE,.rtm_type=RTN_UNICAST}};
 size_t len=sizeof(route.body);len=rtnl_put(&route,len,RTA_DST,&network,4);len=rtnl_put(&route,len,RTA_GATEWAY,&gateway,4);len=rtnl_put(&route,len,RTA_OIF,&index,4);
 TEST_SUCC(rtnl_send(nl,RTM_NEWROUTE,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,130,&route,len));TEST_SUCC(rtnl_receive(nl,&reply,130));TEST_RES(reply.saw_error&&!reply.error,_ret!=0);
 struct{struct fib_rule_hdr body;uint8_t attrs[64];} rule={.body={.family=AF_INET,.table=100,.action=FR_ACT_TO_TBL}};uint32_t priority=100,mark=7,mask=255;len=sizeof(rule.body);
 len=rtnl_put(&rule,len,FRA_PRIORITY,&priority,4);len=rtnl_put(&rule,len,FRA_FWMARK,&mark,4);len=rtnl_put(&rule,len,FRA_FWMASK,&mask,4);
 TEST_SUCC(rtnl_send(nl,RTM_NEWRULE,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,131,&rule,len));TEST_SUCC(rtnl_receive(nl,&reply,131));TEST_RES(reply.saw_error&&!reply.error,_ret!=0);TEST_SUCC(close(nl));
 int range=TEST_SUCC(open("/proc/sys/net/ipv4/ping_group_range",O_WRONLY));TEST_RES(write(range,"0 2147483647",12),_ret==12);TEST_SUCC(close(range));
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP));if(fd<0){__TEST_SUMMARY();return;}
 struct sockaddr_in dst={.sin_family=AF_INET};inet_pton(AF_INET,"198.51.100.9",&dst.sin_addr);
 TEST_SUCC(connect(fd,(struct sockaddr *)&dst,sizeof(dst))); unsigned char packet[16]={8,0,0,0,0x23,0x45,0,1}; memcpy(packet+8,"ordinary",8);
 unsigned short sum=checksum(packet,sizeof(packet));packet[2]=sum>>8;packet[3]=sum;TEST_RES(send(fd,packet,sizeof(packet),0),_ret==sizeof(packet));
 struct pollfd p={.fd=fd,.events=POLLIN};int ready=TEST_RES(poll(&p,1,3000),_ret==1);
 if(ready==1){unsigned char b[128]={};int n=TEST_SUCC(recv(fd,b,sizeof(b),0));TEST_RES(n,_ret==16);if(n==16)TEST_RES(b[0]==0&&!memcmp(b+8,"ordinary",8),_ret!=0);}
 mark=0x107;TEST_SUCC(setsockopt(fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)));
 uint32_t actual=0;socklen_t actual_len=sizeof(actual);TEST_SUCC(getsockopt(fd,SOL_SOCKET,SO_MARK,&actual,&actual_len));TEST_RES(actual,_ret==mark);
 pid_t child=TEST_SUCC(fork());if(child==0){if(setgroups(0,NULL)||setresgid(65534,65534,65534)||setresuid(65534,65534,65534))_exit(2);uint32_t value=0;if(setsockopt(fd,SOL_SOCKET,SO_MARK,&value,sizeof(value))!=-1||errno!=EPERM)_exit(3);_exit(0);}
 if(child>0){int status=0;TEST_RES(waitpid(child,&status,0),_ret==child);TEST_RES(WIFEXITED(status)&&WEXITSTATUS(status)==0,_ret==1);}
 memcpy(packet+8,"marked-7",8);packet[2]=packet[3]=0;sum=checksum(packet,sizeof(packet));packet[2]=sum>>8;packet[3]=sum;
 TEST_RES(send(fd,packet,sizeof(packet),0),_ret==sizeof(packet));ready=TEST_RES(poll(&p,1,3000),_ret==1);
 if(ready==1){unsigned char b[128]={};int n=TEST_SUCC(recv(fd,b,sizeof(b),0));TEST_RES(n,_ret==16);if(n==16)TEST_RES(b[0]==0&&!memcmp(b+8,"marked-7",8),_ret!=0);}
 TEST_SUCC(close(fd));
}
END_TEST()
