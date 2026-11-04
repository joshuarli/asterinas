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

FN_TEST(socket_mark_drives_masked_policy_route)
{
 int netlink=TEST_SUCC(rtnl_open(0));if(netlink<0){__TEST_SUMMARY();return;}
 struct {struct fib_rule_hdr body;uint8_t attributes[64];} rule={.body={.family=AF_INET,.action=FR_ACT_PROHIBIT}};
 size_t len=sizeof(rule.body);uint32_t priority=100,mark=7,mask=255;
 len=rtnl_put(&rule,len,FRA_PRIORITY,&priority,sizeof(priority));len=rtnl_put(&rule,len,FRA_FWMARK,&mark,sizeof(mark));len=rtnl_put(&rule,len,FRA_FWMASK,&mask,sizeof(mask));
 TEST_SUCC(rtnl_send(netlink,RTM_NEWRULE,NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL,120,&rule,len));
 struct rtnl_reply reply;TEST_SUCC(rtnl_receive(netlink,&reply,120));TEST_RES(reply.saw_error && !reply.error,_ret!=0);TEST_SUCC(close(netlink));
 int fd=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));if(fd<0){__TEST_SUMMARY();return;}
 struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(42567),.sin_addr.s_addr=htonl(INADDR_ANY)};
 struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"192.0.2.1",&dst.sin_addr);
 TEST_SUCC(bind(fd,(struct sockaddr *)&local,sizeof(local)));TEST_SUCC(connect(fd,(struct sockaddr *)&dst,sizeof(dst)));
 uint32_t got=99;socklen_t gotlen=sizeof(got);TEST_SUCC(getsockopt(fd,SOL_SOCKET,SO_MARK,&got,&gotlen));TEST_RES(got,_ret==0);
 TEST_RES(send(fd,"ordinary",8,0),_ret==8);struct pollfd p={.fd=fd,.events=POLLIN};
 int ready=TEST_RES(poll(&p,1,2000),_ret==1);if(ready==1){char data[32]={};TEST_RES(recv(fd,data,sizeof(data),0),_ret==8&&!memcmp(data,"ordinary",8));}
 mark=0x107;TEST_SUCC(setsockopt(fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)));
 TEST_SUCC(getsockopt(fd,SOL_SOCKET,SO_MARK,&got,&gotlen));TEST_RES(got,_ret==0x107);
 TEST_ERRNO(send(fd,"blocked",7,0),EACCES);
 TEST_ERRNO(send(fd,"blocked",7,MSG_DONTROUTE),EACCES);
 int constrained=TEST_SUCC(socket(AF_INET,SOCK_DGRAM,0));
 TEST_SUCC(setsockopt(constrained,SOL_SOCKET,SO_BINDTODEVICE,"eth0",5));
 TEST_SUCC(setsockopt(constrained,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)));
 TEST_RES(sendto(constrained,"device-0",8,0,(struct sockaddr *)&dst,sizeof(dst)),_ret==8);
 struct pollfd q={.fd=constrained,.events=POLLIN}; ready=TEST_RES(poll(&q,1,2000),_ret==1);
 if(ready==1){char data[32]={};TEST_RES(recv(constrained,data,sizeof(data),0),_ret==8&&!memcmp(data,"device-0",8));}
 TEST_RES(sendto(constrained,"device-1",8,MSG_DONTROUTE,(struct sockaddr *)&dst,sizeof(dst)),_ret==8);
 ready=TEST_RES(poll(&q,1,2000),_ret==1);
 if(ready==1){char data[32]={};TEST_RES(recv(constrained,data,sizeof(data),0),_ret==8&&!memcmp(data,"device-1",8));}
 TEST_SUCC(close(constrained));
 mark=8;TEST_SUCC(setsockopt(fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)));
 TEST_RES(send(fd,"unmasked",8,0),_ret==8);ready=TEST_RES(poll(&p,1,2000),_ret==1);
 if(ready==1){char data[32]={};TEST_RES(recv(fd,data,sizeof(data),0),_ret==8&&!memcmp(data,"unmasked",8));}
 pid_t child=TEST_SUCC(fork());if(child==0){
  if(setgroups(0,NULL)||setresgid(65534,65534,65534)||setresuid(65534,65534,65534))_exit(2);
  uint32_t value=0;if(setsockopt(fd,SOL_SOCKET,SO_MARK,&value,sizeof(value))!=-1||errno!=EPERM)_exit(3);_exit(0);
 }
 if(child>0){int status=0;TEST_RES(waitpid(child,&status,0),_ret==child);TEST_RES(WIFEXITED(status)&&WEXITSTATUS(status)==0,_ret==1);}
 pid_t raw_child=TEST_SUCC(fork());if(raw_child==0){
  if(prctl(PR_SET_KEEPCAPS,1)||setgroups(0,NULL)||setresgid(65534,65534,65534)||setresuid(65534,65534,65534))_exit(2);
  struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
  struct __user_cap_data_struct caps[2]={};caps[0].effective=1U<<CAP_NET_RAW;caps[0].permitted=1U<<CAP_NET_RAW;
  if(syscall(SYS_capset,&h,caps))_exit(3);
  uint32_t value=8;if(setsockopt(fd,SOL_SOCKET,SO_MARK,&value,sizeof(value)))_exit(4);_exit(0);
 }
 if(raw_child>0){int status=0;TEST_RES(waitpid(raw_child,&status,0),_ret==raw_child);TEST_RES(WIFEXITED(status)&&WEXITSTATUS(status)==0,_ret==1);}
 TEST_SUCC(close(fd));
}
END_TEST()
