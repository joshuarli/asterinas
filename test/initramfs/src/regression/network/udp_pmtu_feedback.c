// SPDX-License-Identifier: MPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
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

FN_TEST(feedback_updates_path_mtu)
{
 int watcher = TEST_SUCC(socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL)));
 struct sockaddr_ll link = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = if_nametoindex("eth0") };
 TEST_SUCC(bind(watcher, (struct sockaddr *)&link, sizeof(link)));
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
 struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(39139) };
 TEST_RES(inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr), _ret == 1);
 int enabled = 1, mode = IP_PMTUDISC_DO, mtu = 0;
 socklen_t len = sizeof(mtu);
 TEST_ERRNO(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len), ENOTCONN);
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 TEST_SUCC(connect(fd, (struct sockaddr *)&dst, sizeof(dst)));
 len = sizeof(mtu);
 TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len));
 TEST_RES(mtu, _ret == 1500);
 char payload[900]; memset(payload, 0x5a, sizeof(payload));
 TEST_RES(send(fd, payload, sizeof(payload), 0), _ret == sizeof(payload));
 struct pollfd ready = { .fd = fd, .events = POLLIN };
 TEST_RES(poll(&ready, 1, 200), _ret == 0);
 len = sizeof(mtu); TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len)); TEST_RES(mtu, _ret == 1500);
 TEST_RES(send(fd, payload, sizeof(payload), 0), _ret == sizeof(payload));
 TEST_RES(poll(&ready, 1, 5000), _ret == 1 && (ready.revents & POLLERR));
 char received[900] = {}; union { struct cmsghdr align; char data[256]; } control = {};
 struct sockaddr_in quoted = {}; struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
 struct msghdr msg = { .msg_name = &quoted, .msg_namelen = sizeof(quoted), .msg_iov = &iov,
  .msg_iovlen = 1, .msg_control = control.data, .msg_controllen = sizeof(control.data) };
 TEST_RES(recvmsg(fd, &msg, MSG_ERRQUEUE), _ret == sizeof(payload) && !memcmp(payload, received, sizeof(payload)));
 TEST_RES(quoted.sin_port, _ret == dst.sin_port);
 struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
 TEST_RES(cmsg, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
 if (cmsg && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
  struct sock_extended_err err; memcpy(&err, CMSG_DATA(cmsg), sizeof(err));
  TEST_RES(err.ee_errno, _ret == EMSGSIZE); TEST_RES(err.ee_origin, _ret == SO_EE_ORIGIN_ICMP);
  TEST_RES(err.ee_type, _ret == ICMP_DEST_UNREACH); TEST_RES(err.ee_code, _ret == ICMP_FRAG_NEEDED);
  TEST_RES(err.ee_info, _ret == 600);
 }
 len = sizeof(mtu); TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len)); TEST_RES(mtu, _ret == 600);
 enabled = 0; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 TEST_ERRNO(send(fd, payload, 700, 0), EMSGSIZE);
 mode = IP_PMTUDISC_WANT; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 TEST_RES(send(fd, payload, 700, 0), _ret == 700);
 mode = IP_PMTUDISC_DONT; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 TEST_RES(send(fd, payload, 700, 0), _ret == 700);
 mode = IP_PMTUDISC_PROBE; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 TEST_RES(send(fd, payload, 700, 0), _ret == 700);
 int second = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
 TEST_SUCC(connect(second, (struct sockaddr *)&dst, sizeof(dst)));
 len = sizeof(mtu); TEST_SUCC(getsockopt(second, IPPROTO_IP, IP_MTU, &mtu, &len));
 TEST_RES(mtu, _ret == 600); TEST_SUCC(close(second));
 int first = 0, last = 0, probe = 0;
 for (int i = 0; i < 40 && (first < 2 || last < 2 || !probe); i++) {
  struct pollfd event = { .fd = watcher, .events = POLLIN };
  if (poll(&event, 1, 500) != 1) break;
  unsigned char frame[1600]; ssize_t size = recv(watcher, frame, sizeof(frame), 0);
  if (size < 34 || frame[12] != 8 || frame[13] != 0 || frame[23] != IPPROTO_UDP ||
      memcmp(frame + 30, &dst.sin_addr, 4)) continue;
  unsigned int flags = ((unsigned int)frame[20] << 8) | frame[21];
  if (size == 610 && flags == 0x2000 && frame[36] == (39139 >> 8) && frame[37] == (39139 & 255) &&
      !memcmp(frame + 42, payload, 568)) first++;
  if (size == 166 && flags == 72 && !memcmp(frame + 34, payload + 568, 132)) last++;
  if (size == 742 && flags == 0x4000 && frame[36] == (39139 >> 8) && frame[37] == (39139 & 255) &&
      !memcmp(frame + 42, payload, 700)) probe++;
 }
 TEST_RES(first, _ret == 2); TEST_RES(last, _ret == 2); TEST_RES(probe, _ret == 1);
 TEST_SUCC(close(watcher)); TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(dont_mode_ignores_fragmentation_error)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
 struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(39140) };
 TEST_RES(inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr), _ret == 1);
 int mode = IP_PMTUDISC_DONT, enabled = 1;
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));
 TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 TEST_SUCC(connect(fd, (struct sockaddr *)&dst, sizeof(dst)));
 char payload[500] = {};
 TEST_RES(send(fd, payload, sizeof(payload), 0), _ret == sizeof(payload));
 struct pollfd ready = { .fd = fd, .events = POLLIN };
 TEST_RES(poll(&ready, 1, 500), _ret == 0);
 int mtu = 0; socklen_t len = sizeof(mtu);
 TEST_SUCC(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len));
 TEST_RES(mtu, _ret == 552);
 TEST_SUCC(close(fd));
}
END_TEST()
