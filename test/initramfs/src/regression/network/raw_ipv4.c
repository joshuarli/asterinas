// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/test.h"

static uint16_t checksum(const void *data, size_t length)
{
 const unsigned char *bytes = data; uint32_t sum = 0;
 while (length >= 2) { sum += ((uint16_t)bytes[0] << 8) | bytes[1]; bytes += 2; length -= 2; }
 if (length) sum += (uint16_t)bytes[0] << 8;
 while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
 return htons((uint16_t)~sum);
}

FN_TEST(raw_icmp_echo_roundtrip_and_protocol_demux)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));
 if (fd < 0) { __TEST_SUMMARY(); return; }
 int other = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));
 if (other < 0) { close(fd); __TEST_SUMMARY(); return; }
 int tos = 16; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 struct { struct icmphdr header; char data[8]; } request = {
  .header = { .type = ICMP_ECHO, .un.echo = { .id = htons(4982), .sequence = htons(7) } }, .data = "request" };
 request.header.checksum = checksum(&request, sizeof(request));
 TEST_RES(sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&peer, sizeof(peer)), _ret == sizeof(request));
 int seen_request = 0, seen_reply = 0;
 for (int i = 0; i < 8 && !(seen_request && seen_reply); i++) {
  struct pollfd ready = { .fd = fd, .events = POLLIN }; if (poll(&ready, 1, 1000) != 1) break;
  unsigned char bytes[512]; struct sockaddr_in sender = {}; socklen_t len = sizeof(sender);
  ssize_t n = recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr *)&sender, &len);
  if (n < 20 + (ssize_t)sizeof(request) || (bytes[0] >> 4) != 4 || (bytes[0] & 15) != 5 || bytes[9] != IPPROTO_ICMP) continue;
  struct icmphdr *icmp = (struct icmphdr *)(bytes + 20);
  if (sender.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || checksum(bytes, 20) || checksum(icmp, sizeof(request)) ||
      icmp->un.echo.id != htons(4982) || icmp->un.echo.sequence != htons(7) || memcmp(bytes + 28, request.data, 8)) continue;
  if (icmp->type == ICMP_ECHO) seen_request = 1;
  if (icmp->type == ICMP_ECHOREPLY && bytes[1] == 16) seen_reply = 1;
 }
 TEST_RES(seen_request, _ret == 1); TEST_RES(seen_reply, _ret == 1);
 struct pollfd other_ready = { .fd = other, .events = POLLIN }; TEST_RES(poll(&other_ready, 1, 100), _ret == 0);
 TEST_SUCC(close(other)); TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(invalid_echo_checksum_is_not_answered)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP)); if (fd < 0) { __TEST_SUMMARY(); return; }
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 struct { struct icmphdr header; char data[8]; } request = {
  .header = { .type = ICMP_ECHO, .un.echo = { .id = htons(9123), .sequence = htons(8) } }, .data = "invalid" };
 request.header.checksum = checksum(&request, sizeof(request)) ^ 1;
 TEST_RES(sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&peer, sizeof(peer)), _ret == sizeof(request));
 struct pollfd ready = { .fd = fd, .events = POLLIN }; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char bytes[128]; ssize_t n = recv(fd, bytes, sizeof(bytes), 0);
 TEST_RES(n, _ret == 36 && bytes[20] == ICMP_ECHO);
 TEST_RES(poll(&ready, 1, 100), _ret == 0); TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(raw_icmp_receives_udp_error_without_consuming_it)
{
 int raw = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP)); if (raw < 0) { __TEST_SUMMARY(); return; }
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0)); TEST_SUCC(bind(receiver, (struct sockaddr *)&peer, sizeof(peer)));
 socklen_t len = sizeof(peer); TEST_SUCC(getsockname(receiver, (struct sockaddr *)&peer, &len)); TEST_SUCC(close(receiver));
 TEST_SUCC(connect(fd, (struct sockaddr *)&peer, sizeof(peer)));
 struct sockaddr_in local; len = sizeof(local); TEST_SUCC(getsockname(fd, (struct sockaddr *)&local, &len));
 TEST_RES(send(fd, "probe", 5, 0), _ret == 5);
 struct pollfd ready = { .fd = raw, .events = POLLIN }; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char bytes[1024]; ssize_t n = recv(raw, bytes, sizeof(bytes), 0); int valid = 0;
 if (n >= 56 && (bytes[0] >> 4) == 4 && bytes[9] == IPPROTO_ICMP && !checksum(bytes, (bytes[0] & 15) * 4)) {
  size_t h = (bytes[0] & 15) * 4; unsigned char *icmp = bytes + h;
  if (h >= 20 && n >= (ssize_t)(h + 8 + 20 + 8) && icmp[0] == ICMP_DEST_UNREACH && icmp[1] == ICMP_PORT_UNREACH && !checksum(icmp, n - h)) {
   unsigned char *quoted = icmp + 8; size_t inner = (quoted[0] & 15) * 4;
   if (inner >= 20 && n >= (ssize_t)(h + 8 + inner + 8) && quoted[9] == IPPROTO_UDP) {
    struct udphdr udp; memcpy(&udp, quoted + inner, sizeof(udp)); valid = udp.source == local.sin_port && udp.dest == peer.sin_port;
   }
  }
 }
 TEST_RES(valid, _ret == 1);
 int error = 0; len = sizeof(error); TEST_SUCC(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)); TEST_RES(error, _ret == ECONNREFUSED);
 TEST_SUCC(close(fd)); TEST_SUCC(close(raw));
}
END_TEST()

FN_TEST(raw_udp_receives_the_ip_datagram_without_consuming_udp)
{
 int raw = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP)); if (raw < 0) { __TEST_SUMMARY(); return; }
 int receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0)); int sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
 struct sockaddr_in destination = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 TEST_SUCC(bind(receiver, (struct sockaddr *)&destination, sizeof(destination)));
 socklen_t len = sizeof(destination); TEST_SUCC(getsockname(receiver, (struct sockaddr *)&destination, &len));
 int enabled = 1; TEST_SUCC(setsockopt(raw, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled)));
 TEST_RES(sendto(sender, "raw-udp", 7, 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == 7);
 struct pollfd ready = { .fd = raw, .events = POLLIN }; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char data[128] = {}; union { struct cmsghdr align; char bytes[128]; } control = {};
 struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
 struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
 ssize_t n = recvmsg(raw, &msg, MSG_CMSG_CLOEXEC | MSG_TRUNC); int valid = 0, stamped = 0;
 if (n == 35 && data[0] == 0x45 && data[9] == IPPROTO_UDP && !memcmp(data + 28, "raw-udp", 7)) {
  struct udphdr udp; memcpy(&udp, data + 20, sizeof(udp)); valid = udp.dest == destination.sin_port;
 }
 for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
  if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPNS && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timespec))) stamped = 1;
 TEST_RES(valid, _ret == 1); TEST_RES(stamped, _ret == 1);
 TEST_RES(recv(receiver, data, sizeof(data), 0), _ret == 7 && !memcmp(data, "raw-udp", 7));
 TEST_SUCC(close(sender)); TEST_SUCC(close(receiver)); TEST_SUCC(close(raw));
}
END_TEST()

FN_TEST(raw_broadcast_requires_broadcast_option)
{
 int fd = TEST_SUCC(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)); if (fd < 0) { __TEST_SUMMARY(); return; }
 struct sockaddr_in peer = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7fffffff) };
 struct icmphdr request = { .type = ICMP_ECHO }; request.checksum = checksum(&request, sizeof(request));
 TEST_ERRNO(sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&peer, sizeof(peer)), EACCES);
 TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(raw_ipv4_requires_cap_net_raw)
{
 pid_t child = TEST_SUCC(fork());
 if (child == 0) {
  if (setresuid(65534, 65534, 65534)) _exit(2);
  errno = 0; int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); _exit(fd == -1 && errno == EPERM ? 0 : 1);
 }
 int status = 0; TEST_RES(waitpid(child, &status, 0), WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()
