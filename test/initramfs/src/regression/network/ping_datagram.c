// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <time.h>
#include <linux/errqueue.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/test.h"

static const char *range_path = "/proc/sys/net/ipv4/ping_group_range";
static int read_range(char *value, size_t capacity)
{
 int fd = open(range_path, O_RDONLY); if (fd < 0) return -1;
 ssize_t count = read(fd, value, capacity - 1); int saved = errno; close(fd); errno = saved;
 if (count < 0) return -1;
 value[count] = 0;
 return 0;
}
static int write_range(const char *value)
{
 int fd = open(range_path, O_WRONLY); if (fd < 0) return -1;
 size_t size = strlen(value); ssize_t n = write(fd, value, size); int saved = errno; close(fd); errno = saved;
 return n == (ssize_t)size ? 0 : -1;
}
static uint16_t checksum(const void *data, size_t length)
{
 const unsigned char *bytes = data; uint32_t sum = 0;
 while (length >= 2) { sum += ((uint16_t)bytes[0] << 8) | bytes[1]; bytes += 2; length -= 2; }
 if (length) sum += (uint16_t)bytes[0] << 8;
 while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
 return htons((uint16_t)~sum);
}
static int unprivileged_open(void)
{
 pid_t child = fork(); if (child < 0) return -1;
 if (child == 0) {
  if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(3);
  errno = 0; int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (fd >= 0) { close(fd); _exit(0); }
  _exit(errno == EACCES ? 1 : 2);
 }
 int status = 0; if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) return -1;
 return WEXITSTATUS(status);
}

static int unprivileged_supplementary_open(void)
{
 pid_t child = fork(); if (child < 0) return -1;
 if (child == 0) {
  gid_t supplementary = 1234;
  if (setgroups(1, &supplementary) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(3);
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (fd >= 0) { close(fd); _exit(0); }
  _exit(1);
 }
 int status = 0; if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) return -1;
 return WEXITSTATUS(status);
}

static int unprivileged_range_write(void)
{
 pid_t child = fork(); if (child < 0) return -1;
 if (child == 0) {
  if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(3);
  errno = 0; int fd = open(range_path, O_WRONLY);
  if (fd >= 0) { close(fd); _exit(1); }
  _exit(errno == EACCES ? 0 : 2);
 }
 int status = 0; if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) return -1;
 return WEXITSTATUS(status);
}

FN_TEST(ping_group_range_validates_updates_and_write_access)
{
 char original[64] = {}, value[64] = {}; int ok = TEST_SUCC(read_range(original, sizeof(original)));
 if (ok < 0) { __TEST_SUMMARY(); return; }
 TEST_RES(unprivileged_range_write(), _ret == 0);
 TEST_SUCC(write_range("0 10\n")); TEST_SUCC(write_range("4\n"));
 TEST_SUCC(read_range(value, sizeof(value))); unsigned int low = 0, high = 0;
 TEST_RES(sscanf(value, "%u %u", &low, &high), _ret == 2 && low == 4 && high == 10);
 TEST_SUCC(write_range("010 0x10\n")); TEST_SUCC(read_range(value, sizeof(value)));
 TEST_RES(sscanf(value, "%u %u", &low, &high), _ret == 2 && low == 8 && high == 16);
 TEST_ERRNO(write_range("0x+10 0x+10\n"), EINVAL); TEST_SUCC(read_range(value, sizeof(value)));
 TEST_RES(sscanf(value, "%u %u", &low, &high), _ret == 2 && low == 8 && high == 16);
 TEST_SUCC(write_range("9 3\n")); TEST_SUCC(read_range(value, sizeof(value)));
 TEST_RES(sscanf(value, "%u %u", &low, &high), _ret == 2 && low == 1 && high == 0);
 TEST_ERRNO(write_range("4294967295 0\n"), EINVAL); TEST_SUCC(write_range(original));
}
END_TEST()

FN_TEST(ping_group_range_controls_unprivileged_sockets)
{
 char original[64] = {}; int ok = TEST_SUCC(read_range(original, sizeof(original))); if (ok < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(write_range("1 0\n")); TEST_ERRNO(socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), EACCES);
 TEST_SUCC(write_range("0 0\n")); TEST_RES(unprivileged_open(), _ret == 1);
 TEST_SUCC(write_range("65534 65534\n")); TEST_RES(unprivileged_open(), _ret == 0);
 TEST_SUCC(write_range("1234 1234\n")); TEST_RES(unprivileged_supplementary_open(), _ret == 0);
 TEST_SUCC(write_range(original));
}
END_TEST()

FN_TEST(ping_socket_reports_a_quoted_icmp_error)
{
 char original[64] = {}; int ok = TEST_SUCC(read_range(original, sizeof(original)));
 if (ok < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(write_range("0 0\n"));
 int raw = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP));
 if (fd < 0 || raw < 0) { if (fd >= 0) close(fd); if (raw >= 0) close(raw); write_range(original); __TEST_SUMMARY(); return; }
 int enabled = 1; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 TEST_SUCC(connect(fd, (struct sockaddr *)&dst, sizeof(dst)));
 struct { struct icmphdr header; char data[8]; } request = { .header = { .type = ICMP_ECHO, .un.echo.sequence = htons(55) }, .data = "errping" };
 TEST_RES(send(fd, &request, sizeof(request), 0), _ret == sizeof(request));
 struct pollfd ready = { .fd = fd, .events = POLLIN }; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char received[256]; TEST_RES(recv(fd, received, sizeof(received), 0), _ret == sizeof(request));
 unsigned char quote[128]; ssize_t quote_len = -1;
 for (int i = 0; i < 8 && quote_len < 0; i++) {
  ready.fd = raw; ready.events = POLLIN; if (poll(&ready, 1, 500) != 1) break;
  ssize_t n = recv(raw, quote, sizeof(quote), 0);
  if (n == 36 && quote[0] == 0x45 && quote[20] == ICMP_ECHO && !memcmp(quote + 28, request.data, 8)) quote_len = n;
 }
 TEST_RES(quote_len, _ret == 36);
 if (quote_len != 36) { close(raw); close(fd); write_range(original); __TEST_SUMMARY(); return; }
 unsigned char error[44] = {}; error[0] = ICMP_TIME_EXCEEDED; error[1] = ICMP_EXC_TTL;
 memcpy(error + 8, quote, 36); uint16_t sum = checksum(error, sizeof(error)); memcpy(error + 2, &sum, 2);
 TEST_RES(sendto(raw, error, sizeof(error), 0, (struct sockaddr *)&dst, sizeof(dst)), _ret == sizeof(error));
 ready.fd = fd; ready.events = POLLIN; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLERR));
 union { struct cmsghdr align; char bytes[128]; } control = {};
 struct sockaddr_in quoted_dst = {}; struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
 struct msghdr msg = { .msg_name = &quoted_dst, .msg_namelen = sizeof(quoted_dst), .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
 TEST_RES(recvmsg(fd, &msg, MSG_ERRQUEUE), _ret == sizeof(request) && !memcmp(received, quote + 20, sizeof(request)));
 struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); TEST_RES(cmsg, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
 if (cmsg && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
  struct sock_extended_err extended; memcpy(&extended, CMSG_DATA(cmsg), sizeof(extended));
  TEST_RES(extended.ee_errno, _ret == EHOSTUNREACH); TEST_RES(extended.ee_origin, _ret == SO_EE_ORIGIN_ICMP);
  TEST_RES(extended.ee_type, _ret == ICMP_TIME_EXCEEDED); TEST_RES(extended.ee_code, _ret == ICMP_EXC_TTL);
 }
 TEST_RES(quoted_dst.sin_addr.s_addr, _ret == dst.sin_addr.s_addr);
 TEST_SUCC(close(fd)); TEST_SUCC(close(raw)); TEST_SUCC(write_range(original));
}
END_TEST()

FN_TEST(ping_shared_identifier_follows_the_latest_binding)
{
 char original[64] = {}; int ok = TEST_SUCC(read_range(original, sizeof(original)));
 if (ok < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(write_range("0 0\n"));
 int first = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP));
 int second = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP));
 if (first < 0 || second < 0) { if (first >= 0) close(first); if (second >= 0) close(second); write_range(original); __TEST_SUMMARY(); return; }
 struct sockaddr_in local = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(23456) };
 TEST_SUCC(bind(first, (struct sockaddr *)&local, sizeof(local)));
 TEST_SUCC(bind(second, (struct sockaddr *)&local, sizeof(local)));
 struct icmphdr request = { .type = ICMP_ECHO, .un.echo.sequence = htons(7) };
 struct sockaddr_in destination = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 TEST_RES(sendto(first, &request, sizeof(request), 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == sizeof(request));
 struct pollfd ready = { .fd = second, .events = POLLIN }; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char packet[64]; TEST_RES(recv(second, packet, sizeof(packet), 0), _ret == sizeof(request) && packet[0] == ICMP_ECHOREPLY);
 ready.fd = first; TEST_RES(poll(&ready, 1, 100), _ret == 0);
 TEST_SUCC(close(second));
 TEST_RES(sendto(first, &request, sizeof(request), 0, (struct sockaddr *)&destination, sizeof(destination)), _ret == sizeof(request));
 ready.fd = first; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 TEST_RES(recv(first, packet, sizeof(packet), 0), _ret == sizeof(request) && packet[0] == ICMP_ECHOREPLY);
 TEST_SUCC(close(first)); TEST_SUCC(write_range(original));
}
END_TEST()

FN_TEST(ping_identifier_respects_reuse_option)
{
 char original[64] = {}; int ok = TEST_SUCC(read_range(original, sizeof(original)));
 if (ok < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(write_range("0 0\n"));
 int first = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));
 int second = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));
 if (first < 0 || second < 0) { if (first >= 0) close(first); if (second >= 0) close(second); write_range(original); __TEST_SUMMARY(); return; }
 int reuse = -1; socklen_t len = sizeof(reuse);
 TEST_SUCC(getsockopt(first, SOL_SOCKET, SO_REUSEADDR, &reuse, &len)); TEST_RES(reuse, _ret == 1);
 reuse = 0; TEST_SUCC(setsockopt(first, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
 struct sockaddr_in local = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(23457) };
 TEST_SUCC(bind(first, (struct sockaddr *)&local, sizeof(local)));
 TEST_ERRNO(bind(second, (struct sockaddr *)&local, sizeof(local)), EADDRINUSE);
 TEST_SUCC(close(first)); TEST_SUCC(bind(second, (struct sockaddr *)&local, sizeof(local)));
 TEST_SUCC(close(second)); TEST_SUCC(write_range(original));
}
END_TEST()

FN_TEST(ping_socket_rewrites_identifier_and_checksum)
{
 char original[64] = {}; int ok = TEST_SUCC(read_range(original, sizeof(original))); if (ok < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(write_range("0 0\n"));
 int watcher = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP));
 if (fd < 0 || watcher < 0) { if (fd >= 0) close(fd); if (watcher >= 0) close(watcher); write_range(original); __TEST_SUMMARY(); return; }
 struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 TEST_SUCC(connect(fd, (struct sockaddr *)&dst, sizeof(dst)));
 struct sockaddr_in local = {}; socklen_t len = sizeof(local); TEST_SUCC(getsockname(fd, (struct sockaddr *)&local, &len));
 TEST_RES(local.sin_port, _ret != 0);
 struct __attribute__((packed)) { struct icmphdr header; char data[7]; } request = {
  .header = { .type = ICMP_ECHO, .un.echo = { .id = htons(1234), .sequence = htons(7) } }, .data = "ping-id" };
 TEST_RES(send(fd, &request, sizeof(request), 0), _ret == sizeof(request));
 struct pollfd ready = { .fd = fd, .events = POLLIN }; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char received[128]; ssize_t n = recv(fd, received, sizeof(received), 0); int valid = 0;
 if (n == sizeof(request) && received[0] == ICMP_ECHOREPLY && !checksum(received, n) && !memcmp(received + 8, request.data, 7)) {
  struct icmphdr header; memcpy(&header, received, sizeof(header));
  valid = header.un.echo.id == local.sin_port && header.un.echo.sequence == htons(7);
 }
 TEST_RES(valid, _ret == 1);
 int found = 0;
 for (int i = 0; i < 8 && !found; i++) {
  struct pollfd event = { .fd = watcher, .events = POLLIN }; if (poll(&event, 1, 500) != 1) break;
  n = recv(watcher, received, sizeof(received), 0);
  if (n == 35 && received[0] == 0x45 && received[20] == ICMP_ECHO && !checksum(received + 20, 15)) {
   struct icmphdr header; memcpy(&header, received + 20, sizeof(header));
   found = header.un.echo.id == local.sin_port && header.un.echo.sequence == htons(7) && !memcmp(received + 28, request.data, 7);
  }
 }
 TEST_RES(found, _ret == 1);
 request.header.type = ICMP_DEST_UNREACH; TEST_ERRNO(send(fd, &request, sizeof(request), 0), EINVAL);
 TEST_SUCC(close(fd)); TEST_SUCC(close(watcher)); TEST_SUCC(write_range(original));
}
END_TEST()

FN_TEST(ping_connected_socket_accepts_alternate_destination)
{
 char original[64] = {}; int ok = TEST_SUCC(read_range(original, sizeof(original)));
 if (ok < 0) { __TEST_SUMMARY(); return; }
 TEST_SUCC(write_range("0 0\n"));
 int raw = TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));
 int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP));
 if (fd < 0 || raw < 0) { if (fd >= 0) close(fd); if (raw >= 0) close(raw); write_range(original); __TEST_SUMMARY(); return; }
 int enabled = 1; TEST_SUCC(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)));
 struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
 TEST_SUCC(connect(fd, (struct sockaddr *)&dst, sizeof(dst)));
 struct { struct icmphdr header; char data[8]; } request = { .header = { .type = ICMP_ECHO, .un.echo.sequence = htons(55) }, .data = "errping" };
 struct sockaddr_in alternate = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000002) };
 TEST_RES(sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&alternate, sizeof(alternate)), _ret == sizeof(request));
 struct pollfd ready = { .fd = fd, .events = POLLIN }; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLIN));
 unsigned char received[256]; TEST_RES(recv(fd, received, sizeof(received), 0), _ret == sizeof(request));
 unsigned char quote[128]; ssize_t quote_len = -1;
 for (int i = 0; i < 8 && quote_len < 0; i++) {
  ready.fd = raw; ready.events = POLLIN; if (poll(&ready, 1, 500) != 1) break;
  ssize_t n = recv(raw, quote, sizeof(quote), 0);
  if (n == 36 && quote[0] == 0x45 && quote[20] == ICMP_ECHO && !memcmp(quote + 28, request.data, 8)) quote_len = n;
 }
 TEST_RES(quote_len, _ret == 36);
 if (quote_len != 36) { close(raw); close(fd); write_range(original); __TEST_SUMMARY(); return; }
 unsigned char error[44] = {}; error[0] = ICMP_TIME_EXCEEDED; error[1] = ICMP_EXC_TTL;
 memcpy(error + 8, quote, 36); uint16_t sum = checksum(error, sizeof(error)); memcpy(error + 2, &sum, 2);
 TEST_RES(sendto(raw, error, sizeof(error), 0, (struct sockaddr *)&dst, sizeof(dst)), _ret == sizeof(error));
 ready.fd = fd; ready.events = POLLIN; TEST_RES(poll(&ready, 1, 2000), _ret == 1 && (ready.revents & POLLERR));
 union { struct cmsghdr align; char bytes[128]; } control = {};
 struct sockaddr_in quoted_dst = {}; struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
 struct msghdr msg = { .msg_name = &quoted_dst, .msg_namelen = sizeof(quoted_dst), .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
 TEST_RES(recvmsg(fd, &msg, MSG_ERRQUEUE), _ret == sizeof(request) && !memcmp(received, quote + 20, sizeof(request)));
 struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); TEST_RES(cmsg, _ret && _ret->cmsg_level == IPPROTO_IP && _ret->cmsg_type == IP_RECVERR);
 if (cmsg && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
  struct sock_extended_err extended; memcpy(&extended, CMSG_DATA(cmsg), sizeof(extended));
  TEST_RES(extended.ee_errno, _ret == EHOSTUNREACH); TEST_RES(extended.ee_origin, _ret == SO_EE_ORIGIN_ICMP);
  TEST_RES(extended.ee_type, _ret == ICMP_TIME_EXCEEDED); TEST_RES(extended.ee_code, _ret == ICMP_EXC_TTL);
 }
 TEST_RES(quoted_dst.sin_addr.s_addr, _ret == alternate.sin_addr.s_addr);
 TEST_SUCC(close(fd)); TEST_SUCC(close(raw)); TEST_SUCC(write_range(original));
}
END_TEST()
