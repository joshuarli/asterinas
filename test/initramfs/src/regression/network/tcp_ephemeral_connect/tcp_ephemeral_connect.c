// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(void)
{
    alarm(5);
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0 || bind(udp, (void *)&target, sizeof(target))) {
        perror("reserve closed TCP destination"); return 1;
    }
    socklen_t size = sizeof(target);
    if (getsockname(udp, (void *)&target, &size)) {
        perror("getsockname"); return 1;
    }
    close(udp);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = { .tv_sec = 2 };
    if (tcp < 0 || setsockopt(tcp, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
        perror("create TCP client"); return 1;
    }
    errno = 0;
    int result = connect(tcp, (void *)&target, sizeof(target));
    int error = errno;
    struct sockaddr_in local, peer;
    size = sizeof(local);
    int local_result = getsockname(tcp, (void *)&local, &size);
    size = sizeof(peer);
    int peer_result = getpeername(tcp, (void *)&peer, &size);
    int peer_error = errno;
    printf("connect result=%d errno=%d target=%u local=%u peer=%d errno=%d\n",
           result, error, ntohs(target.sin_port),
           local_result ? 0 : ntohs(local.sin_port), peer_result, peer_error);
    close(tcp);
    if (result != -1 || error != ECONNREFUSED ||
        peer_result != -1 || peer_error != ENOTCONN) return 1;
    puts("implicit TCP bind does not connect to itself");
    return 0;
}
