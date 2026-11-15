// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include "sock_diag.h"
#include <poll.h>

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); return 1; } } while (0)

static int receive_queue(unsigned short local, unsigned short remote)
{
    static struct entry entries[256];
    int error;
    int count = diag_dump(AF_INET, IPPROTO_TCP, ~0U, 0, entries, 256, &error);
    if (count < 0 || error) return -1;
    for (int i = 0; i < count; i++) {
        if (entries[i].m.id.idiag_sport == local && entries[i].m.id.idiag_dport == remote)
            return entries[i].m.idiag_rqueue;
    }
    return -1;
}

int main(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    struct sockaddr_in peer;
    socklen_t len = sizeof(server);
    char data[100] = {0};
    CHECK(listener >= 0 && client >= 0);
    CHECK(bind(listener, (void *)&server, sizeof(server)) == 0 && listen(listener, 4) == 0);
    CHECK(getsockname(listener, (void *)&server, &len) == 0);
    CHECK(connect(client, (void *)&server, sizeof(server)) == 0);
    len = sizeof(peer);
    CHECK(getsockname(client, (void *)&peer, &len) == 0);
    int accepted = accept(listener, NULL, NULL);
    CHECK(accepted >= 0 && send(client, data, sizeof(data), 0) == sizeof(data));
    CHECK(shutdown(client, SHUT_WR) == 0);
    struct pollfd pollfd = { .fd = accepted, .events = POLLRDHUP };
    CHECK(poll(&pollfd, 1, 2000) == 1 && (pollfd.revents & POLLRDHUP));
    CHECK(receive_queue(server.sin_port, peer.sin_port) == 101);
    CHECK(recv(accepted, data, sizeof(data), MSG_WAITALL) == sizeof(data));
    CHECK(receive_queue(server.sin_port, peer.sin_port) == 0);
    CHECK(recv(accepted, data, 1, 0) == 0);
    CHECK(receive_queue(server.sin_port, peer.sin_port) == 0);
    close(accepted);
    close(client);
    close(listener);
    puts("ok");
    return 0;
}
