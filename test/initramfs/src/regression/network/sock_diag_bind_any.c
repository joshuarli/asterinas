// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s errno=%d\n", __LINE__, #cond, errno); return 1; } } while (0)

static int tcp(void) { return socket(AF_INET, SOCK_STREAM, 0); }

static int bind_to(int fd, unsigned addr, unsigned short port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = port, .sin_addr.s_addr = addr };
    return bind(fd, (void *)&a, sizeof(a));
}

int main(void)
{
    int one = 1;
    int server = tcp();
    CHECK(server >= 0 && bind_to(server, htonl(INADDR_LOOPBACK), 0) == 0 && listen(server, 4) == 0);
    struct sockaddr_in s;
    socklen_t len = sizeof(s);
    CHECK(getsockname(server, (void *)&s, &len) == 0);

    int any = tcp();
    CHECK(bind_to(any, htonl(INADDR_ANY), s.sin_port) == -1 && errno == EADDRINUSE);
    close(any);
    any = tcp();
    setsockopt(any, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    CHECK(bind_to(any, htonl(INADDR_ANY), s.sin_port) == -1 && errno == EADDRINUSE);
    close(any);
    int same = tcp();
    CHECK(bind_to(same, htonl(INADDR_LOOPBACK), s.sin_port) == -1 && errno == EADDRINUSE);
    close(same);

    puts("ok");
    return 0;
}
