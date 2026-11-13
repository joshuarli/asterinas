// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #condition, errno); \
        goto cleanup; \
    } \
} while (0)

struct response {
    struct inet_diag_msg socket;
    unsigned count;
    unsigned acknowledgments;
    unsigned done;
    int error;
};

struct inventory {
    const uint16_t *ports;
    unsigned char *seen;
    unsigned size;
    unsigned duplicates;
};

static int request(unsigned family, unsigned protocol, unsigned states,
                   unsigned flags, const struct inet_diag_sockid *identity,
                   unsigned payload_length, unsigned attribute,
                   struct response *result, struct inventory *inventory) {
    int status = -1;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    struct {
        struct nlmsghdr header;
        struct inet_diag_req_v2 query;
        uint16_t attribute[2];
    } message = {0};
    struct sockaddr_nl source = {.nl_family = AF_NETLINK};
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    socklen_t source_length = sizeof(source);
    memset(result, 0, sizeof(*result));
    REQUIRE(fd >= 0);
    REQUIRE(bind(fd, (void *)&source, sizeof(source)) == 0);
    REQUIRE(getsockname(fd, (void *)&source, &source_length) == 0);
    message.header.nlmsg_len = NLMSG_HDRLEN + payload_length;
    message.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    message.header.nlmsg_flags = NLM_F_REQUEST | flags;
    message.header.nlmsg_seq = 71;
    message.query.sdiag_family = family;
    message.query.sdiag_protocol = protocol;
    message.query.idiag_states = states;
    message.query.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    message.query.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    if (identity) message.query.id = *identity;
    if (attribute) {
        message.attribute[0] = 4;
        message.attribute[1] = attribute;
        message.header.nlmsg_len += 4;
    }
    REQUIRE(sendto(fd, &message, message.header.nlmsg_len, 0,
                   (void *)&kernel, sizeof(kernel)) == (ssize_t)message.header.nlmsg_len);
    for (unsigned round = 0; round < 64; round++) {
        struct pollfd wait = {.fd = fd, .events = POLLIN};
        unsigned char buffer[16384];
        struct sockaddr_nl sender;
        socklen_t sender_length = sizeof(sender);
        REQUIRE(poll(&wait, 1, 2000) == 1);
        REQUIRE((wait.revents & POLLIN) != 0);
        unsigned char peek[32], repeated[32];
        if (inventory && round == 0) {
            REQUIRE(recv(fd, peek, sizeof(peek), MSG_PEEK) == (ssize_t)sizeof(peek));
            REQUIRE(recv(fd, repeated, sizeof(repeated), MSG_PEEK) == (ssize_t)sizeof(repeated));
            REQUIRE(memcmp(peek, repeated, sizeof(peek)) == 0);
        }
        ssize_t length = recvfrom(fd, buffer, sizeof(buffer), 0,
                                  (void *)&sender, &sender_length);
        REQUIRE(length >= (ssize_t)sizeof(struct nlmsghdr));
        if (inventory && round == 0) REQUIRE(memcmp(buffer, peek, sizeof(peek)) == 0);
        REQUIRE(sender_length == sizeof(sender));
        REQUIRE(sender.nl_family == AF_NETLINK && sender.nl_pid == 0);
        for (struct nlmsghdr *header = (void *)buffer; NLMSG_OK(header, length);
             header = NLMSG_NEXT(header, length)) {
            REQUIRE(header->nlmsg_seq == 71 && header->nlmsg_pid == source.nl_pid);
            if (header->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
                REQUIRE(header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct inet_diag_msg)));
                REQUIRE(!(flags & NLM_F_DUMP) || (header->nlmsg_flags & NLM_F_MULTI));
                memcpy(&result->socket, NLMSG_DATA(header), sizeof(result->socket));
                result->count++;
                if (inventory) {
                    for (unsigned index = 0; index < inventory->size; index++) {
                        if (inventory->ports[index] == result->socket.id.idiag_sport) {
                            if (inventory->seen[index]) inventory->duplicates++;
                            inventory->seen[index] = 1;
                        }
                    }
                }
                if (!(flags & (NLM_F_DUMP | NLM_F_ACK))) {
                    status = 0;
                    goto cleanup;
                }
            } else if (header->nlmsg_type == NLMSG_DONE) {
                REQUIRE(header->nlmsg_len >= NLMSG_LENGTH(sizeof(int)));
                REQUIRE(header->nlmsg_flags & NLM_F_MULTI);
                memcpy(&result->error, NLMSG_DATA(header), sizeof(int));
                result->done++;
                status = 0;
                goto cleanup;
            } else if (header->nlmsg_type == NLMSG_ERROR) {
                REQUIRE(header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)));
                struct nlmsgerr error;
                memcpy(&error, NLMSG_DATA(header), sizeof(error));
                REQUIRE(error.msg.nlmsg_seq == 71);
                REQUIRE(error.msg.nlmsg_type == SOCK_DIAG_BY_FAMILY);
                REQUIRE(error.msg.nlmsg_len == message.header.nlmsg_len);
                result->error = error.error;
                if (error.error == 0) result->acknowledgments++;
                status = 0;
                goto cleanup;
            } else {
                REQUIRE(0);
            }
        }
        REQUIRE(length == 0);
    }
cleanup:
    if (fd >= 0 && close(fd)) status = -1;
    return status;
}

static int query(unsigned family, unsigned states, unsigned flags,
                 const struct inet_diag_sockid *identity, struct response *result) {
    return request(family, IPPROTO_TCP, states, flags, identity,
                   sizeof(struct inet_diag_req_v2), 0, result, NULL);
}

static int same_cookie(const struct inet_diag_sockid *first,
                       const struct inet_diag_sockid *second) {
    return first->idiag_cookie[0] == second->idiag_cookie[0] &&
           first->idiag_cookie[1] == second->idiag_cookie[1];
}

static int64_t monotonic_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int exercise(unsigned family) {
    int status = -1, listener = -1, client = -1, accepted = -1;
    union {
        struct sockaddr address;
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } local = {0};
    socklen_t address_length;
    struct stat metadata;
    struct response response;
    struct inet_diag_sockid selector = {.idiag_cookie = {~0U, ~0U}};
    listener = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(listener >= 0);
    if (family == AF_INET) {
        local.ipv4.sin_family = AF_INET;
        local.ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address_length = sizeof(local.ipv4);
    } else {
        local.ipv6.sin6_family = AF_INET6;
        local.ipv6.sin6_addr = in6addr_loopback;
        address_length = sizeof(local.ipv6);
    }
    REQUIRE(bind(listener, &local.address, address_length) == 0);
    REQUIRE(listen(listener, 8) == 0);
    REQUIRE(getsockname(listener, &local.address, &address_length) == 0);
    selector.idiag_sport = family == AF_INET ? local.ipv4.sin_port : local.ipv6.sin6_port;
    REQUIRE(query(family, 1U << 10, NLM_F_DUMP | NLM_F_ACK, &selector, &response) == 0);
    REQUIRE(response.done == 1 && response.error == 0 && response.count == 1);
    REQUIRE(response.socket.idiag_family == family && response.socket.idiag_state == 10);
    REQUIRE(response.socket.id.idiag_sport == selector.idiag_sport);
    REQUIRE(response.socket.id.idiag_dport == 0 && response.socket.id.idiag_if == 0);
    REQUIRE(response.socket.idiag_rqueue == 0 && response.socket.idiag_wqueue == 8);
    REQUIRE(fstat(listener, &metadata) == 0);
    REQUIRE(response.socket.idiag_inode == metadata.st_ino);
    REQUIRE(response.socket.idiag_uid == metadata.st_uid && metadata.st_uid == geteuid());
    struct inet_diag_sockid listener_identity = response.socket.id;
    REQUIRE(listener_identity.idiag_cookie[0] != 0 || listener_identity.idiag_cookie[1] != 0);
    REQUIRE(query(family, 0, NLM_F_DUMP, &selector, &response) == 0);
    REQUIRE(response.done == 1 && response.error == 0 && response.count == 0);
    REQUIRE(query(family, ~0U, NLM_F_ACK, &listener_identity, &response) == 0);
    REQUIRE(response.count == 1 && response.acknowledgments == 1 && response.error == 0);
    struct inet_diag_sockid wrong_cookie = listener_identity;
    wrong_cookie.idiag_cookie[0] ^= 1;
    REQUIRE(query(family, ~0U, NLM_F_ACK, &wrong_cookie, &response) == 0);
    REQUIRE(response.count == 0 && response.done == 0 && response.error == -ENOENT);
    if (geteuid() == 0) {
        REQUIRE(fchown(listener, 1001, (gid_t)-1) == 0);
        REQUIRE(query(family, 1U << 10, NLM_F_DUMP, &selector, &response) == 0);
        REQUIRE(response.count == 1 && response.socket.idiag_uid == 1001);
        REQUIRE(same_cookie(&listener_identity, &response.socket.id));
        REQUIRE(fchown(listener, 0, (gid_t)-1) == 0);
    }
    REQUIRE(request(family, 253, ~0U, NLM_F_DUMP | NLM_F_ACK, &selector,
                    sizeof(struct inet_diag_req_v2), 0, &response, NULL) == 0);
    REQUIRE(response.count == 0 && response.done == 1 && response.error == -ENOENT);
    REQUIRE(request(AF_UNSPEC, IPPROTO_TCP, ~0U, NLM_F_DUMP | NLM_F_ACK, &selector,
                    sizeof(struct inet_diag_req_v2), 0, &response, NULL) == 0);
    REQUIRE(response.count == 0 && response.done == 0 && response.error == -ENOENT);
    REQUIRE(request(family, IPPROTO_TCP, ~0U, NLM_F_ACK, &selector, 2, 0, &response, NULL) == 0);
    REQUIRE(response.count == 0 && response.done == 0 && response.error == -EINVAL);
    REQUIRE(request(family, IPPROTO_TCP, 1U << 10, NLM_F_DUMP, &selector,
                    sizeof(struct inet_diag_req_v2), 99, &response, NULL) == 0);
    REQUIRE(response.count == 1 && response.done == 1 && response.error == 0);
    REQUIRE(request(family, IPPROTO_TCP, ~0U, NLM_F_DUMP, &selector,
                    sizeof(struct inet_diag_req_v2), INET_DIAG_REQ_BYTECODE, &response, NULL) == 0);
    REQUIRE(response.count == 0 && response.done == 0 && response.error == -EINVAL);
    client = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(client >= 0);
    REQUIRE(connect(client, &local.address, address_length) == 0);
    accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    REQUIRE(accepted >= 0);
    REQUIRE(query(family, 1U << 1, NLM_F_DUMP, &selector, &response) == 0);
    REQUIRE(response.count == 1 && response.error == 0 && response.done == 1);
    REQUIRE(response.socket.idiag_state == 1);
    REQUIRE(fstat(accepted, &metadata) == 0);
    REQUIRE(response.socket.idiag_inode == metadata.st_ino && response.socket.idiag_uid == metadata.st_uid);
    struct inet_diag_sockid accepted_identity = response.socket.id;
    struct inet_diag_sockid client_selector = {
        .idiag_sport = accepted_identity.idiag_dport,
        .idiag_dport = accepted_identity.idiag_sport,
        .idiag_cookie = {~0U, ~0U},
    };
    REQUIRE(query(family, 1U << 1, NLM_F_DUMP, &client_selector, &response) == 0);
    REQUIRE(response.count == 1 && response.error == 0);
    REQUIRE(fstat(client, &metadata) == 0);
    REQUIRE(response.socket.idiag_inode == metadata.st_ino && response.socket.idiag_uid == metadata.st_uid);
    struct inet_diag_sockid client_identity = response.socket.id;
    REQUIRE(!same_cookie(&accepted_identity, &client_identity));
    REQUIRE(send(client, "hello", 5, MSG_NOSIGNAL) == 5);
    struct pollfd wait = {.fd = accepted, .events = POLLIN};
    REQUIRE(poll(&wait, 1, 2000) == 1 && (wait.revents & POLLIN));
    REQUIRE(query(family, ~0U, NLM_F_ACK, &accepted_identity, &response) == 0);
    REQUIRE(response.count == 1 && response.error == 0 && response.socket.idiag_rqueue == 5);
    char payload[5];
    REQUIRE(recv(accepted, payload, sizeof(payload), MSG_WAITALL) == 5);
    REQUIRE(memcmp(payload, "hello", 5) == 0);
    REQUIRE(shutdown(client, SHUT_WR) == 0);
    REQUIRE(poll(&wait, 1, 2000) == 1 && (wait.revents & POLLIN));
    REQUIRE(recv(accepted, payload, sizeof(payload), 0) == 0);
    REQUIRE(query(family, 1U << 8, NLM_F_DUMP, &selector, &response) == 0);
    REQUIRE(response.count == 1 && response.error == 0 && response.socket.idiag_state == 8);
    REQUIRE(close(client) == 0);
    client = -1;
    REQUIRE(query(family, ~0U, NLM_F_DUMP, &client_selector, &response) == 0);
    REQUIRE(response.count == 1 && response.error == 0);
    REQUIRE(response.socket.idiag_state == 4 || response.socket.idiag_state == 5);
    REQUIRE(response.socket.idiag_inode == 0);
    REQUIRE(same_cookie(&client_identity, &response.socket.id));
    REQUIRE(close(accepted) == 0);
    accepted = -1;
    int64_t start = monotonic_millis();
    REQUIRE(start >= 0);
    do {
        REQUIRE(query(family, ~0U, NLM_F_DUMP, &client_selector, &response) == 0);
        REQUIRE(response.count == 1 && response.error == 0);
        if (response.socket.idiag_state == 6) break;
        int64_t now = monotonic_millis();
        REQUIRE(now >= start && now - start < 2000);
    } while (1);
    REQUIRE(response.socket.idiag_inode == 0 && response.socket.idiag_uid == 0);
    REQUIRE(same_cookie(&client_identity, &response.socket.id));
    status = 0;
cleanup:
    if (accepted >= 0 && close(accepted)) status = -1;
    if (client >= 0 && close(client)) status = -1;
    if (listener >= 0 && close(listener)) status = -1;
    if (status == 0) printf("TCP diagnostic IPv%u state, queues, identity, owner and protocol controls passed\n", family == AF_INET ? 4 : 6);
    return status;
}

static int large_dump(void) {
    enum { count = 700 };
    int status = -1;
    int listeners[count];
    uint16_t ports[count];
    unsigned char seen[count];
    for (unsigned index = 0; index < count; index++) listeners[index] = -1;
    memset(seen, 0, sizeof(seen));
    for (unsigned index = 0; index < count; index++) {
        struct sockaddr_in local = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };
        socklen_t length = sizeof(local);
        listeners[index] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        REQUIRE(listeners[index] >= 0);
        REQUIRE(bind(listeners[index], (void *)&local, sizeof(local)) == 0);
        REQUIRE(listen(listeners[index], 1) == 0);
        REQUIRE(getsockname(listeners[index], (void *)&local, &length) == 0);
        ports[index] = local.sin_port;
    }
    struct inventory inventory = {.ports = ports, .seen = seen, .size = count};
    struct response response;
    REQUIRE(request(AF_INET, IPPROTO_TCP, 1U << 10, NLM_F_DUMP, NULL,
                    sizeof(struct inet_diag_req_v2), 0, &response, &inventory) == 0);
    REQUIRE(response.done == 1 && response.error == 0 && response.count >= count);
    REQUIRE(inventory.duplicates == 0);
    for (unsigned index = 0; index < count; index++) REQUIRE(seen[index] == 1);
    status = 0;
cleanup:
    for (unsigned index = 0; index < count; index++) {
        if (listeners[index] >= 0 && close(listeners[index])) status = -1;
    }
    if (status == 0) puts("TCP diagnostic paged dump preserves 700 owned listeners and peek state");
    return status;
}

static int repeated_dumps(void) {
    int status = -1;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    REQUIRE(fd >= 0);
    for (unsigned index = 0; index < 8; index++) {
        struct {
            struct nlmsghdr header;
            struct inet_diag_req_v2 query;
        } message = {
            .header = {
                .nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2)),
                .nlmsg_type = SOCK_DIAG_BY_FAMILY,
                .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                .nlmsg_seq = index + 1,
            },
            .query = {.sdiag_family = AF_INET, .sdiag_protocol = IPPROTO_TCP},
        };
        struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
        REQUIRE(sendto(fd, &message, sizeof(message), 0,
                       (void *)&kernel, sizeof(kernel)) == (ssize_t)sizeof(message));
        struct pollfd wait = {.fd = fd, .events = POLLIN};
        REQUIRE(poll(&wait, 1, 2000) == 1 && (wait.revents & POLLIN));
        unsigned char buffer[128];
        ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
        REQUIRE(length >= (ssize_t)NLMSG_LENGTH(sizeof(int)));
        const struct nlmsghdr *header = (void *)buffer;
        REQUIRE(header->nlmsg_len == (unsigned)length);
        REQUIRE(header->nlmsg_type == NLMSG_DONE && header->nlmsg_seq == index + 1);
        int error;
        memcpy(&error, NLMSG_DATA(header), sizeof(error));
        REQUIRE(error == 0);
    }
    status = 0;
cleanup:
    if (fd >= 0 && close(fd)) status = -1;
    if (status == 0) puts("TCP diagnostic completed dumps release their receive capacity");
    return status;
}

int main(void) {
    return exercise(AF_INET) || exercise(AF_INET6) || large_dump() || repeated_dumps() ? 1 : 0;
}
