// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct req { uint32_t size, spare; uint64_t id, mask, ns_id; };
struct result { uint32_t size, opts; uint64_t mask; uint32_t major, minor; uint64_t magic; uint32_t flags, fs_type; uint64_t id, parent; uint32_t old_id, old_parent; uint64_t attr, propagation, peer, master, from; uint32_t root, point; char rest[400]; char strings[]; };
int main(void) {
    struct statx sx;
    char buf[4096] = {0};
    struct result *r = (void *)buf;
    if (statx(-100, "/proc", 0, 0x4000, &sx)) { perror("statx"); return 1; }
    struct req req = {24, 0, sx.stx_mnt_id, 0x3f, 0};
    if (syscall(457, &req, buf, sizeof(buf), 0)) { perror("statmount"); return 1; }
    if ((r->mask & 0x3b) != 0x3b || r->id != req.id || strcmp(r->strings + r->point, "/proc") || strcmp(r->strings + r->root, "/") || strcmp(r->strings + r->fs_type, "proc")) { fprintf(stderr, "bad result mask=%lx point=%s root=%s type=%s size=%u\n", r->mask, r->strings + r->point, r->strings + r->root, r->strings + r->fs_type, r->size); return 1; }
    req.size = sizeof(req);
    req.mask = 0x11;
    memset(buf, 0, sizeof(buf));
    if (syscall(457, &req, buf, sizeof(buf), 0) || r->mask != req.mask || strcmp(r->strings + r->point, "/proc")) { perror("statmount version 1"); return 1; }
    errno = 0;
    if (syscall(457, &req, buf, 1, 0) != -1 || errno != EOVERFLOW) { fprintf(stderr, "small buffer errno=%d\n", errno); return 1; }
    req.id = UINT64_MAX - 1; errno = 0;
    if (syscall(457, &req, buf, sizeof(buf), 0) != -1 || errno != ENOENT) { fprintf(stderr, "unknown id errno=%d\n", errno); return 1; }
    puts("statmount witness passed");
    return 0;
}
