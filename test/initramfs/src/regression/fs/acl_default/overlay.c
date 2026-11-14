// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#define DEFAULT "system.posix_acl_default"
#define ACCESS "system.posix_acl_access"
struct entry { uint16_t tag, perm; uint32_t id; };
struct acl { uint32_t version; struct entry e[5]; };
static const struct acl acl = { 2, {{1,7,~0u},{2,5,12345},{4,7,~0u},{16,7,~0u},{32,0,~0u}} };
static void need(int ok, const char *what) { if (!ok) { perror(what); exit(1); } }
int main(int argc, char **argv) {
    const char *base = argc > 1 ? argv[1] : "/work";
    char root[256], lower[300], upper[300], work[300], merged[300], opts[1024], p[400];
    snprintf(root, sizeof root, "%s/acl-overlay-%d", base, getpid());
    snprintf(lower, sizeof lower, "%s/lower", root); snprintf(upper, sizeof upper, "%s/upper", root);
    snprintf(work, sizeof work, "%s/work", root); snprintf(merged, sizeof merged, "%s/merged", root);
    need(mkdir(root, 0755) == 0 && mkdir(lower, 0755) == 0 && mkdir(upper, 0755) == 0 && mkdir(work, 0755) == 0 && mkdir(merged, 0755) == 0, "mkdir");
    snprintf(p, sizeof p, "%s/d", lower);
    need(mkdir(p, 0755) == 0 && setxattr(p, DEFAULT, &acl, sizeof acl, 0) == 0, "lower default");
    snprintf(opts, sizeof opts, "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work);
    need(mount("overlay", merged, "overlay", 0, opts) == 0, "mount overlay");
    snprintf(p, sizeof p, "%s/d", merged);
    need(chmod(p, 0750) == 0, "copy-up chmod");
    struct acl got;
    need(getxattr(p, DEFAULT, &got, sizeof got) == sizeof got && !memcmp(&got, &acl, sizeof got), "copied default");
    snprintf(p, sizeof p, "%s/d", upper);
    need(getxattr(p, DEFAULT, &got, sizeof got) == sizeof got && !memcmp(&got, &acl, sizeof got), "upper default");
    umask(077);
    snprintf(p, sizeof p, "%s/d/f", merged);
    int fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0666);
    need(fd >= 0 && close(fd) == 0, "create in overlay");
    struct stat st; need(stat(p, &st) == 0, "stat");
    if ((st.st_mode & 0777) != 0660) { fprintf(stderr, "mode %o\n", st.st_mode & 0777); return 1; }
    need(getxattr(p, ACCESS, &got, sizeof got) == sizeof got, "inherited access");
    need(umount(merged) == 0, "umount");
    printf("overlay default ACL copy-up passed\n");
    return 0;
}
