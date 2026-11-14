// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define DIR "/mnt/cow"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, #x, strerror(errno)); exit(1); } } while (0)

static char original[512];
static char changed[512];
static pthread_barrier_t writers_ready;

static void path(char *out, size_t size, int n)
{
    CHECK(snprintf(out, size, DIR "/file%d", n) > 0);
}

static void expect_value(int n, const char *name, const char *expected, size_t len)
{
    char p[64], value[4096];
    path(p, sizeof(p), n);
    ssize_t got = getxattr(p, name, value, sizeof(value));
    CHECK(got == (ssize_t)len && !memcmp(value, expected, len));
}

static void expect_blocks(int n, blkcnt_t blocks)
{
    char p[64];
    struct stat st;
    path(p, sizeof(p), n);
    CHECK(stat(p, &st) == 0 && st.st_blocks == blocks && (st.st_mode & 0777) == 0644);
}

static void *writer(void *arg)
{
    int n = *(int *)arg;
    char p[64];
    path(p, sizeof(p), n);
    char value[512];
    memset(value, 'a' + n, sizeof(value));
    int barrier = pthread_barrier_wait(&writers_ready);
    if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) return (void *)1;
    if (setxattr(p, "user.shared", value, sizeof(value), XATTR_REPLACE)) return (void *)1;
    return NULL;
}

static void verify(void)
{
    expect_value(0, "user.shared", changed, sizeof(changed));
    expect_value(1, "user.shared", original, sizeof(original));
    expect_value(1, "user.added", "added", 5);
    for (int i = 4; i <= 6; i++) {
        char value[512];
        memset(value, 'a' + i, sizeof(value));
        expect_value(i, "user.shared", value, sizeof(value));
    }
    for (int i = 0; i <= 6; i++) if (i != 3) expect_blocks(i, i == 2 ? 0 : 8);
    expect_blocks(7, 0);
    errno = 0;
    CHECK(getxattr(DIR "/file2", "user.shared", NULL, 0) == -1 && errno == ENODATA);
    CHECK(access(DIR "/file3", F_OK) == -1 && errno == ENOENT);
}

int main(int argc, char **argv)
{
    const char *dev = argc > 1 ? argv[1] : "/dev/vdb";
    struct statfs before, after;
    pthread_t threads[2];
    int ids[2] = {4, 5};
    void *result;
    printf("uid=%ld device=%s\n", (long)getuid(), dev);
    if (argc == 1 && access(dev, F_OK)) {
        FILE *f = fopen("/sys/class/block/vdb/dev", "r");
        unsigned int major_nr, minor_nr;
        CHECK(f && fscanf(f, "%u:%u", &major_nr, &minor_nr) == 2);
        CHECK(mknod(dev, S_IFBLK | 0600, makedev(major_nr, minor_nr)) == 0);
        fclose(f);
    }
    memset(original, 'x', sizeof(original));
    memset(changed, 'y', sizeof(changed));
    mkdir(DIR, 0755);
    CHECK(mount(dev, DIR, "ext2", 0, NULL) == 0);
    CHECK(statfs(DIR, &before) == 0);
    for (int i = 0; i < 8; i++) { expect_value(i, "user.shared", original, sizeof(original)); expect_blocks(i, 8); }
    int fill = open(DIR "/fill", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    CHECK(fill >= 0);
    char block[4096] = {0};
    ssize_t written;
    do { written = write(fill, block, sizeof(block)); } while (written > 0);
    CHECK(written == -1 && errno == ENOSPC);
    errno = 0;
    CHECK(setxattr(DIR "/file0", "user.shared", changed, sizeof(changed), XATTR_REPLACE) == -1 && errno == ENOSPC);
    expect_value(0, "user.shared", original, sizeof(original));
    expect_value(7, "user.shared", original, sizeof(original));
    CHECK(close(fill) == 0);
    CHECK(unlink(DIR "/fill") == 0);
    sync();
    CHECK(statfs(DIR, &before) == 0);
    errno = 0;
    CHECK(setxattr(DIR "/file0", "user.shared", changed, sizeof(changed), XATTR_CREATE) == -1 && errno == EEXIST);
    errno = 0;
    CHECK(setxattr(DIR "/file0", "user.missing", changed, sizeof(changed), XATTR_REPLACE) == -1 && errno == ENODATA);
    char huge[4096] = {0};
    errno = 0;
    CHECK(setxattr(DIR "/file0", "user.huge", huge, sizeof(huge), 0) == -1 && errno == ENOSPC);
    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(bad != MAP_FAILED);
    errno = 0;
    CHECK(setxattr(DIR "/file0", "user.shared", bad, 512, XATTR_REPLACE) == -1 && errno == EFAULT);
    CHECK(munmap(bad, 4096) == 0);
    expect_value(0, "user.shared", original, sizeof(original));
    CHECK(setxattr(DIR "/file0", "user.shared", changed, sizeof(changed), XATTR_REPLACE) == 0);
    CHECK(setxattr(DIR "/file1", "user.added", "added", 5, XATTR_CREATE) == 0);
    CHECK(removexattr(DIR "/file2", "user.shared") == 0);
    CHECK(unlink(DIR "/file3") == 0);
    CHECK(pthread_barrier_init(&writers_ready, NULL, 2) == 0);
    for (int i = 0; i < 2; i++) CHECK(pthread_create(&threads[i], NULL, writer, &ids[i]) == 0);
    for (int i = 0; i < 2; i++) CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    CHECK(pthread_barrier_destroy(&writers_ready) == 0);
    expect_value(7, "user.shared", original, sizeof(original));
    CHECK(chown(DIR "/file6", 1000, 1000) == 0);
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) {
        if (setgid(1000) || setuid(1000)) _exit(2);
        printf("user uid=%ld\n", (long)getuid()); fflush(stdout);
        char value[512];
        memset(value, 'g', sizeof(value));
        _exit(setxattr(DIR "/file6", "user.shared", value, sizeof(value), XATTR_REPLACE) ? 3 : 0);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    expect_value(7, "user.shared", original, sizeof(original));
    CHECK(removexattr(DIR "/file7", "user.shared") == 0);
    sync();
    verify();
    CHECK(statfs(DIR, &after) == 0 && after.f_bfree + 4 == before.f_bfree);
    CHECK(umount(DIR) == 0);
    CHECK(mount(dev, DIR, "ext2", 0, NULL) == 0);
    verify();
    CHECK(umount(DIR) == 0);
    return 0;
}
