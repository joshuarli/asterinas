// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static ino_t expected;
static const char *kind;
static int clone_flag;

static void check(const char *path)
{
    char link[128], prefix[32], extra;
    unsigned long long ino;
    struct stat st;
    ssize_t n = readlink(path, link, sizeof(link) - 1);
    if (n < 0) { perror(path); exit(1); }
    link[n] = 0;
    snprintf(prefix, sizeof(prefix), "%s:[", kind);
    if (strncmp(link, prefix, strlen(prefix)) ||
        sscanf(link + strlen(prefix), "%llu]%c", &ino, &extra) != 1 || !ino) {
        fprintf(stderr, "bad link %s: %s\n", path, link); exit(1);
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &st) || st.st_ino != ino || (expected && st.st_ino != expected)) {
        fprintf(stderr, "bad namespace handle %s\n", path); exit(1);
    }
    expected = st.st_ino;
    if (ioctl(fd, NS_GET_NSTYPE) != clone_flag) {
        fprintf(stderr, "bad namespace type %s\n", path); exit(1);
    }
    int owner = ioctl(fd, NS_GET_USERNS);
    struct stat owner_st, user_st;
    if (owner < 0 || fstat(owner, &owner_st) ||
        stat("/proc/self/ns/user", &user_st) || owner_st.st_ino != user_st.st_ino) {
        fprintf(stderr, "bad namespace owner %s\n", path); exit(1);
    }
    close(owner);
    errno = 0;
    if (ioctl(fd, NS_GET_PARENT) != -1 ||
        errno != (clone_flag == CLONE_NEWPID ? EPERM : EINVAL)) {
        fprintf(stderr, "bad namespace parent %s: %d\n", path, errno); exit(1);
    }
    close(fd);
}

static void *thread_fn(void *unused)
{
    char path[128];
    (void)unused;
    snprintf(path, sizeof(path), "/proc/self/task/%ld/ns/%s", syscall(SYS_gettid), kind);
    check(path);
    return NULL;
}

static void check_kind(void)
{
    DIR *dir = opendir("/proc/self/ns");
    struct dirent *entry;
    int found = 0, status;
    pthread_t thread;
    char path[128];
    if (!dir) { perror("opendir"); exit(1); }
    while ((entry = readdir(dir))) found += !strcmp(entry->d_name, kind);
    closedir(dir);
    if (found != 1) { fprintf(stderr, "%s entries: %d\n", kind, found); exit(1); }
    snprintf(path, sizeof(path), "/proc/self/ns/%s", kind);
    check(path);
    if (pthread_create(&thread, NULL, thread_fn, NULL) || pthread_join(thread, NULL)) exit(1);
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (!pid) { check(path); _exit(0); }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) exit(1);
    printf("%s namespace discovery, identity and ioctls passed\n", kind);
}

int main(void)
{
    kind = "net";
    clone_flag = CLONE_NEWNET;
    check_kind();
    expected = 0;
    kind = "pid";
    clone_flag = CLONE_NEWPID;
    check_kind();
    return 0;
}
