// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static volatile sig_atomic_t child = -1;
static volatile sig_atomic_t observer = -1;
static int pipes[2][2] = {{-1, -1}, {-1, -1}};
static char work[PATH_MAX];
static char raw_path[PATH_MAX];
static char renamed_path[PATH_MAX];
static int original = -1;

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); \
    failures++; goto out; \
} } while (0)

static int same_inode(const char *a, const char *b)
{
    struct stat x, y;
    return stat(a, &x) == 0 && stat(b, &y) == 0 &&
           x.st_dev == y.st_dev && x.st_ino == y.st_ino;
}

static int link_equals(const char *path, const char *expected)
{
    char value[PATH_MAX];
    ssize_t n = readlink(path, value, sizeof(value) - 1);
    if (n < 0) {
        fprintf(stderr, "readlink %s: errno=%d\n", path, errno);
        return 0;
    }
    value[n] = 0;
    if (strcmp(value, expected)) fprintf(stderr, "readlink %s: got '%s', expected '%s'\n", path, value, expected);
    return strcmp(value, expected) == 0;
}

static int transfer(int fd, int writing)
{
    char byte = 'x';
    return (writing ? write(fd, &byte, 1) : read(fd, &byte, 1)) == 1;
}

static void reap_owned(volatile sig_atomic_t *pid)
{
    if (*pid > 0) {
        kill(*pid, SIGKILL);
        while (waitpid(*pid, NULL, 0) < 0 && errno == EINTR) {}
        *pid = -1;
    }
}

static void cleanup_child(void)
{
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_BLOCK, &set, &old);
    reap_owned(&observer);
    reap_owned(&child);
    for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) {
        if (pipes[i][j] >= 0) close(pipes[i][j]);
        pipes[i][j] = -1;
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
}

static void alarm_handler(int signal_number)
{
    (void)signal_number;
    cleanup_child();
    if (original >= 0) close(original);
    rmdir(raw_path);
    rmdir(renamed_path);
    rmdir(work);
    const char message[] = "proc_fs_links: timed out\n";
    ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(written == (ssize_t)sizeof(message) - 1 ? 1 : 2);
}

static void close_pipe_end(int i, int j)
{
    close(pipes[i][j]);
    pipes[i][j] = -1;
}

static int start_child(void)
{
    sigset_t set, old;
    if (pipe(pipes[0]) || pipe(pipes[1])) return -1;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &set, &old) < 0) return -1;
    child = fork();
    if (child == 0) {
        close_pipe_end(0, 0);
        close_pipe_end(1, 1);
    } else if (child > 0) {
        close_pipe_end(0, 1);
        close_pipe_end(1, 0);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
    return child < 0 ? -1 : 0;
}

static int wait_owned(volatile sig_atomic_t *pid, int *status)
{
    siginfo_t info = {0};
    sigset_t set, old;
    int rc;
    do { rc = waitid(P_PID, *pid, &info, WEXITED | WNOWAIT); } while (rc < 0 && errno == EINTR);
    if (rc < 0) return 0;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &set, &old) < 0) return 0;
    do { rc = waitpid(*pid, status, 0); } while (rc < 0 && errno == EINTR);
    if (rc == *pid) *pid = -1;
    sigprocmask(SIG_SETMASK, &old, NULL);
    return rc > 0;
}

static int finish_child(void)
{
    int status;
    if (!transfer(pipes[1][1], 1)) return 0;
    if (!wait_owned(&child, &status)) return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void self_links(void)
{
    char cwd[PATH_MAX], alias[128];
    int dot = -1;
    struct stat a, b;
    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    CHECK(link_equals("/proc/self/cwd", cwd));
    CHECK(link_equals("/proc/self/root", "/"));
    CHECK(same_inode("/proc/self/cwd", "."));
    CHECK(same_inode("/proc/self/root", "/"));
    dot = open(".", O_RDONLY | O_DIRECTORY);
    CHECK(dot >= 0 && fstat(dot, &a) == 0 && stat("/proc/self/cwd", &b) == 0);
    CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
    snprintf(alias, sizeof(alias), "/proc/self/task/%ld/cwd", (long)syscall(SYS_gettid));
    CHECK(link_equals(alias, cwd) && same_inode(alias, "."));
    snprintf(alias, sizeof(alias), "/proc/self/task/%ld/root", (long)syscall(SYS_gettid));
    CHECK(link_equals(alias, "/") && same_inode(alias, "/"));
    CHECK(chdir("/proc/self/cwd") == 0 && same_inode(".", cwd));
out:
    if (dot >= 0) close(dot);
}

static void foreign_links(void)
{
    char path[128], target[PATH_MAX];
    CHECK(start_child() == 0);
    if (child == 0) {
        int ok = chdir(work) == 0 && transfer(pipes[0][1], 1) && transfer(pipes[1][0], 0);
        _exit(ok ? 0 : 1);
    }
    CHECK(transfer(pipes[0][0], 0));
    snprintf(path, sizeof(path), "/proc/%ld/cwd", (long)child);
    CHECK(realpath(work, target) != NULL && link_equals(path, target) && same_inode(path, work));
    snprintf(path, sizeof(path), "/proc/%ld/task/%ld/cwd", (long)child, (long)child);
    CHECK(link_equals(path, target) && same_inode(path, work));
    snprintf(path, sizeof(path), "/proc/%ld/root", (long)child);
    CHECK(same_inode(path, "/"));
    snprintf(path, sizeof(path), "/proc/%ld/cwd", (long)child);
    CHECK(transfer(pipes[1][1], 1));
    siginfo_t info = {0};
    CHECK(waitid(P_PID, child, &info, WEXITED | WNOWAIT) == 0);
    char value[PATH_MAX];
    errno = 0;
    CHECK(readlink(path, value, sizeof(value)) == -1 && errno == ENOENT);
    int status;
    CHECK(wait_owned(&child, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    errno = 0;
    CHECK(access(path, F_OK) == -1 && errno == ENOENT);
out:
    cleanup_child();
}

static void rename_deleted(void)
{
    char expected[PATH_MAX], actual[PATH_MAX];
    int n;
    CHECK(mkdir(raw_path, 0700) == 0 && chdir(raw_path) == 0);
    CHECK(getcwd(expected, sizeof(expected)) && link_equals("/proc/self/cwd", expected));
    CHECK(rename(raw_path, renamed_path) == 0);
    CHECK(getcwd(expected, sizeof(expected)) && link_equals("/proc/self/cwd", expected));
    CHECK(same_inode("/proc/self/cwd", "."));
    CHECK(rmdir(renamed_path) == 0);
    n = snprintf(actual, sizeof(actual), "%s (deleted)", expected);
    CHECK(n > 0 && (size_t)n < sizeof(actual));
    CHECK(link_equals("/proc/self/cwd", actual) && same_inode("/proc/self/cwd", "."));
out:
    if (original >= 0 && fchdir(original) != 0) failures++;
    rmdir(raw_path);
    rmdir(renamed_path);
}

static void chroot_cases(void)
{
    CHECK(start_child() == 0);
    if (child == 0) {
        int rc = chroot("/proc/self/root");
        _exit(geteuid() == 0 ? (rc == 0 ? 0 : 1) : (rc == -1 && errno == EPERM ? 0 : 1));
    }
    int status;
    CHECK(wait_owned(&child, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    cleanup_child();
    if (geteuid() != 0) return;
    CHECK(start_child() == 0);
    if (child == 0) {
        int ok = chroot(work) == 0 && chdir("/") == 0 &&
                 transfer(pipes[0][1], 1) && transfer(pipes[1][0], 0);
        _exit(ok ? 0 : 1);
    }
    CHECK(transfer(pipes[0][0], 0));
    char path[128];
    snprintf(path, sizeof(path), "/proc/%ld/root", (long)child);
    CHECK(same_inode(path, work));
    CHECK(finish_child());
out:
    cleanup_child();
}

static int drop_caps(void)
{
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2] = {{0}};
    return syscall(SYS_capset, &h, d) == 0;
}

static void access_case(int mode)
{
    int status;
    CHECK(start_child() == 0);
    if (child == 0) {
        int ok = 1;
        if (mode == 0 || mode == 1 || mode == 2) ok = setgid(1001) == 0 && setuid(1001) == 0;
        if (mode == 1) ok = ok && prctl(PR_SET_DUMPABLE, 0) == 0;
        if (mode == 2) ok = ok && prctl(PR_SET_DUMPABLE, 1) == 0;
        ok = ok && transfer(pipes[0][1], 1) && transfer(pipes[1][0], 0);
        _exit(ok ? 0 : 1);
    }
    CHECK(transfer(pipes[0][0], 0));
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    CHECK(sigprocmask(SIG_BLOCK, &set, &old) == 0);
    observer = fork();
    if (observer == 0) {
        close_pipe_end(0, 0);
        close_pipe_end(1, 1);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
    CHECK(observer >= 0);
    if (observer == 0) {
        char path[128], buf[PATH_MAX];
        int ok;
        if (mode == 2) {
            setfsgid(1001);
            setfsuid(1001);
            ok = setfsgid((gid_t)-1) == 1001 && setfsuid((uid_t)-1) == 1001 && drop_caps();
        } else {
            ok = setgid(mode == 0 ? 1002 : 1001) == 0 &&
                 setuid(mode == 0 ? 1002 : 1001) == 0;
            if (mode == 1) ok = ok && prctl(PR_SET_DUMPABLE, 1) == 0;
        }
        const char *links[] = {"cwd", "root"};
        for (int i = 0; i < 2; i++) {
            snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, links[i]);
            errno = 0;
            ssize_t result = readlink(path, buf, sizeof(buf));
            if ((mode == 2 && result < 0) ||
                (mode != 2 && (result != -1 || errno != EACCES)))
                dprintf(STDERR_FILENO, "access mode=%d link=%s result=%zd errno=%d\n", mode, links[i], result, errno);
            if (mode == 2) ok = ok && result >= 0;
            else ok = ok && result == -1 && errno == EACCES;
        }
        _exit(ok ? 0 : 1);
    }
    CHECK(wait_owned(&observer, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(finish_child());
out:
    cleanup_child();
}

static void pivot_control(void)
{
    int status;
    CHECK(start_child() == 0);
    if (child == 0) {
        int ok = unshare(CLONE_NEWNS) == 0 &&
                 mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0 && chdir("/") == 0;
        if (ok) {
            errno = 0;
            long result = syscall(SYS_pivot_root, "/proc/self/cwd", "/proc/self/root");
            ok = result == -1 && errno == EBUSY;
            if (!ok) dprintf(STDERR_FILENO, "pivot control: result=%ld errno=%d\n", result, errno);
        } else {
            dprintf(STDERR_FILENO, "pivot control: setup errno=%d\n", errno);
        }
        _exit(ok ? 0 : 1);
    }
    CHECK(wait_owned(&child, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0);
out:
    cleanup_child();
}

int main(void)
{
    const char *base = getenv("TMPDIR");
    char resolved[PATH_MAX];
    struct sigaction action = {0};
    if (!base || !*base) base = ".";
    int n = snprintf(work, sizeof(work), "%s/proc-fs-links-XXXXXX", base);
    if (n <= 0 || (size_t)n >= sizeof(work) || !mkdtemp(work)) return 1;
    original = open(".", O_RDONLY | O_DIRECTORY);
    if (original < 0 || !realpath(work, resolved)) goto init_failed;
    memcpy(work, resolved, strlen(resolved) + 1);
    n = snprintf(raw_path, sizeof(raw_path), "%s/\xff", work);
    if (n <= 0 || (size_t)n >= sizeof(raw_path)) goto init_failed;
    n = snprintf(renamed_path, sizeof(renamed_path), "%s/renamed", work);
    if (n <= 0 || (size_t)n >= sizeof(renamed_path)) goto init_failed;
    action.sa_handler = alarm_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) < 0) goto init_failed;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) goto init_failed;
    alarm(30);
    self_links();
    if (failures) goto out;
    foreign_links();
    if (failures) goto out;
    chroot_cases();
    if (failures) goto out;
    if (geteuid() == 0) {
        access_case(0);
        if (failures) goto out;
        access_case(1);
        if (failures) goto out;
        access_case(2);
        if (failures) goto out;
        pivot_control();
        if (failures) goto out;
    }
    rename_deleted();
out:
    alarm(0);
    cleanup_child();
    close(original);
    if (rmdir(work) != 0) failures++;
    return failures ? 1 : 0;
init_failed:
    if (original >= 0) close(original);
    rmdir(work);
    return 1;
}
