// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/xattr.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid;
static pid_t owner;
static int fds[4] = {-1, -1, -1, -1};
static char dir[4096], paths[4][4096];
static void *stack;
static const size_t stack_size = 1024 * 1024;

static void cleanup(void)
{
    if (getpid() != owner) return;
    sigset_t set, old; sigemptyset(&set); sigaddset(&set, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &set, &old) < 0) _exit(1);
    if (child_pid > 0) { kill(child_pid, SIGKILL); while (waitpid(child_pid, NULL, 0) < 0 && errno == EINTR) {} child_pid = 0; }
    for (int i = 0; i < 4; i++) if (fds[i] >= 0) { close(fds[i]); fds[i] = -1; }
    if (stack) { munmap(stack, stack_size); stack = NULL; }
    for (int i = 0; i < 4; i++) if (paths[i][0]) unlink(paths[i]);
    if (dir[0]) rmdir(dir);
    if (sigprocmask(SIG_SETMASK, &old, NULL) < 0) _exit(1);
}
static void timeout(int sig)
{
    (void)sig;
    if (child_pid > 0) { kill(child_pid, SIGKILL); while (waitpid(child_pid, NULL, 0) < 0 && errno == EINTR) {} child_pid = 0; }
    for (int i = 0; i < 4; i++) if (fds[i] >= 0) close(fds[i]);
    for (int i = 0; i < 4; i++) if (paths[i][0]) unlink(paths[i]);
    if (dir[0]) rmdir(dir);
    (void)!write(2, "dumpability: timeout\n", 21);
    _exit(1);
}
static void fail(const char *expr, int line)
{
    int e = errno;
    dprintf(2, "dumpability:%d: %s (errno %d: %s)\n", line, expr, e, strerror(e));
    cleanup();
    _exit(1);
}
#define CHECK(x) do { if (!(x)) fail(#x, __LINE__); } while (0)
static void block_alarm(sigset_t *old)
{
    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGALRM);
    CHECK(sigprocmask(SIG_BLOCK, &set, old) == 0);
}
static pid_t spawn(void)
{
    sigset_t old; block_alarm(&old);
    pid_t p = fork();
    if (p > 0) child_pid = p;
    CHECK(sigprocmask(SIG_SETMASK, &old, NULL) == 0);
    CHECK(p >= 0); return p;
}
static void reap(pid_t p)
{
    int status; siginfo_t info;
    int observed; do { observed = waitid(P_PID, p, &info, WEXITED | WNOWAIT); } while (observed < 0 && errno == EINTR);
    CHECK(observed == 0);
    sigset_t old; block_alarm(&old);
    pid_t r; do { r = waitpid(p, &status, 0); } while (r < 0 && errno == EINTR);
    if (r == p) child_pid = 0;
    CHECK(sigprocmask(SIG_SETMASK, &old, NULL) == 0);
    CHECK(r == p && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static void dump(int v) { CHECK(prctl(PR_SET_DUMPABLE, v, 0, 0, 0) == 0); CHECK(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == v); }
static void check_dump(int v) { CHECK(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == v); }
static void byte_write(int fd) { char c = 'x'; ssize_t n; do { n = write(fd, &c, 1); } while (n < 0 && errno == EINTR); CHECK(n == 1); }
static void byte_read(int fd) { char c; ssize_t n; do { n = read(fd, &c, 1); } while (n < 0 && errno == EINTR); CHECK(n == 1 && c == 'x'); }
static void caps(struct __user_cap_data_struct data[2], int set)
{
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    CHECK(syscall(set ? SYS_capset : SYS_capget, &h, data) == 0);
}
static void empty_caps(void) { struct __user_cap_data_struct d[2] = {{0}}; caps(d, 1); }
static void drop_ids(void) { CHECK(setresgid(1001, 1001, 1001) == 0); CHECK(setresuid(1001, 1001, 1001) == 0); }
static int shared_child(void *arg) { (void)arg; dump(1); _exit(0); }
static void lifecycle(void)
{
    check_dump(1); dump(0); dump(1);
    int invalid[] = {2, -1, 3};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) { errno = 0; CHECK(prctl(PR_SET_DUMPABLE, invalid[i], 0, 0, 0) == -1 && errno == EINVAL); check_dump(1); }
    CHECK(setuid(geteuid()) == 0); CHECK(setgid(getegid()) == 0);
    CHECK(setreuid(-1, geteuid()) == 0); CHECK(setregid(-1, getegid()) == 0);
    CHECK(setresuid(-1, geteuid(), -1) == 0); CHECK(setresgid(-1, getegid(), -1) == 0);
    CHECK((uid_t)setfsuid(geteuid()) == geteuid()); CHECK((gid_t)setfsgid(getegid()) == getegid()); check_dump(1);
    pid_t p = spawn(); if (!p) { if (geteuid() == 0) drop_ids(); dump(1); errno = 0; CHECK(setuid(12345) == -1 && errno == EPERM); check_dump(1); _exit(0); } reap(p);
    dump(0); p = spawn(); if (!p) { check_dump(0); dump(1); _exit(0); } reap(p); check_dump(0);
    stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0); CHECK(stack != MAP_FAILED);
    sigset_t old; block_alarm(&old); p = clone(shared_child, (char *)stack + stack_size, CLONE_VM | SIGCHLD, NULL); if (p > 0) child_pid = p; CHECK(sigprocmask(SIG_SETMASK, &old, NULL) == 0); CHECK(p > 0); reap(p); check_dump(1); CHECK(munmap(stack, stack_size) == 0); stack = NULL;
    dump(0); errno = 0; execl("/definitely-not-a-dumpability-executable", "missing", NULL); CHECK(errno == ENOENT); check_dump(0);
    p = spawn(); if (!p) { CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0); execl("/proc/self/exe", "dumpability", "--exec-check", "1", "-1", "-1", "keep-reset", NULL); fail("ordinary exec", __LINE__); } reap(p); check_dump(0);
}
static void identities(void)
{
    for (int i = 0; i < 10; i++) {
        pid_t p = spawn(); if (!p) {
            dump(1);
            switch (i) {
            case 0: CHECK(setuid(1001) == 0); break;
            case 1: CHECK(setreuid(-1, 1001) == 0); break;
            case 2: CHECK(setresuid(-1, 1001, -1) == 0); break;
            case 3: CHECK(setgid(1001) == 0); break;
            case 4: CHECK(setregid(-1, 1001) == 0); break;
            case 5: CHECK(setresgid(-1, 1001, -1) == 0); break;
            case 6: CHECK(setfsuid(1001) == 0); CHECK(setfsuid(-1) == 1001); break;
            case 7: CHECK(setfsgid(1001) == 0); CHECK(setfsgid(-1) == 1001); break;
            case 8: CHECK(setresuid(1001, 0, 0) == 0); break;
            case 9: CHECK(setresgid(1001, 0, 0) == 0); break;
            } check_dump(i >= 8 ? 1 : 0); _exit(0);
        } reap(p);
    }
}
static void copy_self(const char *dest, mode_t mode)
{
    int in = open("/proc/self/exe", O_RDONLY), out = -1; CHECK(in >= 0);
    out = open(dest, O_CREAT | O_EXCL | O_WRONLY, 0600); if (out < 0) { close(in); fail("create fixture", __LINE__); }
    char buf[16384]; ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) { ssize_t pos = 0; while (pos < n) { ssize_t w = write(out, buf + pos, n - pos); if (w <= 0) { close(in); close(out); fail("write fixture", __LINE__); } pos += w; } }
    if (n < 0 || fchmod(out, mode) < 0) { close(in); close(out); fail("finish fixture", __LINE__); }
    CHECK(close(in) == 0); CHECK(close(out) == 0);
}
static void exec_fixtures(void)
{
    const char *tmp = getenv("TMPDIR"); if (!tmp || !*tmp) tmp = ".";
    int length = snprintf(dir, sizeof(dir), "%s/dumpability-XXXXXX", tmp); CHECK(length >= 0 && length < (int)sizeof(dir)); CHECK(mkdtemp(dir) != NULL); CHECK(chmod(dir, 0755) == 0);
    char resolved[4096]; CHECK(realpath(dir, resolved) != NULL); CHECK(strlen(resolved) < sizeof(dir)); strcpy(dir, resolved);
    const mode_t modes[] = {04755, 02755, 0111, 0755};
    for (int i = 0; i < 4; i++) { length = snprintf(paths[i], sizeof(paths[i]), "%s/image%d", dir, i); CHECK(length >= 0 && length < (int)sizeof(paths[i])); copy_self(paths[i], modes[i]); }
    struct vfs_cap_data cap = {0}; cap.magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE; cap.data[0].permitted = 1u << CAP_NET_BIND_SERVICE;
    CHECK(setxattr(paths[3], "security.capability", &cap, sizeof(cap), 0) == 0);
    for (int i = 0; i < 4; i++) {
        pid_t p = spawn(); if (!p) { drop_ids(); dump(1); execl(paths[i], "dumpability", "--exec-check", "0", i == 0 ? "0" : "1001", i == 1 ? "0" : "1001", i == 3 ? "cap" : "none", NULL); fail("fixture exec", __LINE__); } reap(p);
    }
}
static void maps_with_caps(const char *path, struct __user_cap_data_struct reduced[2],
                           struct __user_cap_data_struct saved[2], int denied)
{
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    sigset_t old; block_alarm(&old);
    int changed = syscall(SYS_capset, &h, reduced);
    int fd = -1, error = 0;
    if (changed == 0) { errno = 0; fd = open(path, O_RDONLY); error = errno; }
    int restored = syscall(SYS_capset, &h, saved);
    CHECK(sigprocmask(SIG_SETMASK, &old, NULL) == 0);
    if (fd >= 0 && denied) { close(fd); fd = -2; }
    CHECK(restored == 0); CHECK(changed == 0);
    if (denied) { CHECK(fd == -1 && error == EACCES); }
    else { errno = error; CHECK(fd >= 0); CHECK(close(fd) == 0); }
}
static void proc_maps(void)
{
    int root = geteuid() == 0;
    int ready[2], release[2]; CHECK(pipe(ready) == 0); fds[0] = ready[0]; fds[1] = ready[1]; CHECK(pipe(release) == 0); fds[2] = release[0]; fds[3] = release[1];
    pid_t p = spawn(); if (!p) {
        close(ready[0]); close(release[1]);
        if (root) {
            struct __user_cap_data_struct target[2] = {{0}};
            target[0].permitted = target[0].effective = 1u << CAP_NET_BIND_SERVICE;
            caps(target, 1); dump(1); byte_write(ready[1]); byte_read(release[0]);
        }
        empty_caps(); dump(0); byte_write(ready[1]); byte_read(release[0]); dump(1); byte_write(ready[1]); byte_read(release[0]); close(ready[1]); close(release[0]); _exit(0);
    }
    close(ready[1]); fds[1] = -1; close(release[0]); fds[2] = -1; byte_read(ready[0]);
    char path[64]; int length = snprintf(path, sizeof(path), "/proc/%ld/maps", (long)p); CHECK(length >= 0 && length < (int)sizeof(path));
    struct __user_cap_data_struct saved[2] = {{0}}, reduced[2]; caps(saved, 0); memcpy(reduced, saved, sizeof(saved));
    if (root) {
        uint32_t required = (1u << CAP_SYS_PTRACE) | (1u << CAP_NET_BIND_SERVICE);
        CHECK((saved[0].effective & required) == required);
        reduced[0].effective &= ~required;
        maps_with_caps(path, reduced, saved, 1);
        reduced[0].effective |= 1u << CAP_NET_BIND_SERVICE;
        maps_with_caps(path, reduced, saved, 0);
        byte_write(release[1]); byte_read(ready[0]);
        int fd = open(path, O_RDONLY); CHECK(fd >= 0); CHECK(close(fd) == 0);
    }
    memcpy(reduced, saved, sizeof(saved)); reduced[0].effective &= ~(1u << CAP_SYS_PTRACE);
    maps_with_caps(path, reduced, saved, 1);
    byte_write(release[1]); byte_read(ready[0]);
    maps_with_caps(path, reduced, saved, 0);
    byte_write(release[1]); close(ready[0]); fds[0] = -1; close(release[1]); fds[3] = -1; reap(p);
    dump(0); int fd = open("/proc/self/maps", O_RDONLY); CHECK(fd >= 0); CHECK(close(fd) == 0);
}
int main(int argc, char **argv)
{
    if ((argc == 5 || argc == 6) && strcmp(argv[1], "--exec-check") == 0) { check_dump(atoi(argv[2])); if (atoi(argv[3]) >= 0) CHECK(geteuid() == (uid_t)atoi(argv[3])); if (atoi(argv[4]) >= 0) CHECK(getegid() == (gid_t)atoi(argv[4])); if (argc == 6 && strcmp(argv[5], "keep-reset") == 0) CHECK(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0); if (argc == 6 && strcmp(argv[5], "cap") == 0) { struct __user_cap_data_struct d[2] = {{0}}; caps(d, 0); CHECK((d[0].permitted & (1u << CAP_NET_BIND_SERVICE)) && (d[0].effective & (1u << CAP_NET_BIND_SERVICE))); } return 0; }
    owner = getpid(); CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR); struct sigaction sa = {.sa_handler = timeout}; sigemptyset(&sa.sa_mask); CHECK(sigaction(SIGALRM, &sa, NULL) == 0); alarm(60);
    lifecycle(); if (geteuid() == 0) { identities(); exec_fixtures(); } else puts("dumpability: root-only credential and exec cohort not run"); proc_maps(); cleanup(); alarm(0); puts("DUMPABILITY_PASS"); return 0;
}
