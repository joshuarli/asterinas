// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)

static int ready[2], release_thread[2], release_child[2];
struct report { pid_t tid, child; };

static void transfer(int fd, void *buf, size_t len, int writing)
{
    char *p = buf;
    while (len) {
        ssize_t n = writing ? write(fd, p, len) : read(fd, p, len);
        CHECK(n > 0);
        p += n;
        len -= (size_t)n;
    }
}

static void check_task_children(pid_t pid, pid_t tid, const pid_t *expected, size_t count)
{
    char path[128], buf[4096];
    CHECK(snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, tid) > 0);
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    size_t used = 0;
    for (;;) {
        CHECK(used < sizeof(buf) - 1);
        ssize_t n = read(fd, buf + used, sizeof(buf) - 1 - used);
        CHECK(n >= 0);
        if (!n) break;
        used += (size_t)n;
    }
    CHECK(close(fd) == 0);
    buf[used] = '\0';
    size_t seen = 0;
    int found[16] = {0};
    CHECK(count <= sizeof(found) / sizeof(found[0]));
    char *p = buf;
    while (*p) {
        CHECK(isdigit((unsigned char)*p));
        char *end;
        errno = 0;
        long id = strtol(p, &end, 10);
        CHECK(!errno && id > 0 && (*end == '\0' || isspace((unsigned char)*end)));
        size_t i;
        for (i = 0; i < count; i++) if (expected[i] == id && !found[i]) break;
        CHECK(i < count);
        found[i] = 1;
        seen++;
        p = end;
        while (isspace((unsigned char)*p)) p++;
    }
    CHECK(seen == count);
    if (!count) CHECK(used == 0);
}

static void check_children(pid_t tid, const pid_t *expected, size_t count)
{
    check_task_children(getpid(), tid, expected, count);
}

static void *worker(void *unused)
{
    (void)unused;
    struct report r = { .tid = (pid_t)syscall(SYS_gettid) };
    r.child = fork();
    CHECK(r.child >= 0);
    if (!r.child) {
        char c;
        transfer(release_child[0], &c, 1, 0);
        _exit(0);
    }
    transfer(ready[1], &r, sizeof(r), 1);
    char c;
    transfer(release_thread[0], &c, 1, 0);
    return NULL;
}

static int exec_gate[2];

static void *exec_worker(void *unused)
{
    (void)unused;
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char c;
        transfer(exec_gate[0], &c, 1, 0);
        _exit(0);
    }
    CHECK(close(exec_gate[0]) == 0);
    char pid_arg[32], fd_arg[32];
    CHECK(snprintf(pid_arg, sizeof(pid_arg), "%d", child) > 0);
    CHECK(snprintf(fd_arg, sizeof(fd_arg), "%d", exec_gate[1]) > 0);
    execl("/proc/self/exe", "proc_task_children", "exec-check", pid_arg, fd_arg, (char *)NULL);
    _exit(127);
}

static void check_nonleader_exec(void)
{
    CHECK(pipe(exec_gate) == 0);
    pid_t process = fork();
    CHECK(process >= 0);
    if (!process) {
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, exec_worker, NULL) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        _exit(1);
    }
    CHECK(close(exec_gate[0]) == 0 && close(exec_gate[1]) == 0);
    int status;
    CHECK(waitpid(process, &status, 0) == process);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void check_subreaper(pid_t leader)
{
    int report[2], gate[2];
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    CHECK(pipe(report) == 0 && pipe(gate) == 0);
    pid_t intermediate = fork();
    CHECK(intermediate >= 0);
    if (!intermediate) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            char c;
            transfer(gate[0], &c, 1, 0);
            _exit(0);
        }
        transfer(report[1], &child, sizeof(child), 1);
        _exit(0);
    }
    pid_t child;
    transfer(report[0], &child, sizeof(child), 0);
    CHECK(waitpid(intermediate, NULL, 0) == intermediate);
    check_children(leader, &child, 1);
    char c = 'x';
    transfer(gate[1], &c, 1, 1);
    CHECK(waitpid(child, NULL, 0) == child);
    check_children(leader, NULL, 0);
    CHECK(close(report[0]) == 0 && close(report[1]) == 0);
    CHECK(close(gate[0]) == 0 && close(gate[1]) == 0);
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 0) == 0);
}

static void check_clone_parent(pid_t leader)
{
    int report[2], gate[2];
    CHECK(pipe(report) == 0 && pipe(gate) == 0);
    pid_t caller = fork();
    CHECK(caller >= 0);
    if (!caller) {
        pid_t sibling = (pid_t)syscall(SYS_clone, CLONE_PARENT | SIGCHLD, 0, 0, 0, 0);
        CHECK(sibling >= 0);
        if (!sibling) {
            char c;
            transfer(gate[0], &c, 1, 0);
            _exit(0);
        }
        transfer(report[1], &sibling, sizeof(sibling), 1);
        char c;
        transfer(gate[0], &c, 1, 0);
        _exit(0);
    }
    pid_t sibling;
    transfer(report[0], &sibling, sizeof(sibling), 0);
    CHECK(sibling > 0);
    pid_t expected[] = { caller, sibling };
    check_children(leader, expected, 2);
    char tokens[] = { 'x', 'x' };
    transfer(gate[1], tokens, sizeof(tokens), 1);
    CHECK(waitpid(caller, NULL, 0) == caller);
    CHECK(waitpid(sibling, NULL, 0) == sibling);
    check_children(leader, NULL, 0);
    CHECK(close(report[0]) == 0 && close(report[1]) == 0);
    CHECK(close(gate[0]) == 0 && close(gate[1]) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "exec-check") == 0) {
        pid_t child = (pid_t)strtol(argv[2], NULL, 10);
        int fd = (int)strtol(argv[3], NULL, 10);
        CHECK(child > 0 && fd >= 0);
        check_children((pid_t)syscall(SYS_gettid), &child, 1);
        char c = 'x';
        transfer(fd, &c, 1, 1);
        CHECK(waitpid(child, NULL, 0) == child);
        CHECK(close(fd) == 0);
        return 0;
    }
    CHECK(argc == 1);
    char process_alias[64];
    CHECK(snprintf(process_alias, sizeof(process_alias), "/proc/%d/children", getpid()) > 0);
    errno = 0;
    CHECK(open(process_alias, O_RDONLY) == -1 && errno == ENOENT);
    pid_t leader = (pid_t)syscall(SYS_gettid);
    CHECK(pipe(ready) == 0 && pipe(release_thread) == 0 && pipe(release_child) == 0);
    check_children(leader, NULL, 0);
    check_clone_parent(leader);
    check_subreaper(leader);
    check_nonleader_exec();
    pid_t own_child = fork();
    CHECK(own_child >= 0);
    if (!own_child) {
        char c;
        transfer(release_child[0], &c, 1, 0);
        _exit(0);
    }
    check_children(leader, &own_child, 1);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    struct report r;
    transfer(ready[0], &r, sizeof(r), 0);
    CHECK(r.tid != leader && r.child > 0);
    check_children(leader, &own_child, 1);
    check_children(r.tid, &r.child, 1);
    char c = 'x';
    transfer(release_thread[1], &c, 1, 1);
    CHECK(pthread_join(thread, NULL) == 0);
    pid_t both[] = { own_child, r.child };
    check_children(leader, both, 2);
    char tokens[] = { 'x', 'x' };
    transfer(release_child[1], tokens, sizeof(tokens), 1);
    CHECK(waitpid(own_child, NULL, 0) == own_child);
    siginfo_t info = {0};
    CHECK(waitid(P_PID, (id_t)r.child, &info, WEXITED | WNOWAIT) == 0);
    CHECK(info.si_pid == r.child);
    check_children(leader, &r.child, 1);
    check_task_children(r.child, r.child, NULL, 0);
    CHECK(waitpid(r.child, NULL, 0) == r.child);
    check_children(leader, NULL, 0);
    char child_path[64];
    CHECK(snprintf(child_path, sizeof(child_path), "/proc/%d/task/%d/children", r.child, r.child) > 0);
    errno = 0;
    CHECK(open(child_path, O_RDONLY) == -1 && errno == ENOENT);
    char path[128];
    CHECK(snprintf(path, sizeof(path), "/proc/%d/task/%d/children", getpid(), r.tid) > 0);
    errno = 0;
    CHECK(open(path, O_RDONLY) == -1 && errno == ENOENT);
    CHECK(close(ready[0]) == 0 && close(ready[1]) == 0);
    CHECK(close(release_thread[0]) == 0 && close(release_thread[1]) == 0);
    CHECK(close(release_child[0]) == 0 && close(release_child[1]) == 0);
    return 0;
}
