// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PRIO(class, level) (((class) << 13) | (level))

static long get_priority(int which, int who)
{
    long priority = syscall(SYS_ioprio_get, which, who);
    assert(priority >= 0);
    return priority;
}

static void set_priority(int which, int who, int priority)
{
    assert(syscall(SYS_ioprio_set, which, who, priority) == 0);
}

static void wait_child(pid_t child)
{
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

struct sched_attribute {
    uint32_t size;
    uint32_t policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime;
    uint64_t deadline;
    uint64_t period;
    uint32_t util_min;
    uint32_t util_max;
};

static void set_nice(pid_t tid, int nice)
{
    struct sched_attribute attribute = { .size = sizeof(attribute), .nice = nice };
    assert(syscall(SYS_sched_setattr, tid, &attribute, 0) == 0);
}

static void check_reset_child(int nice)
{
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setsid() == getpid());
        assert(sched_getscheduler(0) == SCHED_OTHER);
        long actual = get_priority(2, 0);
        if (actual != PRIO(2, (nice + 20) / 5))
            fprintf(stderr, "reset expected nice=%d actual priority=%ld actual nice=%d\n", nice, actual, getpriority(PRIO_PROCESS, 0));
        assert(actual == PRIO(2, (nice + 20) / 5));
        _exit(0);
    }
    wait_child(child);
}

struct thread_args {
    int ready;
    int release;
};

static void *thread_main(void *argument)
{
    struct thread_args *args = argument;
    set_priority(1, 0, PRIO(2, 7));
    set_nice(0, 10);
    pid_t tid = (pid_t)syscall(SYS_gettid);
    assert(write(args->ready, &tid, sizeof(tid)) == sizeof(tid));
    char byte;
    assert(read(args->release, &byte, 1) == 0);
    return NULL;
}

struct target {
    pid_t pid;
    pid_t tid;
    int release;
};

static struct target start_target(uid_t real, uid_t effective)
{
    int ready[2], release[2];
    assert(pipe(ready) == 0 && pipe(release) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        assert(setresuid(real, effective, real) == 0);
        set_priority(1, 0, PRIO(2, 6));
        struct thread_args args = {ready[1], release[0]};
        pthread_t thread;
        assert(pthread_create(&thread, NULL, thread_main, &args) == 0);
        char byte;
        assert(read(release[0], &byte, 1) == 0);
        assert(pthread_join(thread, NULL) == 0);
        close(ready[1]);
        close(release[0]);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    pid_t tid;
    assert(read(ready[0], &tid, sizeof(tid)) == sizeof(tid));
    close(ready[0]);
    assert(tid != child && tid > 0);
    return (struct target){child, tid, release[1]};
}

static void stop_target(struct target target)
{
    close(target.release);
    wait_child(target.pid);
}

static void expect_target(struct target target, int priority)
{
    assert(get_priority(1, target.pid) == priority);
    assert(get_priority(1, target.tid) == priority);
}

static void fallback_cases(void)
{
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setsid() == getpid());
        set_priority(1, 0, 0);
        assert(get_priority(1, 0) == 0);
        assert(get_priority(2, 0) == PRIO(2, 4));
        assert(get_priority(2, getpgrp()) == PRIO(2, 4));
        set_priority(1, 0, 8);
        assert(get_priority(1, 0) == 8);
        assert(get_priority(2, 0) == PRIO(2, 4));
        assert(setpriority(PRIO_PROCESS, 0, 5) == 0);
        assert(getpriority(PRIO_PROCESS, 0) == 5);
        assert(get_priority(2, 0) == PRIO(2, 5));
        struct sched_param parameter = {0};
        assert(sched_setscheduler(0, SCHED_IDLE, &parameter) == 0);
        assert(get_priority(2, 0) == PRIO(3, 5));
        parameter.sched_priority = 1;
        assert(sched_setscheduler(0, SCHED_FIFO, &parameter) == 0);
        assert(get_priority(2, 0) == PRIO(1, 5));
        set_nice(0, 10);
        assert(get_priority(2, 0) == PRIO(2, 6));
        assert(sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &parameter) == 0);
        assert(get_priority(2, 0) == PRIO(1, 6));
        check_reset_child(0);
        set_nice(0, -5);
        assert(sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &parameter) == 0);
        assert(get_priority(2, 0) == PRIO(1, 3));
        check_reset_child(0);
        _exit(0);
    }
    wait_child(child);
}

static void selector_cases(void)
{
    assert(setsid() == getpid());
    struct target first = start_target(65532, 65533);
    struct target second = start_target(65533, 65532);
    set_priority(2, 0, PRIO(3, 0));
    assert(get_priority(1, 0) == PRIO(3, 0));
    expect_target(first, PRIO(3, 0));
    expect_target(second, PRIO(3, 0));
    assert(get_priority(2, getpgrp()) == PRIO(3, 0));
    set_priority(1, first.tid, PRIO(2, 2));
    assert(get_priority(1, first.pid) == PRIO(3, 0));
    assert(get_priority(2, 0) == PRIO(2, 2));
    assert(get_priority(3, 65532) == PRIO(2, 2));
    assert(get_priority(3, 65533) == PRIO(3, 0));
    set_priority(1, first.tid, 0);
    assert(get_priority(3, 65532) == PRIO(2, 6));
    struct sched_param parameter = { .sched_priority = 1 };
    assert(sched_setscheduler(first.tid, SCHED_FIFO, &parameter) == 0);
    assert(get_priority(3, 65532) == PRIO(1, 6));
    set_priority(3, 65532, PRIO(2, 5));
    expect_target(first, PRIO(2, 5));
    expect_target(second, PRIO(3, 0));
    set_priority(2, getpgrp(), PRIO(2, 6));
    expect_target(first, PRIO(2, 6));
    expect_target(second, PRIO(2, 6));
    assert(get_priority(1, 0) == PRIO(2, 6));
    set_priority(1, first.tid, PRIO(1, 3));
    assert(get_priority(2, 0) == PRIO(1, 3));
    assert(get_priority(3, 65532) == PRIO(1, 3));
    set_priority(1, first.tid, PRIO(2, 6));
    pid_t actor = fork();
    assert(actor >= 0);
    if (actor == 0) {
        assert(setresuid(65532, 65532, 65532) == 0);
        set_priority(1, 0, PRIO(3, 0));
        assert(get_priority(3, 0) == PRIO(2, 6));
        long foreign_before = get_priority(1, second.pid);
        errno = 0;
        assert(syscall(SYS_ioprio_set, 2, 0, PRIO(3, 0)) == -1 && errno == EPERM);
        assert(get_priority(1, second.pid) == foreign_before);
        errno = 0;
        assert(syscall(SYS_ioprio_set, 3, 0, PRIO(2, 3)) == -1 && errno == EPERM);
        assert(get_priority(1, 0) == PRIO(3, 0));
        set_priority(3, 65532, PRIO(2, 4));
        expect_target(first, PRIO(2, 4));
        assert(get_priority(1, 0) == PRIO(2, 4));
        assert(get_priority(1, second.pid) == foreign_before);
        errno = 0;
        assert(syscall(SYS_ioprio_set, 3, 65532, PRIO(1, 3)) == -1 && errno == EPERM);
        expect_target(first, PRIO(2, 4));
        _exit(0);
    }
    wait_child(actor);
    for (int which = 2; which <= 3; ++which) {
        errno = 0;
        assert(syscall(SYS_ioprio_get, which, INT_MAX) == -1 && errno == ESRCH);
        errno = 0;
        assert(syscall(SYS_ioprio_set, which, INT_MAX, PRIO(2, 3)) == -1 && errno == ESRCH);
    }
    errno = 0;
    assert(syscall(SYS_ioprio_get, 4, 0) == -1 && errno == EINVAL);
    stop_target(second);
    stop_target(first);
}

int main(void)
{
    assert(geteuid() == 0);
    fallback_cases();
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        selector_cases();
        _exit(0);
    }
    wait_child(child);
    puts("IOPRIO_SELECTORS_PASS");
    return 0;
}
