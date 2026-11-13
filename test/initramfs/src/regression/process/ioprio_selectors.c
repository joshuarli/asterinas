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

struct race_args {
    pid_t target;
    int nice;
    pthread_barrier_t *barrier;
};

static void rendezvous(pthread_barrier_t *barrier)
{
    int result = pthread_barrier_wait(barrier);
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *race_set_priority(void *argument)
{
    struct race_args *args = argument;
    for (int round = 0; round < 128; ++round) {
        rendezvous(args->barrier);
        for (int change = 0; change < 64; ++change)
            assert(setpriority(PRIO_PROCESS, args->target, args->nice) == 0);
        rendezvous(args->barrier);
    }
    return NULL;
}

static void priority_race(void)
{
    struct target target = start_target(0, 0);
    pthread_barrier_t barrier;
    assert(pthread_barrier_init(&barrier, NULL, 3) == 0);
    struct race_args args[2] = {{target.pid, 10, &barrier}, {target.pid, 19, &barrier}};
    pthread_t workers[2];
    for (int i = 0; i < 2; ++i)
        assert(pthread_create(&workers[i], NULL, race_set_priority, &args[i]) == 0);
    for (int round = 0; round < 128; ++round) {
        rendezvous(&barrier);
        rendezvous(&barrier);
        struct sched_attribute actual = {0};
        assert(syscall(SYS_sched_getattr, target.pid, &actual, sizeof(actual), 0) == 0);
        assert(getpriority(PRIO_PROCESS, target.pid) == actual.nice);
    }
    for (int i = 0; i < 2; ++i)
        assert(pthread_join(workers[i], NULL) == 0);
    assert(pthread_barrier_destroy(&barrier) == 0);
    stop_target(target);
}

static void priority_permissions(void)
{
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setresuid(65534, 65534, 65534) == 0);
        int owner = getppid();
        errno = 0;
        int before_nice = getpriority(PRIO_PROCESS, owner);
        assert(errno == 0);
        errno = 0;
        assert(setpriority(PRIO_PROCESS, owner, 19) == -1 && errno == EPERM);
        assert(getpriority(PRIO_PROCESS, owner) == before_nice);
        struct sched_attribute actual = {0};
        assert(syscall(SYS_sched_getattr, owner, &actual, sizeof(actual), 0) == 0);
        assert(actual.nice == before_nice);
        assert(setpriority(PRIO_PROCESS, 0, 10) == 0);
        errno = 0;
        assert(setpriority(PRIO_PROCESS, 0, 9) == -1 && errno == EACCES);
        assert(getpriority(PRIO_PROCESS, 0) == 10);
        _exit(0);
    }
    wait_child(child);
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
        assert(getpriority(PRIO_PROCESS, 0) == 10);
        assert(get_priority(2, 0) == PRIO(2, 6));
        assert(sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &parameter) == 0);
        assert(get_priority(2, 0) == PRIO(1, 6));
        check_reset_child(0);
        assert(setpriority(PRIO_PROCESS, 0, -5) == 0);
        assert(getpriority(PRIO_PROCESS, 0) == -5);
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
        assert(setpriority(PRIO_PROCESS, second.pid, 19) == 0);
        assert(getpriority(PRIO_PROCESS, second.pid) == 19);
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
    priority_permissions();
    priority_race();
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
