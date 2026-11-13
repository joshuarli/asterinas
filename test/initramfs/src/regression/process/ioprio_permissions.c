// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PRIO(class, data) (((class) << 13) | (data))

static long get_priority(pid_t tid)
{
    long priority = syscall(SYS_ioprio_get, 1, tid);
    assert(priority >= 0);
    return priority;
}

static void set_priority(pid_t tid, unsigned int priority)
{
    assert(syscall(SYS_ioprio_set, 1, tid, priority) == 0);
    assert(get_priority(tid) == (priority & 0xffff));
}

static void reject_priority(pid_t tid, unsigned int priority, int error)
{
    long before = get_priority(tid);
    errno = 0;
    assert(syscall(SYS_ioprio_set, 1, tid, priority) == -1);
    assert(errno == error);
    assert(get_priority(tid) == before);
}

static void wait_child(pid_t child)
{
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void effective_capabilities(uint32_t effective)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {0};
    assert(syscall(SYS_capget, &header, data) == 0);
    assert((data[0].permitted & effective) == effective);
    data[0].effective = effective;
    data[1].effective = 0;
    assert(syscall(SYS_capset, &header, data) == 0);
    assert(syscall(SYS_capget, &header, data) == 0);
    assert(data[0].effective == effective && data[1].effective == 0);
}

static void roundtrips(void)
{
    const unsigned int priorities[] = {
        PRIO(2, 3), PRIO(3, 0), PRIO(0, 0), PRIO(2, 0x1ffb),
        PRIO(0, 8), PRIO(3, 7), 0x12340000 | PRIO(2, 5),
        0xffff0000 | PRIO(2, 4),
    };
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        effective_capabilities(1u << CAP_SETUID);
        for (unsigned int i = 0; i < sizeof(priorities) / sizeof(priorities[0]); ++i) {
            set_priority(0, priorities[i]);
            assert(get_priority((pid_t)syscall(SYS_gettid)) == (priorities[i] & 0xffff));
        }
        reject_priority(0, PRIO(0, 1), EINVAL);
        for (unsigned int class = 4; class < 8; ++class)
            reject_priority(0, PRIO(class, 0), EINVAL);
        reject_priority(0, PRIO(1, 4), EPERM);
        errno = 0;
        assert(syscall(SYS_ioprio_set, 1, INT_MAX, PRIO(0, 1)) == -1 && errno == EINVAL);
        errno = 0;
        assert(syscall(SYS_ioprio_set, 1, INT_MAX, PRIO(1, 4)) == -1 && errno == EPERM);
        errno = 0;
        assert(syscall(SYS_ioprio_set, 1, INT_MAX, PRIO(2, 3)) == -1 && errno == ESRCH);
        assert(setresuid(65534, 65534, 65534) == 0);
        set_priority(0, PRIO(2, 3));
        set_priority(0, PRIO(3, 0));
        set_priority(0, PRIO(0, 0));
        reject_priority(0, PRIO(1, 4), EPERM);
        _exit(0);
    }
    wait_child(child);
}

struct target {
    pid_t pid;
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
        set_priority(0, PRIO(2, 6));
        assert(write(ready[1], "r", 1) == 1);
        close(ready[1]);
        char byte;
        assert(read(release[0], &byte, 1) == 0);
        close(release[0]);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    char byte;
    assert(read(ready[0], &byte, 1) == 1 && byte == 'r');
    close(ready[0]);
    return (struct target){child, release[1]};
}

static void credential_case(uid_t real, uid_t effective, pid_t target, int error)
{
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setresuid(real, effective, real) == 0);
        effective_capabilities(0);
        if (error)
            reject_priority(target, PRIO(2, 2), error);
        else
            set_priority(target, PRIO(2, 2));
        _exit(0);
    }
    wait_child(child);
}

static void capability_case(uint32_t capability, pid_t target, int error)
{
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        effective_capabilities(capability);
        if (error)
            reject_priority(target, PRIO(2, 1), error);
        else
            set_priority(target, PRIO(2, 1));
        if (capability)
            set_priority(0, PRIO(1, 4));
        else
            reject_priority(0, PRIO(1, 4), EPERM);
        _exit(0);
    }
    wait_child(child);
}

int main(void)
{
    assert(geteuid() == 0);
    roundtrips();
    struct target foreign = start_target(65533, 65534);
    struct target same = start_target(65534, 65533);
    credential_case(65534, 65534, foreign.pid, EPERM);
    credential_case(65534, 65534, same.pid, 0);
    credential_case(65534, 65532, same.pid, 0);
    credential_case(65532, 65534, same.pid, 0);
    capability_case(0, foreign.pid, EPERM);
    capability_case(1u << CAP_SYS_ADMIN, foreign.pid, EPERM);
    capability_case(1u << CAP_SYS_NICE, foreign.pid, 0);
    close(same.release);
    wait_child(same.pid);
    close(foreign.release);
    wait_child(foreign.pid);
    puts("IOPRIO_PERMISSIONS_PASS");
    return 0;
}
