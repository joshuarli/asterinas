// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#define OPTS                                                                \
    (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |    \
     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT)
#define ORIG_RAX_OFF 120L

static int out_fd_global = -1;
static char *self_exe;

static void hang(int sig)
{
    (void)sig;
    puts("WITNESS_TRACED_GROUP_EXIT_HANG");
    fflush(stdout);
    _exit(1);
}

static long peek(pid_t pid, long off)
{
    errno = 0;
    long v = ptrace(PTRACE_PEEKUSER, pid, (void *)off, 0);
    if (v == -1 && errno) {
        perror("peekuser");
        _exit(3);
    }
    return v;
}

static int run_tracer(pid_t tracee)
{
    int status;
    if (waitpid(tracee, &status, 0) != tracee || !WIFSTOPPED(status)) {
        puts("WITNESS_TRACED_GROUP_EXIT_FAIL no initial stop");
        return 1;
    }
    if (ptrace(PTRACE_SETOPTIONS, tracee, 0, (void *)(long)OPTS)) {
        perror("setoptions");
        return 1;
    }
    if (ptrace(PTRACE_SYSCALL, tracee, 0, 0)) {
        perror("syscall resume");
        return 1;
    }
    for (;;) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == tracee) {
                if (WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE)
                    return 0;
                printf("WITNESS_TRACED_GROUP_EXIT_FAIL tracee status=%x pid=%d\n", status, pid);
                return 1;
            }
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;
        int sig = WSTOPSIG(status);
        int deliver = 0;
        int req = PTRACE_SYSCALL;
        if (sig == (SIGTRAP | 0x80)) {
            long nr = peek(pid, ORIG_RAX_OFF);
            (void)nr;
        } else if (sig == SIGTRAP) {
            unsigned event = ((unsigned)status >> 16) & 0xff;
            if (event != PTRACE_EVENT_FORK && event != PTRACE_EVENT_VFORK &&
                event != PTRACE_EVENT_CLONE && event != PTRACE_EVENT_EXEC &&
                event != PTRACE_EVENT_VFORK_DONE && event != PTRACE_EVENT_EXIT) {
                printf("WITNESS_TRACED_GROUP_EXIT_FAIL unknown event %u\n", event);
                return 1;
            }
            unsigned long msg = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg)) {
                perror("geteventmsg");
                return 1;
            }
            if (event == PTRACE_EVENT_EXIT)
                req = PTRACE_CONT;
        } else {
            deliver = sig;
        }
        if (ptrace(req, pid, 0, (void *)(long)deliver)) {
            if (errno == ESRCH)
                continue;
            perror("cont");
            return 1;
        }
    }
}

static void *writer_thread(void *arg)
{
    (void)arg;
    int fd = out_fd_global;
    static char buf[8192];
    memset(buf, 'y', sizeof buf);
    for (size_t i = 1; i < sizeof buf; i += 2)
        buf[i] = '\n';
    for (;;) {
        ssize_t n = write(fd, buf, sizeof buf);
        if (n < 0)
            _exit(127);
    }
    return NULL;
}

static int writer_main(int out_fd)
{
    out_fd_global = out_fd;
    pthread_t th;
    if (pthread_create(&th, NULL, writer_thread, NULL))
        _exit(126);
    for (;;)
        pause();
    return 0;
}

static int run_case(void)
{
    int p[2];
    if (pipe(p)) {
        perror("pipe");
        return 2;
    }
    pid_t reader = fork();
    if (reader == 0) {
        close(p[1]);
        int seen = 0;
        char buf[512];
        while (seen < 2) {
            ssize_t n = read(p[0], buf, sizeof buf);
            if (n <= 0)
                _exit(0);
            for (ssize_t i = 0; i < n && seen < 2; i++)
                if (buf[i] == '\n')
                    seen++;
        }
        _exit(0);
    }
    if (reader < 0)
        return 2;
    pid_t tracer = fork();
    if (tracer == 0) {
        pid_t tracee = fork();
        if (tracee == 0) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0))
                _exit(10);
            raise(SIGSTOP);
            dup2(p[1], 99);
            close(p[0]);
            close(p[1]);
            char fdarg[16];
            snprintf(fdarg, sizeof fdarg, "%d", 99);
            char *args[] = { self_exe, "writer", fdarg, NULL };
            execv("/proc/self/exe", args);
            _exit(11);
        }
        close(p[0]);
        close(p[1]);
        int rc = run_tracer(tracee);
        _exit(rc ? 1 : 0);
    }
    if (tracer < 0)
        return 2;
    close(p[0]);
    close(p[1]);
    int status, rc = 0;
    pid_t w;
    int tracer_rc = -1, reader_rc = -1;
    while ((w = waitpid(-1, &status, 0)) > 0) {
        if (w == tracer)
            tracer_rc = (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
        if (w == reader)
            reader_rc = (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
    }
    if (tracer_rc != 0 || reader_rc != 0)
        rc = 1;
    return rc;
}

int main(int argc, char **argv)
{
    self_exe = argv[0];
    if (argc == 3 && !strcmp(argv[1], "writer")) {
        int fd = (int)strtol(argv[2], NULL, 10);
        return writer_main(fd);
    }
    signal(SIGALRM, hang);
    alarm(45);
    int rc = run_case();
    if (rc) {
        puts("WITNESS_TRACED_GROUP_EXIT_FAIL first run");
        return 1;
    }
    if (geteuid() == 0) {
        pid_t child = fork();
        if (child < 0)
            return 2;
        if (child == 0) {
            alarm(45);
            if (setgid(1000) || setuid(1000))
                _exit(2);
            if (prctl(PR_SET_DUMPABLE, 1))
                _exit(2);
            int r = run_case();
            _exit(r ? 1 : 0);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
            puts("WITNESS_TRACED_GROUP_EXIT_FAIL unprivileged run");
            return 1;
        }
    }
    puts("WITNESS_TRACED_GROUP_EXIT_PASS");
    return 0;
}
