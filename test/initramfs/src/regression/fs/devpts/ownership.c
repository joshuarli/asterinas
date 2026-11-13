// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int child(const char *dir, gid_t gid, mode_t mode)
{
    char path[512];
    struct stat st = {0};
    int number, unlock = 0;
    if (setgroups(0, NULL) || setgid(1000) || setuid(1000)) {
        perror("drop credentials");
        return 1;
    }
    if (snprintf(path, sizeof(path), "%s/ptmx", dir) >= (int)sizeof(path)) return 1;
    if (stat(path, &st) || (st.st_mode & 07777) != 0666) {
        perror("ptmx mode");
        return 1;
    }
    int master = open(path, O_RDWR | O_NOCTTY);
    if (master < 0 || ioctl(master, TIOCGPTN, &number) || ioctl(master, TIOCSPTLCK, &unlock)) {
        perror("open master");
        return 1;
    }
    if (snprintf(path, sizeof(path), "%s/%d", dir, number) >= (int)sizeof(path)) return 1;
    if (stat(path, &st) || st.st_uid != 1000 || st.st_gid != gid || (st.st_mode & 07777) != mode) {
        fprintf(stderr, "slave metadata: uid=%u gid=%u mode=%o\n", st.st_uid, st.st_gid, st.st_mode & 07777);
        close(master);
        return 1;
    }
    int slave = open(path, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        perror("open slave");
        close(master);
        return 1;
    }
    close(slave);
    close(master);
    return 0;
}

static int run(const char *dir, const char *options, gid_t gid, mode_t mode, mode_t ptmx_mode)
{
    if (mount("devpts", dir, "devpts", 0, options)) {
        perror("mount devpts");
        return 1;
    }
    char path[512];
    struct stat st;
    int valid = snprintf(path, sizeof(path), "%s/ptmx", dir) < (int)sizeof(path) &&
        !stat(path, &st) && (st.st_mode & 07777) == ptmx_mode;
    if (valid && ptmx_mode != 0666) valid = chmod(path, 0666) == 0;
    if (!valid) {
        fprintf(stderr, "incorrect ptmx mode or chmod failed\n");
        umount(dir);
        return 1;
    }
    pid_t pid = fork();
    int status = 0, result = 1;
    if (pid == 0) _exit(child(dir, gid, mode));
    if (pid < 0) perror("fork");
    else if (waitpid(pid, &status, 0) < 0) perror("waitpid");
    else result = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    if (umount(dir)) {
        perror("umount devpts");
        result = 1;
    }
    return result;
}

static int reject(const char *dir, const char *options)
{
    if (mount("devpts", dir, "devpts", 0, options) == 0) {
        fprintf(stderr, "invalid options accepted: %s\n", options);
        if (umount(dir)) perror("umount devpts");
        return 1;
    }
    if (errno != EINVAL) {
        perror("invalid options");
        return 1;
    }
    return 0;
}

int main(void)
{
    const char *tmpdir = getenv("TMPDIR");
    char dir[512];
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
    if (snprintf(dir, sizeof(dir), "%s/devpts-XXXXXX", tmpdir) >= (int)sizeof(dir)) return 1;
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 1;
    }
    int result = 1;
    if (chmod(dir, 0755)) perror("chmod mountpoint");
    else if (run(dir, NULL, 1000, 0600, 0000)) {}
    else if (run(dir, "newinstance,mode=0620,gid=5,ptmxmode=0666", 5, 0620, 0666)) {}
    else if (run(dir, "newinstance,mode=0640,ptmxmode=0622", 1000, 0640, 0622)) {}
    else if (run(dir, "newinstance,mode=7620,gid=0x5,ptmxmode=7666", 5, 07620, 07666)) {}
    else if (run(dir, "newinstance,mode=0620,gid=05\n,ptmxmode=0666", 5, 0620, 0666)) {}
    else if (reject(dir, "mode=xyz") || reject(dir, "ptmxmode=8") ||
             reject(dir, "gid=0xg") || reject(dir, "gid=4294967295")) {}
    else result = 0;
    if (rmdir(dir)) {
        perror("rmdir mountpoint");
        result = 1;
    }
    return result;
}
