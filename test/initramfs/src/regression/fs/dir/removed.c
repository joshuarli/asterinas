// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    const char *root = getenv("TMPDIR");
    if (!root || !*root) root = "/tmp";
    char path[512];
    if (snprintf(path, sizeof(path), "%s/removed-dir-XXXXXX", root) >= (int)sizeof(path)) return 1;
    if (!mkdtemp(path)) { perror("create directory"); return 1; }
    int saved = open(".", O_RDONLY | O_DIRECTORY);
    int original = open(path, O_RDONLY | O_DIRECTORY);
    if (saved < 0 || original < 0 || fchdir(original) || rmdir(path)) {
        perror("remove current directory"); return 1;
    }
    int failed = 0;
    struct stat st;
    if (fstat(original, &st) || st.st_nlink != 0) {
        perror("stat removed directory"); failed = 1;
    }
    if (fstatat(AT_FDCWD, ".", &st, 0)) {
        perror("stat current directory after removal"); failed = 1;
    }
    char data[4096];
    errno = 0;
    long result = syscall(SYS_getcwd, data, sizeof(data));
    if (result != -1 || errno != ENOENT) {
        fprintf(stderr, "getcwd removed: result=%ld errno=%d\n", result, errno);
        failed = 1;
    }
    errno = 0;
    result = syscall(SYS_getdents64, original, data, sizeof(data));
    if (result != -1 || errno != ENOENT) {
        fprintf(stderr, "getdents removed: result=%ld errno=%d\n", result, errno);
        failed = 1;
    }
    DIR *directory = opendir(".");
    if (!directory) { perror("open removed directory"); failed = 1; }
    else {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry || errno) {
            fprintf(stderr, "readdir removed: entry=%s errno=%d\n", entry ? entry->d_name : "none", errno);
            failed = 1;
        }
        if (closedir(directory)) failed = 1;
    }
    if (fchdir(saved) || close(saved) || close(original)) return 1;
    if (!failed) puts("removed directories: cwd fails, directory handles stay valid, libc iteration is empty");
    return failed;
}
