#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>          /* Definition of O_* and S_* constants */
#include <linux/openat2.h>  /* Definition of RESOLVE_* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <unistd.h>

int main() {

    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = 0;
    how.resolve = 0;

    int fd = syscall(SYS_openat2, AT_FDCWD, "flag", &how, sizeof(how));

    char buf[100];

    read(fd, buf, 100);
    puts(buf);

    return 0;
}
