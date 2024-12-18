#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>

int main(){

    dup2(1, 2);

    char cmd[0x1000] = {0};

    // while(1){
    //     memset(cmd, 0, sizeof 0x1000);
    //     read(0, cmd, sizeof cmd - 1);
    //     if(strstr(cmd, "exit")){
    //         return 0;
    //     }
    //     system(cmd);
    // }

    setns(open("/proc/108/ns/mnt", 0), 0);
    setns(open("/proc/108/ns/pid", 0), 0);
    setns(open("/proc/108/ns/net", 0), 0);

    int fd = open("/proc/108/fd/0", O_RDWR);
    if(fd < 0){
        perror("open");
    }

    system("id ; mount -t tmpfs none /tmp ; mkdir -p /tmp/x;ls -al /proc/108/");

    sleep(10000);
}