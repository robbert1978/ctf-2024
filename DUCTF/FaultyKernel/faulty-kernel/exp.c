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

#include <linux/btrfs.h>
#include <linux/userfaultfd.h>
#include <linux/sysctl.h>
#include <linux/capability.h>
#include <linux/types.h>

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

u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;

u8 WAIT()
{
    write(STDERR_FILENO, "[WAITING...]\n", 13);
    u8 c;
    read(STDIN_FILENO, &c, 1);
    return c;
}

static inline void panic(const char* msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void getShell()
{
    if (getuid())
    {
        panic("NO ROOT");
    }
    logOK("Rooted!");
    char* argv[] = { "/bin/sh", NULL };
    char** envp = &argv[1];
    execve(argv[0], argv, envp);
}

void save_state()
{
    __asm__(
        "mov [rip + user_cs], cs\n"
        "mov [rip + user_ss], ss\n"
        "mov [rip + user_sp], rsp\n"
        "mov [rip + user_ip], %0\n"
        "pushf\n"
        "pop qword ptr [rip + user_rflags]\n" ::"r"(getShell));
    logInfo("Saved user state");
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

#define devname "/dev/challenge"

int main(int argc, char** argv, char** envp)
{
    int fd1 = open(devname, O_RDWR);
    if (fd1 == -1) {
        panic("open devfile");
    }

    int fd2 = open(devname, O_RDWR);
    if (fd2 == -1) {
        panic("open devfile");
    }

    char* m1 = mmap((void*)0x1337000ULL, 0x1000, PROT_READ, MAP_FILE | MAP_PRIVATE, fd1, 0);
    if (m1 == MAP_FAILED) {
        perror("mmap(0x1337000ULL)");
        return 1;
    }

    logInfo("m1 = %p", m1);



    char* m2 = mmap((void*)0x6969000ULL, 0x1000, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd1, 0);
    if (m2 == MAP_FAILED) {
        perror("mmap(0x6969000ULL)");
        return 1;
    }

    logInfo("m2 = %p", m2);

    // char* m3 = mmap((void*)0x4242000ULL, 0x1000, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd1, 0);
    // if (m3 == MAP_FAILED) {
    //     perror("mmap(0x4242000ULL)");
    //     return 1;
    // }
    // logInfo("m3 = %p", m3);


    // char c1 = m1[0];
    // munmap(m1, 0x1000);

    // m3[0] = 'B';
    // m2[0] = 'X';


    // munmap(m3, 0x1000);
    // WAIT();
    // munmap(m2, 0x1000);
    int pid = fork();
    if (pid == 0) {
        m2[0] = 'A';
        return 0;
    }
    wait(NULL);

    m2[0] = m1[0];

    WAIT();

}