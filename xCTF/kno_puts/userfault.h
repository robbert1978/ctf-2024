#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef __USERFAULT_HEADER__
#define __USERFAULT_HEADER__

#define PAGE_SIZE 0x1000

struct userfault_arg
{
    uint32_t ufd;
    uint32_t numPages;
    uint64_t uf_page;
    uint32_t faultCount;
    void (*free_victim)(void);
};

extern char uf_buffer[PAGE_SIZE * 2];
extern struct userfault_arg userfaultArg;

int register_ufd(uint64_t page, uint numPages);
void set_page_wp(uintptr_t page, bool protected);
void *userfaultHandler(void *arg);
pthread_t createThreadUserFault(uint64_t page, uint numPages, void (*free_victim)(void));

#endif
