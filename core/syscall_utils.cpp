#include "syscall_utils.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

#if defined(__aarch64__)
#ifndef __NR_lseek
#define __NR_lseek 62
#endif
static inline long raw_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ __volatile__("svc 0"
        : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    return x0;
}
#define SG_NR_open    __NR_openat
#define SG_NR_read    __NR_read
#define SG_NR_close   __NR_close
#define SG_NR_access  __NR_faccessat
#define SG_NR_getpid  __NR_getpid
#define SG_NR_gettid  __NR_gettid
#define SG_NR_tgkill  __NR_tgkill
#define SG_NR_lseek   __NR_lseek
#else
#error "SentinelGuard demo 仅支持 arm64-v8a"
#endif

extern "C" {

ssize_t sg_read(int fd, void *buf, size_t n) {
    return raw_syscall(SG_NR_read, fd, (long)buf, n, 0, 0, 0);
}
int sg_open(const char *path, int flags, unsigned int mode) {
    /* Android 无独立 open 号，统一用 openat(AT_FDCWD=-100) */
    return (int)raw_syscall(SG_NR_open, -100, (long)path, flags, mode, 0, 0);
}
int sg_close(int fd) { return (int)raw_syscall(SG_NR_close, fd, 0, 0, 0, 0, 0); }
int sg_access(const char *path, int mode) {
    return (int)raw_syscall(SG_NR_access, -100, (long)path, mode, 0, 0, 0);
}
pid_t sg_getpid(void) { return (pid_t)raw_syscall(SG_NR_getpid, 0, 0, 0, 0, 0, 0); }
int sg_gettid(void) { return (int)raw_syscall(SG_NR_gettid, 0, 0, 0, 0, 0, 0); }
int sg_tgkill(pid_t pid, int tid, int sig) {
    return (int)raw_syscall(SG_NR_tgkill, pid, tid, sig, 0, 0, 0);
}
ssize_t sg_lseek(int fd, off_t off, int whence) {
    return raw_syscall(SG_NR_lseek, fd, (long)off, whence, 0, 0, 0);
}

int sg_open_fallback(const char *path, int flags, unsigned int mode, int *used) {
    int fd = sg_open(path, flags, mode);
    if (fd >= 0) { if (used) *used = 1; return fd; }
    if (used) *used = 0;
    return open(path, flags, mode);
}
ssize_t sg_read_fallback(int fd, void *buf, size_t n, int used) {
    return used ? sg_read(fd, buf, n) : read(fd, buf, n);
}

int sg_mem_readable(const void *addr, size_t len) {
    /* 关键技巧：write() 到管道，内核做 copy_from_user。
     * 源不可读时返回 EFAULT/短写，而不是让本进程 SIGSEGV。 */
    int p[2];
    if (pipe(p) != 0) return 0;
    ssize_t n = write(p[1], addr, len);
    close(p[0]); close(p[1]);
    return n == (ssize_t)len ? 1 : 0;
}

size_t sg_strlen(const char *s) {
    size_t n = 0; while (s[n]) n++; return n;
}
int sg_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (unsigned char)*a - (unsigned char)*b : 0;
}
char *sg_strncpy(char *dst, const char *src, size_t n) {
    size_t i = 0; for (; i + 1 < n && src[i]; i++) dst[i] = src[i];
    dst[i] = 0; return dst;
}
const char *sg_strstr(const char *h, const char *nd) {
    if (!*nd) return h;
    for (; *h; h++) {
        const char *a = h, *b = nd;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return h;
    }
    return 0;
}

} // extern "C"
