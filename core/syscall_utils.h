#ifndef SENTINEL_SYSCALL_UTILS_H
#define SENTINEL_SYSCALL_UTILS_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 直接 svc 的系统调用封装：绕开被 Frida/PLT hook 的 libc 导出符号。
 * 这是 anti-hook 的基石——检测逻辑自己不能被检测对象的手段掐断。*/
ssize_t sg_read(int fd, void *buf, size_t count);
int    sg_open(const char *path, int flags, unsigned int mode);
int    sg_close(int fd);
int    sg_access(const char *path, int mode);
pid_t  sg_getpid(void);
int    sg_gettid(void);
int    sg_tgkill(pid_t pid, int tid, int sig);
ssize_t sg_lseek(int fd, off_t off, int whence);

/* syscall 优先，失败回退 libc，兼容受限机型。out_used_syscall=1 表示走的 svc。 */
int    sg_open_fallback(const char *path, int flags, unsigned int mode, int *out_used_syscall);
ssize_t sg_read_fallback(int fd, void *buf, size_t n, int used_syscall);

/* XOM(Execute-Only Memory) 守卫：用 write 到管道探测目标地址可读性，
 * 不可读时返回 0，绝不直接解引用——否则在只执行段上读字节会 SIGSEGV。*/
int    sg_mem_readable(const void *addr, size_t len);

/* 自实现字符串函数，避免 strstr/strcmp 本身被 hook。 */
size_t sg_strlen(const char *s);
int    sg_strncmp(const char *a, const char *b, size_t n);
char  *sg_strncpy(char *dst, const char *src, size_t n);
const char *sg_strstr(const char *hay, const char *needle);

#ifdef __cplusplus
}
#endif
#endif
