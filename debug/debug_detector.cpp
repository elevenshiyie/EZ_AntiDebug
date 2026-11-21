#include "../core/syscall_utils.h"
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <errno.h>

extern "C" {
int  sg_dbg_tracerpid_pid(void);
int  sg_dbg_ptrace_self(void);
int  sg_dbg_sigtrap_trap(void);
}

/* ============================================================================
 * 调试/断点域。边界要说清楚（面试叙事的关键）：
 *  - 软件断点(INT3/BRK) 会改 .text → 可被 CRC/inline 抓到；
 *  - TracerPid 查的其实是"有没有被 ptrace 附加"，不是"有没有断点"；
 *  - 硬件断点写的是调试寄存器(DBGBVR/DR0-7)，不改 text，
 *    untrusted_app 用户态既读不到也清不掉 → 本框架不承诺"拦硬断",
 *    只检测"我正被调试"这个上游事实。想真防硬断需要内核/eBPF，越界。
 * ========================================================================== */

/* 返回 TracerPid 的数值：-1=读不到(SKIPPED)，0=无 tracer，>0=tracer 的 pid
 * （Java 层与 guard pid 比对区分"自家守护占位"与"外部 tracer 附加"） */
int sg_dbg_tracerpid_pid(void) {
    int used = 0;
    int fd = sg_open_fallback("/proc/self/status", 0, 0, &used);
    if (fd < 0) return -1;
    char buf[4096]; size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = sg_read_fallback(fd, buf + n, sizeof(buf) - 1 - n, used);
        if (r <= 0) break;
        n += (size_t)r;
    }
    buf[n] = 0; sg_close(fd);
    const char *p = sg_strstr(buf, "TracerPid:");
    if (!p) return -1;
    p += sg_strlen("TracerPid:");
    while (*p == ' ' || *p == '\t') p++;
    int v = 0;
    while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
    return v;
}

/* PTRACE_TRACEME 自检：能成功 = 没被别人 trace；EPERM = 已有 tracer。
 * 注意这与 ART debugger 冲突，生产环境如需调试可配置关闭。 */
int sg_dbg_ptrace_self(void) {
    errno = 0;
    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (r == 0) return 0;
    if (errno == EPERM || errno == EBUSY) return 1;
    return -1;
}

/* SIGTRAP handler 完整性：在专用线程给自己发 SIGTRAP，
 * 若自有 handler 没被调用(被 Frida signal chaining 吞掉)→ 可疑。
 * 专用线程 + siglongjmp 避免跨线程 longjmp 崩溃。 */
static sigjmp_buf s_env;
static volatile int s_ran;
static void trap_handler(int s) { (void)s; s_ran = 1; siglongjmp(s_env, 1); }

static void *trap_thread(void *arg) {
    int *out = (int *)arg;
    struct sigaction sa, old;
    sa.sa_handler = trap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGTRAP, &sa, &old) != 0) { *out = -1; return 0; }
    s_ran = 0;
    if (sigsetjmp(s_env, 1) == 0) {
        sg_tgkill(sg_getpid(), sg_gettid(), SIGTRAP);
        sigaction(SIGTRAP, &old, 0);
        *out = 1;           // 没 longjmp 回来 → handler 没跑 → 可疑
        return 0;
    }
    sigaction(SIGTRAP, &old, 0);
    *out = s_ran ? 0 : 1;
    return 0;
}

int sg_dbg_sigtrap_trap(void) {
    int result = 0;
    pthread_t th;
    if (pthread_create(&th, 0, trap_thread, &result) != 0) return -1;
    pthread_join(th, 0);
    return result;
}
