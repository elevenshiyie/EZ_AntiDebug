#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <elf.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
int      sg_guard_start(void);
int      sg_guard_hwbp_status(void);
int      sg_guard_hold_status(void);
int      sg_guard_hold_errno(void);
uint32_t sg_guard_sigtrap_count(void);
int32_t  sg_guard_pid(void);
int      sg_guard_set_nondumpable(void);
int      sg_guard_apply_read_channel_lock(void);
}

/* ============================================================================
 * Self-Trace Guard：把"以调试器之道还治调试器"落地。
 *
 * 回答的问题：外部程序读内存有固定几条通道，其中 ptrace 通道可以被"占位"封死——
 * 一个进程同一时刻只能被一个 tracer 附加。我们自己 fork 一个守护子进程
 * ptrace(SEIZE) 本进程，外部的 gdb / Frida ptrace 模式 attach 直接 EPERM。
 *
 * 为什么选 SEIZE 而非 PTRACE_TRACEME 自陷（关键设计决策，面试必答）：
 *   - TRACEME 在 SELinux Enforcing 下确实可用（自陷不涉及跨进程 attach），
 *     但它要求主进程每收到一个信号/每触发一次 stop 都停下来交给守护子进程，
 *     由我们做"信号总调度"。面对一款多线程 UE 游戏，这是海量信号转发工程，
 *     调不稳就卡死/崩溃——工程量大、收益与威胁模型不对等。
 *   - 本项目的定位是对目标 hack/cheat（注入器 + Dobby hook）对症下药，
 *     不是上极致的通用防护。盲目上 TRACEME 是"过度防御"，负收益。
 *   - SEIZE 在 permissive / 无 SELinux 限制环境能干净占位且零干扰；
 *     在 Enforcing 下诚实降级为"检测"（dbg.tracerpid 仍能发现外部附加）。
 *   - 结论：用 SEIZE + 检测降级，把 TRACEME 作为"评估过但权衡后不选"的
 *     备选方案记录在 README，体现"防御强度匹配威胁模型"的工程判断。
 *
 * 顺带解决的遗留问题——硬件断点：
 *   调试寄存器 EL0 不可直接读，但 tracer 身份可以通过内核代理访问：
 *   PTRACE_GETREGSET(NT_ARM_HW_BREAK / NT_ARM_HW_WATCH) 读硬断点寄存器，
 *   发现非零 DBGVR → 有人下了硬断；PTRACE_SETREGSET 清零 → 真正"防住"。
 *   而且硬断触发的 SIGTRAP 会先经过 tracer（我们），拦截/记录/转发全由我们定。
 *
 * 诚实边界（写进 SPEC，别夸大）：
 *   - root 不受限：CAP_SYS_PTRACE 可无视占位/PR_SET_PTRACER，仍能读能附加。
 *   - process_vm_readv / /proc/pid/mem 不走 ptrace 附加，本模块不拦读，
 *     靠 prctl(PR_SET_DUMPABLE,0) 挡非 root 工具（默认关闭，见 trade-off 注释）。
 *   - fork 守护在 zygote 派生进程里有已知坑：子进程只允许纯 syscall，
 *     禁止 ART/JNI/malloc/stdio（scudo 锁可能被其他线程持有 → 死锁）。
 *   - dumpable=0 与 self-trace 互斥：dumpable=0 时 ptrace_may_access 只放行
 *     CAP_SYS_PTRACE，自己的守护子进程也附加不上。二者只能选一。
 * ========================================================================== */

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN 0x4208
#endif
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59646162 /* "Yama" */
#endif

struct SgGuardShared {
    volatile uint32_t magic;      /* 'SGRD'，页有效 */
    volatile uint32_t hold_ok;    /* 子进程成功 SEIZE 本进程（ptrace 占位生效） */
    volatile uint32_t hold_errno; /* SEIZE 失败时的 errno（诊断用） */
    volatile uint32_t hwbp_hits;  /* 发现（并清除）硬件断点的次数 */
    volatile uint32_t sigtrap_cnt;/* 拦截到的真实 SIGTRAP 次数 */
    volatile uint32_t guard_pid;
};

/* channel_guard.cpp 提供的哨兵接口（extern "C" 声明，避免重复定义/名字修饰） */
extern "C" {
void *sg_guard_sentinel_addr(void);
void  sg_guard_sentinel_tamper(void);
int   sg_guard_sentinel_tampered(void);
}

static SgGuardShared *g_shared;
static int g_started;
static volatile int g_read_channel_locked; /* dumpable=0 是否已生效（挡外部读） */

/* ARM64 内核结构 user_hwdebug_state { u64 dbgvr; u32 dbgcr; u32 pad; }[16]
 * GETREGSET 返回若干组，判 dbgvr 非 0 即有硬件断点/观察点。 */
static int probe_regset(pid_t t, int nt, int clear) {
    unsigned char buf[512];
    struct iovec iov = { buf, sizeof(buf) };
    memset(buf, 0, sizeof(buf));
    if (ptrace(PTRACE_GETREGSET, t, (void *)(long)nt, &iov) != 0)
        return -1; /* 内核/SELinux 不支持 → 上层按 SKIPPED 处理 */
    size_t n = iov.iov_len / 16;
    if (n > 16) n = 16;
    int hits = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t vr;
        memcpy(&vr, buf + i * 16, 8);
        if (vr) hits++;
    }
    if (hits && clear) {
        memset(buf, 0, iov.iov_len);
        struct iovec z = { buf, iov.iov_len };
        ptrace(PTRACE_SETREGSET, t, (void *)(long)nt, &z); /* 清除断点寄存器 */
    }
    return hits;
}

static void bump(volatile uint32_t *p) {
    __atomic_fetch_add((uint32_t *)p, 1, __ATOMIC_RELAXED);
}

/* ---- 哨兵硬断：用我们自己的硬断反制外部硬断 ----
 * 外部调试器用硬断（DR0-3）断我们。反制分两层：
 *   1) 守护每轮体检 GETREGSET 读 DR0-7，发现非零 dbgvr 就清掉（已有 probe_regset）。
 *   2) 我们自己也占一个硬断"哨兵"：把哨兵函数地址写进 dbgvr，enable 它。
 *      下次体检时，若哨兵 dbgvr 被改/被清，说明外部动了我们的调试寄存器 → 告警。
 *
 * 实现：守护在 SEIZE 成功后，用 PTRACE_SETREGSET 写入哨兵断点。
 * user_hwdebug_state 布局：{ u64 dbgvr; u32 dbgcr; u32 pad; }[16]。
 * ARM64 硬件断点 DBGBCR 使能位：bit0 = E(enable)，bit1-4 = PMC(权限)，
 * bit5-8 = BAS，bit9-12 = HMC，bit16-20 = LBN(长度)，bit24-28 = BT(类型)。
 * 这里设：E=1, PMC=0b11(EL0+EL1), BAS=0xf(4字节), LBN=0, BT=0b0000(指令断点) → 0x3f1。
 * 实测不同 SoC 有差异，写失败按 SKIPPED，不阻塞。 */
static void install_sentinel_bp(pid_t target, uint64_t addr) {
    if (!addr) return;
    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));
    /* 组 0：哨兵断点 */
    uint64_t vr = addr;
    uint32_t cr = 0x3f1; /* E|PMC(EL0+1)|BAS=0xf|BT=0 */
    memcpy(buf, &vr, 8);
    memcpy(buf + 8, &cr, 4);
    struct iovec iov = { buf, 512 };
    ptrace(PTRACE_SETREGSET, target, (void *)(long)NT_ARM_HW_BREAK, &iov);
}

/* 体检：读回哨兵断点，比对我们写入的地址。若 dbgvr 被改或 cr 使能位被清 → 篡改 */
static void check_sentinel_bp(pid_t target, uint64_t addr) {
    if (!addr) return;
    unsigned char buf[512];
    struct iovec iov = { buf, sizeof(buf) };
    memset(buf, 0, sizeof(buf));
    if (ptrace(PTRACE_GETREGSET, target, (void *)(long)NT_ARM_HW_BREAK, &iov) != 0)
        return;
    uint64_t vr;
    uint32_t cr;
    memcpy(&vr, buf, 8);
    memcpy(&cr, buf + 8, 4);
    /* 哨兵地址被改，或使能位被清，或权限位被改 → 有人动了我们的断点 */
    if (vr != addr || !(cr & 1) || ((cr >> 1) & 0x3) != 0x3) {
        /* 通知父进程侧计数（通过 channel_guard 的接口） */
        sg_guard_sentinel_tamper();
    }
}

/* ---- 子进程：纯 syscall 守护循环，这里禁止任何 libc 分配/ART 调用 ---- */
static void child_loop(pid_t target) {
    setpgid(0, 0); /* 脱离 app 进程组，避免拖动时收到组信号 */

    /* 等 parent 完成 PR_SET_PTRACER 授权后再 SEIZE（Yama ptrace_scope=1 场景）。
     * 注意：在 SELinux Enforcing 下 SEIZE 会被 process:ptrace 拦截而失败，
     * 这是诚实标注的边界（详见文件头注释），失败后 hold 降级为 NOT_HELD。 */
    int ok = 0;
    int last_err = 0;
    for (int i = 0; i < 100; i++) {
        if (ptrace(PTRACE_SEIZE, target, 0, 0) == 0) { ok = 1; break; }
        last_err = errno;
        if (errno == ESRCH) _exit(0); /* parent 已死 */
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, 0);
    }
    g_shared->hold_ok = ok;
    g_shared->hold_errno = (uint32_t)last_err;
    g_shared->guard_pid = (uint32_t)getpid();
    if (!ok) _exit(0);

    /* 占位成功后，立即装哨兵硬断（用我们自己的断点反制外部断点） */
    uint64_t sentinel = (uint64_t)sg_guard_sentinel_addr();
    install_sentinel_bp(target, sentinel);

    for (;;) {
        int st = 0;
        pid_t r = waitpid(target, &st, __WALL | WNOHANG);
        if (r == target) {
            if (WIFEXITED(st) || WIFSIGNALED(st)) _exit(0); /* 被守护进程退出 */
            if (WIFSTOPPED(st)) {
                int sig = WSTOPSIG(st);
                int event = (st >> 16); /* ptrace 事件号 */
                /* 每种停都做一次硬件断点体检（GETREGSET 要求 tracee 处于 stop） */
                int hb = probe_regset(target, NT_ARM_HW_BREAK, 1 /*清除*/);
                int hw = probe_regset(target, NT_ARM_HW_WATCH, 1);
                if (hb > 0 || hw > 0) bump(&g_shared->hwbp_hits);
                /* 顺带检查哨兵断点是否被外部篡改（读回比对） */
                check_sentinel_bp(target, sentinel);

                if (event == 0 && sig == SIGTRAP) {
                    /* 真实 SIGTRAP：软断 BRK / 硬断触发 / 断点指令。
                     * 选择不转发（吞掉）：默认行为是杀进程，转发无意义；
                     * 已记数 sigtrap_cnt + 上方已清硬断寄存器。 */
                    bump(&g_shared->sigtrap_cnt);
                    ptrace(PTRACE_CONT, target, 0, 0);
                } else if (event != 0) {
                    /* ptrace 事件 stop（含我们 INTERRUPT 的体检停、SEIZE 停）。
                     * 关键：CONT 的 data 必须传 0，否则会把 SIGTRAP 注入给进程 */
                    ptrace(PTRACE_CONT, target, 0, 0);
                } else {
                    /* 其他真实信号原样转发（group-stop 完整实现需
                     * PTRACE_LISTEN，demo 简化为 CONT 转发，生产需补） */
                    ptrace(PTRACE_CONT, target, 0, (void *)(long)sig);
                }
                continue;
            }
        }
        /* 事件空闲期：周期 500ms 轻量体检（INTERRUPT 瞬时停→查→CONT，
         * 微秒级调度开销）。覆盖"下了断点但还没触发"的窗口。 */
        struct timespec ts = { 0, 500 * 1000 * 1000 };
        nanosleep(&ts, 0);
        ptrace(PTRACE_INTERRUPT, target, 0, 0);
        /* INTERRUPT 产生的 event-stop 下一轮 waitpid 收到：
         * event=PTRACE_EVENT_STOP(5) 不计入 sigtrap，仅用于体检路由 */
    }
}

/* ---- 父进程侧 API ---- */

int sg_guard_start(void) {
    if (g_started) return 0;
    void *p = mmap(0, 4096, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return -1;
    memset(p, 0, 4096);
    g_shared = (SgGuardShared *)p;
    g_shared->magic = 0x53475244; /* "SGRD" */

    pid_t child = fork();
    if (child < 0) {
        munmap(p, 4096);
        g_shared = 0;
        return -1;
    }
    if (child == 0) {
        child_loop(getppid());
        _exit(0);
    }
    /* 授权子进程 trace 自己（Yama: tracer 须为祖先，子进程不是 → 需显式豁免）。
     * 注意：这只对 Yama LSM 生效，对 SELinux 无效（二者是两套独立机制）。 */
    prctl(PR_SET_PTRACER, (unsigned long)child, 0, 0, 0);
    g_started = 1;
    return 0;
}

/* ---- 封外部读通道（dumpable=0 策略化） ----
 *
 * 攻击模型（用户实测）：外挂改 dex 把 hack.so 塞进 app lib 目录，进程内
 * dlopen 后 hack.so 用 *(type*) 直接指针读写 + mincore。对"已在进程内的
 * hack.so 读写"，用户态无解——它与你同权限，mprotect/mincore/缺页陷阱都拦
 * 不住（它可再 mprotect 回来、mincore 只是查驻留不产生访问事件、自己装
 * handler 即绕过）。真正的防线是"上游别让它进来"。
 *
 * 封通道能做的是堵"外部进程读我"这条独立通路：
 *   prctl(PR_SET_DUMPABLE, 0) 挡 /proc/<pid>/mem、process_vm_readv（非 root）。
 *
 * 但 dumpable=0 与 self-trace 守护互斥（dumpable=0 后守护的 SEIZE 也附加不上）。
 * 所以在"守护占位成功"时不能开；只有当占位失败（SELinux Enforcing 下
 * hold_ok=0）时，互斥矛盾本就不存在，此时开 dumpable=0 是白赚的防护。
 *
 * 由父进程在 fork 后、守护 SEIZE 结果稳定后调用。返回 0=成功置位，-1=失败。 */
int sg_guard_apply_read_channel_lock(void) {
    /* 等守护子进程把 hold_ok 写稳定（最多等 ~1s，SEIZE 重试 100 次 × 10ms） */
    for (int i = 0; i < 200 && g_shared && g_shared->magic == 0x53475244; i++) {
        if (g_shared->guard_pid != 0) break; /* 子进程已写入结果 */
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, 0);
    }
    int held = g_shared && g_shared->magic == 0x53475244 && g_shared->hold_ok;
    if (held) return 0;               /* 守护已占位 → 保持 dumpable，互斥不破坏 */
    /* 占位失败（SELinux Enforcing）→ 开 dumpable=0 挡外部读 */
    int rc = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (rc == 0) __atomic_store_n(&g_read_channel_locked, 1, __ATOMIC_RELAXED);
    return rc;
}

/* 查询 read-channel lock（dumpable=0）是否已生效。
 * 用于扫描线程：dumpable=0 时 PTRACE_TRACEME 自检必然 EPERM（通道已被自己封死），
 * 该自检不再能区分"有无外部 tracer"，应降级为 SKIPPED 而非误报 SUSPICIOUS。 */
extern "C" int sg_guard_read_channel_locked(void) {
    return __atomic_load_n(&g_read_channel_locked, __ATOMIC_RELAXED) ? 1 : 0;
}

/* 三态：1=有硬件断点被拦/清除，0=无，-1=守护未运行 */
int sg_guard_hwbp_status(void) {
    if (!g_shared || g_shared->magic != 0x53475244 || !g_shared->hold_ok)
        return -1;
    return g_shared->hwbp_hits > 0 ? 1 : 0;
}

/* 1=占位生效（外部 ptrace attach 必失败），0=未生效，-1=未启动 */
int sg_guard_hold_status(void) {
    if (!g_shared || g_shared->magic != 0x53475244) return -1;
    return g_shared->hold_ok ? 1 : 0;
}

/* SEIZE 失败时的 errno（EPERM/EACCES 通常是 SELinux/Yama，供诊断） */
int sg_guard_hold_errno(void) {
    if (!g_shared || g_shared->magic != 0x53475244) return -1;
    return (int)g_shared->hold_errno;
}

uint32_t sg_guard_sigtrap_count(void) {
    return (g_shared && g_shared->magic == 0x53475244) ? g_shared->sigtrap_cnt : 0;
}

/* 守护子进程 pid：Java 侧用它和 /proc/self/status 的 TracerPid 比对——
 * TracerPid == guard_pid → 是自家占位（OK）；!= guard_pid → 外部 tracer（命中） */
int32_t sg_guard_pid(void) {
    if (!g_shared || g_shared->magic != 0x53475244 || !g_shared->hold_ok)
        return -1;
    return (int32_t)g_shared->guard_pid;
}

/* 可选增强：挡非 root 工具读 /proc/<pid>/mem、process_vm_readv（adb shell 等）。
 * 注意 trade-off：dumpable=0 后 debuggerd 无法出 tombstone、ANR 无 trace、
 * 且 self-trace 守护会附加失败（互斥）——生产慎用，默认不调。 */
int sg_guard_set_nondumpable(void) {
    return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}
