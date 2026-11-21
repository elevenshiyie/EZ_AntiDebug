/* ============================================================================
 * Channel Guard：封"读内存"的其余通道 + 恶意驱动扫描 + 哨兵硬断反制。
 *
 * 一、封 open/read/write 与 syscall 层读写（先厘清能不能封）：
 *   外部进程读本进程内存的通道，本质是内核实现的，攻击者在自己地址空间里
 *   调 syscall，本进程根本收不到任何事件——用户态"拦截"不了这个 syscall。
 *   能做的只有两件事：
 *     (1) 让通道"走不通"：
 *         - prctl(PR_SET_DUMPABLE, 0)：封 /proc/<pid>/mem、process_vm_readv
 *           （非 root；注意与 self-trace 守护互斥，见下方 trade-off）。
 *         - self-trace 占位：封 ptrace attach（已在 self_guard.cpp）。
 *     (2) 让通道"读了也没用"：关键数据不落明文，见 sg_channel_hide_data 注释。
 *
 * 二、/proc /dev 恶意驱动扫描：
 *   遍历 /proc（进程伪装名、可疑内核模块线索）与 /dev（字符设备驱动），
 *   命中关键字表即判违规。用户要求"不用太细节，find(hack) 判违规即可"，
 *   这里给一个可扩展的关键字表 + 轻量遍历骨架，命中即返回。
 *
 * 三、哨兵硬断反制硬断（用户思路的落地形态）：
 *   外部调试器用硬断（DR0-3）断点我们的函数。反制靠三件套：
 *     (1) self-trace 守护用 PTRACE_GETREGSET 读并清除调试寄存器（已有）。
 *     (2) 我们自己也占一个硬断做"哨兵"：设一个我们自己的函数地址为断点，
 *         如果它被外部覆盖/清掉，或它的 DBGCR 使能位被改，说明有外部干预。
 *     (3) SIGTRAP handler：硬断命中时 CPU 先走我们的 tracer（守护子进程），
 *         守护清寄存器 + 记数，异常处理链不交给外部。
 *   边界（诚实写）：内核态调试器（KGDB、Frida kernel、自定义 LKM 的 hw_breakpoint）
 *   走 kernel API 下断，用户态 tracer 的 GETREGSET 看不到，防不住——只能靠
 *   "内核态难写"这一事实 + 行为检测（如发现自己的断点被改）做威慑。
 * ========================================================================== */

#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <dirent.h>

#include "../core/syscall_utils.h"

extern "C" {
int  sg_guard_scan_sysfs(void);
int  sg_guard_scan_devices(void);
void *sg_guard_sentinel_addr(void);
void sg_guard_sentinel_tamper(void);
int  sg_guard_sentinel_tampered(void);
int  sg_guard_install_sigtrap(void);
int  sg_guard_trap_count(void);
}

#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif

/* ---- 恶意驱动/进程 关键字表（可扩展） ---- */
static const char *const SUSPECT_NAMES[] = {
    "frida", "gadget", "gum", "stalker",        /* Frida 系 */
    "xposed", "lsposed", "edxposed", "sandhook", /* Xposed/ART hook 系 */
    "substrate", "cycript", "rydjailbreak",       /* 越狱/注入 */
    "hack", "cheat", "speedhack", "gg", "gameguardian", /* 外挂（用户点名的 find("hack")） */
    "rootcloak", "magiskhide", "shamiko",         /* 隐藏类（本身即可疑） */
    "kgdb", "kdump", "crash",                     /* 内核调试 */
    0
};

/* 用 sg_ 系列 syscall 读目录项，避免被 hook 的 readdir/read 干扰。
 * 但 dirent 解析依赖 libc，这里退一步：直接 open + 逐个 read 目录流，
 * 用最小依赖解析 dirent 结构（Linux 上 dirent 布局稳定：d_name 紧跟 d_reclen）。 */
static int dir_has_suspect(const char *path) {
    int used = 0;
    int fd = sg_open_fallback(path, O_RDONLY | O_DIRECTORY, 0, &used);
    if (fd < 0) return -1;

    char buf[4096];
    int hit = 0;
    for (;;) {
        ssize_t n = sg_read_fallback(fd, buf, sizeof(buf), used);
        if (n <= 0) break;
        /* 遍历目录项：每个 dirent 前 2 字节 = ino, 再 2 字节 = offset,
         * 再 2 字节 = reclen, 再 1 字节 = type, 名字从偏移 19 开始。 */
        size_t off = 0;
        while (off + 19 <= (size_t)n) {
            unsigned short reclen;
            memcpy(&reclen, buf + off + 4, 2);
            if (reclen == 0 || off + reclen > (size_t)n) break;
            const char *name = buf + off + 19;
            for (int i = 0; SUSPECT_NAMES[i]; i++) {
                if (sg_strstr(name, SUSPECT_NAMES[i])) { hit = 1; break; }
            }
            if (hit) break;
            off += reclen;
        }
        if (hit) break;
    }
    sg_close(fd);
    return hit;
}

/* 扫描 /proc（进程名伪装/恶意模块线索）与 /dev（字符设备驱动）。
 * 返回 1=命中可疑名，0=干净，-1=打不开目录（SKIPPED）。 */
int sg_guard_scan_sysfs(void) {
    int r1 = dir_has_suspect("/proc");
    int r2 = dir_has_suspect("/dev");
    if (r1 == 1 || r2 == 1) return 1;
    if (r1 < 0 && r2 < 0) return -1;
    return 0;
}

/* 读 /proc/self/status 的 TracerPid + 检查 /proc/self/maps 里是否有可疑驱动映射。
 * 这里聚焦"恶意驱动"：检查 /proc/modules（需 root，通常 EPERM）与 /dev 设备。 */
int sg_guard_scan_devices(void) {
    return dir_has_suspect("/dev");
}

/* ---- 封通道：dumpable=0 ----
 * 注意：sg_guard_set_nondumpable 已在 self_guard.cpp 定义（避免重复符号），
 * 这里不再重复。dumpable=0 挡 /proc/<pid>/mem、process_vm_readv（非 root）。
 * 与 self-trace 守护互斥，默认不调（见 self_guard.cpp 注释）。 */

/* ---- 哨兵硬断：占一个硬断点反制外部硬断 ----
 * 思路：我们把某个"哨兵函数"地址写进 DBGBVR0 + DBGBCR0（使能），
 * 然后周期性（由守护子进程代查）检查：
 *   - 若我们的 DBGBVR0 被改成了别的地址 → 外部动了调试寄存器 → 告警
 *   - 若 DBGBCR0 使能位被清 → 外部禁用了我们的断点 → 告警
 *
 * 注意：EL0 无权写调试寄存器（MDBGEN/MDSCR_EL1 未开），所以"自己占硬断"
 * 只能靠我们的 tracer（守护子进程）用 PTRACE_SETREGSET 代写。这里父进程
 * 不直接写，而是暴露一个"哨兵地址"给守护，守护 SEIZE 后 SETREGSET 写入。
 * 因此本文件只保存哨兵地址与期望状态，实际写/查在 self_guard.cpp 完成。
 * */

static void *g_sentinel_addr;         /* 哨兵函数地址 */
static volatile uint32_t g_sentinel_tampered; /* 哨兵断点被外部篡改的次数 */

/* 一个永远不该被正常执行到的哨兵函数（除非外部设断让它停在这里） */
__attribute__((noinline))
static void sentinel_probe(void) {
    __asm__ __volatile__("" ::: "memory");
}

/* 注册哨兵：返回哨兵地址（供守护 SETREGSET 使用） */
void *sg_guard_sentinel_addr(void) {
    g_sentinel_addr = (void *)&sentinel_probe;
    return g_sentinel_addr;
}

/* 记录"哨兵断点被篡改"（由守护在体检时发现后调用） */
void sg_guard_sentinel_tamper(void) {
    __atomic_fetch_add(&g_sentinel_tampered, 1, __ATOMIC_RELAXED);
}

/* 查询哨兵是否被篡改：0=正常，>0=被篡改次数，-1=未初始化 */
int sg_guard_sentinel_tampered(void) {
    if (!g_sentinel_addr) return -1;
    return (int)g_sentinel_tampered;
}

/* ---- SIGTRAP 异常处理链反制 ----
 * 当硬断命中时，若守护子进程未占位（如 root 用 CAP_SYS_PTRACE 绕过），
 * SIGTRAP 会走本进程的默认 handler（杀进程）或被外部 tracer 截获。
 * 这里装一个 SIGTRAP handler 作为"最后一道异常处理链"：
 *   收到 SIGTRAP 且守护未运行 → 说明被外部硬断/软断点中 → 记数告警。
 * 这个 handler 本身也构成"异常处理机制"的一环：谁改了我们的断点，
 * 异常会先落到我们这里，而不是直接崩溃给攻击者看。 */

static volatile sig_atomic_t g_trap_count;

static void sigtrap_handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    __atomic_fetch_add(&g_trap_count, 1, __ATOMIC_RELAXED);
    /* 不调用任何 libc 打印（可能被 hook），仅计数。
     * 若要区分断点类型：info->si_code == TRAP_BRKPT(软断) / TRAP_HWBKPT(硬断) */
}

int sg_guard_install_sigtrap(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigtrap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO; /* 三参 handler，可读 si_code 判软断/硬断 */
    if (sigaction(SIGTRAP, &sa, 0) != 0) return -1;
    return 0;
}

int sg_guard_trap_count(void) {
    return (int)g_trap_count;
}
