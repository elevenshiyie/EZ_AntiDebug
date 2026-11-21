/* ============================================================================
 * Anti-Shadow-Hook：检测"影子页 + 异常处理机制"类 hook。
 *
 * 针对的是这种纯用户态 hook 手法（如用户贴的 SIGHOOK / shadowpage_hook）：
 *   1) 把目标函数页 mprotect 成 无执行权限(PROT_READ|WRITE)，制造"执行即缺页"；
 *   2) 装 SIGSEGV handler，在缺页时把 pc 改到"影子页"（从一块大内存池切出）；
 *   3) 影子页开头 BRK #0 触发 SIGTRAP，trap handler 再把 pc 改到 hook 函数；
 *   4) 用 seccomp 过滤器锁住 rt_sigaction/rt_sigprocmask，防止目标反杀 handler；
 *   5) 用后台线程周期 mprotect 回 PROT_READ|WRITE，对抗目标恢复页权限。
 *
 * 为什么用户态能防：这套东西每一步都调用用户态 API，必然留下可观察痕迹：
 *
 *  指纹 1（最强）——代码段丢执行权限：
 *      目标函数所在页被 mprotect 成 rw-p/r--p，而磁盘 ELF 里它本该是 r-xp。
 *      直接扫 /proc/self/maps，找出"带路径的可执行段"里 perms 少了 'x' 的段。
 *
 *  指纹 2——匿名 r-x 内存池（影子页/跳板所在）：
 *      8MB 级 alignas(16384) 的 MEMORY_POOL，mprotect 成 r-xp，无文件路径。
 *      这是匿名可执行段的典型，但阈值要够低（这块池子通常 8MB，远超
 *      一般 JIT 白名单阈值）。配合 inject.anon_rx 一起判。
 *
 *  指纹 3——非默认信号 handler（SIGSEGV/SIGTRAP/SIGSYS 被捕获）：
 *      /proc/self/status 的 SigCgt 位掩码，bit 对应信号号。
 *      SIGSEGV(11)、SIGTRAP(5)、SIGSYS(31) 正常进程不该捕获，被置位即异常。
 *
 *  指纹 4——seccomp filter 模式：
 *      /proc/self/status 的 Seccomp 字段 = 2 表示安装了 seccomp-bpf 过滤器。
 *      普通 app 不该有；hook 用它锁信号 handler。置 2 即异常。
 *
 * 边界（诚实写）：
 *   - 这些全是"检测"，不是"拦截"——发现 hook 后我们只能告警/上报。
 *   - 若攻击者用内核态改页表做真·影子页（不 mprotect、不装 handler），
 *     上述用户态指纹全部失效——那属于内核态范畴，本模块不承诺覆盖。
 *
 * 白名单驱动（重要）：
 *   这三条信号在"裸"判定下几乎所有真实 App 都会亮（UE/JIT 改段权限、
 *   ART 装 SIGSEGV、内嵌 WebView 装 seccomp）。因此每条检测先查全局白名单
 *   （core/whitelist），命中 → 放行(OK)，否则才告警。接入方通过 sg_wl_* 注册
 *   自己 App 的常态特征；未注册时这些信号仍会亮，提醒接入方"补齐白名单"。
 * ========================================================================== */

#include "../core/maps.h"
#include "../core/syscall_utils.h"
#include "../core/whitelist.h"
#include <stdint.h>
#include <string.h>

extern "C" {
int  sg_guard_text_exec_check(char *buf, size_t len);
int  sg_guard_shadow_pool_check(void);
int  sg_guard_signal_handler_check(char *buf, size_t len);
int  sg_guard_seccomp_check(void);
}

/* ---- 指纹 1：代码段/数据段权限被异常翻转 ----
 * SIGHOOK 这类影子页 hook 必然做两件权限翻转：
 *   (a) 目标函数页 mprotect 成 PROT_READ|WRITE → .text 丢 'x'、多了 'w'；
 *   (b) 内存池 MEMORY_POOL 从 .rodata/.bss mprotect 成 r-x → 数据段多了 'x'。
 * 两个方向都扫：找到"文件映射段"里权限异常的组合即告警。
 * 返回 1=权限异常，0=正常，-1=读不到 maps。 */
int sg_guard_text_exec_check(char *buf, size_t len) {
    if (buf && len) buf[0] = 0;
    SgMapEntry *maps = 0;
    int count = 0;
    if (!sg_read_maps(&maps, &count)) return -1;

    int hit = 0;
    for (int i = 0; i < count; i++) {
        const SgMapEntry *m = &maps[i];
        /* 只看有文件路径的段（so/oat/dex），匿名段另查 */
        if (m->path[0] != '/') continue;

        /* 白名单：命中"系统只读分区前缀"或"App 常态子串"白名单的段，
         * 其 mprotect 改动视为平台/App 自身行为，放行。 */
        if (sg_wl_match_path_prefix(m->path)) continue;
        if (sg_wl_match_path(m->path)) continue;

        int is_exec_file = sg_strstr(m->path, ".so") || sg_strstr(m->path, ".oat")
            || sg_strstr(m->path, ".vdex") || sg_strstr(m->path, ".art")
            || sg_strstr(m->path, ".dex");

        /* 方向 (a)：代码段丢执行权限——本该 r-xp 的段变成 rw-p / r--p。
         * 特征：有读、无执行、且可写（.text 被改成 RW 才能反复 mprotect 对抗） */
        if (is_exec_file && m->perms[0] == 'r' && m->perms[2] != 'x'
            && m->perms[1] == 'w') {
            hit = 1;
            if (buf && len) sg_strncpy(buf, m->path, len);
            break;
        }
        /* 方向 (b)：数据段被改成可执行——rodata/data 本该 r--p/rw-p，
         * 现在多了 'x'（MEMORY_POOL 被 memory_pool_read_exec 打开执行）。
         * 注意要排除 .so 里正常的 r-xp .text 段：真正的 .text 本身就是 r-xp，
         * 所以这里只看"可写且可执行"的 rwxp 段（数据段被开执行+写），
         * 以及"只读但可执行"里路径含 .rodata 字样的异常。 */
        if (is_exec_file && m->perms[2] == 'x' && m->perms[1] == 'w') {
            hit = 1;
            if (buf && len) sg_strncpy(buf, m->path, len);
            break;
        }
    }
    sg_free_maps(maps);
    return hit;
}

/* ---- 指纹 2：匿名大内存池（影子页/跳板） ----
 * 影子页 hook 需要一个 8MB 级 r-x 匿名池。这里扫 maps 里"无路径、有 x、
 * size 超过阈值"的匿名段。阈值设 1MB，避开正常的 JIT(几十 KB) 与 scudo。 */
int sg_guard_shadow_pool_check(void) {
    SgMapEntry *maps = 0;
    int count = 0;
    if (!sg_read_maps(&maps, &count)) return -1;

    int hit = 0;
    for (int i = 0; i < count; i++) {
        const SgMapEntry *m = &maps[i];
        /* 只要匿名段：无路径，或路径以 '[' 开头（[anon:...] / [heap] 等） */
        if (m->path[0] != '\0' && m->path[0] != '[') continue;
        if (m->perms[2] != 'x') continue;            /* 要可执行 */
        uint64_t size = m->end - m->start;
        /* 影子页池通常 1MB~8MB；正常 JIT 段一般 < 256KB。
         * 但要排除 [vdso]/[vvar] 这类系统固定小段（它们 < 1MB 不影响）。 */
        if (size >= (1u << 20)) { hit = 1; break; }
    }
    sg_free_maps(maps);
    return hit;
}

/* ---- 指纹 3 + 4：读 /proc/self/status 的 SigCgt 与 Seccomp ----
 * 返回 bitmask 编码：bit0=SIGSEGV被捕获, bit1=SIGTRAP被捕获,
 * bit2=SIGSYS被捕获, bit3=seccomp filter 模式。0=干净，-1=读不到。 */
static int read_status_signal_bits(void) {
    int used = 0;
    int fd = sg_open_fallback("/proc/self/status", 0, 0, &used);
    if (fd < 0) return -1;
    char buf[8192]; size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = sg_read_fallback(fd, buf + n, sizeof(buf) - 1 - n, used);
        if (r <= 0) break;
        n += (size_t)r;
    }
    buf[n] = 0; sg_close(fd);

    int result = 0;
    const char *p = sg_strstr(buf, "SigCgt:");
    if (p) {
        p += sg_strlen("SigCgt:");
        /* SigCgt 是 64-bit 掩码的十六进制字符串 */
        while (*p == ' ' || *p == '\t') p++;
        unsigned long long sigcgt = 0;
        for (int i = 0; i < 16 && *p; i++) {
            char c = *p;
            unsigned long long v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else break;
            sigcgt = (sigcgt << 4) | v;
            p++;
        }
        /* SIGSEGV=11, SIGTRAP=5, SIGSYS=31 */
        if (sigcgt & (1ULL << 11)) result |= 1;  /* SIGSEGV */
        if (sigcgt & (1ULL << 5))  result |= 2;  /* SIGTRAP */
        if (sigcgt & (1ULL << 31)) result |= 4;  /* SIGSYS */
    }

    p = sg_strstr(buf, "Seccomp:");
    if (p) {
        p += sg_strlen("Seccomp:");
        while (*p == ' ' || *p == '\t') p++;
        int seccomp = 0;
        while (*p >= '0' && *p <= '9') { seccomp = seccomp * 10 + (*p - '0'); p++; }
        if (seccomp == 2) result |= 8;  /* seccomp filter 模式 */
    }

    return result;
}

int sg_guard_signal_handler_check(char *buf, size_t len) {
    if (buf && len) buf[0] = 0;
    int bits = read_status_signal_bits();
    if (bits < 0) return -1;

    /* 逐信号判定，命中白名单的号放行。这样"ART 装 SIGSEGV"可白名单，
     * 而 SIGTRAP/SIGSYS 被 SIGHOOK 捕获时仍能告警。 */
    int suspicious = 0;
    if ((bits & 0x1) && !sg_wl_match_signal(11)) suspicious = 1;  /* SIGSEGV */
    if ((bits & 0x2) && !sg_wl_match_signal(5))  suspicious = 1;  /* SIGTRAP */
    if ((bits & 0x4) && !sg_wl_match_signal(31)) suspicious = 1;  /* SIGSYS */

    /* 输出触发命中的信号号（诊断白名单缺口） */
    if (suspicious && buf && len) {
        int pos = 0;
        const char *names[3] = { "SIGSEGV(11)", "SIGTRAP(5)", "SIGSYS(31)" };
        int flags[3] = { (bits & 0x1) && !sg_wl_match_signal(11),
                         (bits & 0x2) && !sg_wl_match_signal(5),
                         (bits & 0x4) && !sg_wl_match_signal(31) };
        for (int i = 0; i < 3 && pos < (int)len - 1; i++) {
            if (!flags[i]) continue;
            if (pos > 0 && pos < (int)len - 1) buf[pos++] = ',';
            const char *n = names[i];
            while (*n && pos < (int)len - 1) buf[pos++] = *n++;
        }
        buf[pos] = 0;
    }
    return suspicious;
}

int sg_guard_seccomp_check(void) {
    if (sg_wl_seccomp_enabled()) return 0;   /* App 声明 seccomp 属常态 */
    int bits = read_status_signal_bits();
    if (bits < 0) return -1;
    return (bits & 0x8) ? 1 : 0;             /* seccomp filter 模式 */
}
