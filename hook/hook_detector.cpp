#include "../core/maps.h"
#include "../core/syscall_utils.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
int  sg_hook_inline_scan(void);
int  sg_hook_got_scan(void);
int  sg_hook_ue_processevent_scan(char *buf, size_t len);
}

#if defined(__aarch64__)
/* Frida/Dobby 典型的 8 字节 inline trampoline:
 *   ldr x16, [pc, #8]; br x16  => 58 00 00 50  00 02 1f d6
 *   ldr x17, [pc, #8]; br x17  => 59 00 00 50  20 02 1f d6
 * 确定性特征，误报极低。 */
static int is_frida_trampoline(const uint8_t *b) {
    const uint64_t p1 = 0xD61F020058000050ULL;
    const uint64_t p2 = 0xD61F022059000050ULL;
    const uint64_t p3 = 0xD61F022058000051ULL;
    uint64_t w; memcpy(&w, b, 8);
    return w == p1 || w == p2 || w == p3;
}

/* 从 trampoline 首部解析绝对跳转目标。Dobby 布局：
 *   [0..7]   ldr x16, [pc, #8]; br x16
 *   [8..15]  <8 字节绝对目标地址>
 * 返回 1 表示解析成功，*target 存目标地址。 */
static int trampoline_target(const uint8_t *b, uint64_t *target) {
    if (!is_frida_trampoline(b)) return 0;
    uint64_t t; memcpy(&t, b + 8, 8);
    *target = t;
    return 1;
}

/* 测试期白名单：跳转目标落在这些"合法 hook 来源 so"内就放行。
 * 场景：游戏自己的 wind.so 用 Dobby hook eglSwapBuffers 实现联机/地图，
 * 行为与外挂同源，但来源合法。测试期硬编码，开源前再决定是否保留。 */
static int is_legit_hook_owner(const char *path) {
    if (!path || !path[0]) return 0;
    static const char *LEGIT[] = {
        "wind.so",        /* 游戏自研联机/地图库，Dobby hook 是正常功能 */
        0
    };
    for (int i = 0; LEGIT[i]; i++)
        if (sg_strstr(path, LEGIT[i])) return 1;
    return 0;
}
#endif

/* inline hook：看常见函数首部。XOM 守卫必须放前面——只执行段直接读会 SEGV。
 * 目标分两类：
 *   (1) libc 高频函数（Frida/普通 inline hook 常挂这里）；
 *   (2) 系统渲染库导出函数（eglSwapBuffers 等）——外挂/Dobby 最爱 hook
 *       渲染入口来画自己的 UI/Esp，这类 hook 挂的是 libEGL/libGLESv3，
 *       漏扫就等于漏掉一大类外挂。 */
int sg_hook_inline_scan(void) {
#if defined(__aarch64__)
    /* 名字 + 所在库（dlsym 时限定优先从该库解析，避免误解析到别处） */
    static const struct { const char *sym; const char *lib; } TARGETS[] = {
        { "open",             "libc.so" },
        { "read",             "libc.so" },
        { "strcmp",           "libc.so" },
        { "malloc",           "libc.so" },
        { "eglSwapBuffers",   "libEGL.so" },
        { "eglSwapBuffersWithDamageKHR", "libEGL.so" },
        { "glDrawArrays",     "libGLESv3.so" },
        { "glDrawElements",   "libGLESv3.so" },
        { 0, 0 }
    };
    int hooked = 0;
    for (int i = 0; TARGETS[i].sym; i++) {
        void *sym = dlsym(RTLD_DEFAULT, TARGETS[i].sym);
        if (!sym) continue;
        if (!sg_mem_readable(sym, 16)) continue;  // XOM → 跳过，不误报、不崩溃
        if (!is_frida_trampoline((const uint8_t *)sym)) continue;
        /* 首部是 trampoline：解析跳转目标，判断归属。目标落在合法 so（如
         * wind.so）则放行——那是游戏自己的 Dobby hook，不是外挂。 */
        uint64_t target = 0;
        char owner[256] = {0};
        if (trampoline_target((const uint8_t *)sym, &target)
            && sg_addr_owner_path(target, owner, sizeof(owner))
            && is_legit_hook_owner(owner)) {
            continue;  // 合法 hook 来源，跳过
        }
        hooked = 1;
        break;
    }
    return hooked;
#else
    return -1;
#endif
}

/* GOT 劫持：dlsym 解析出的函数地址若落在"可疑匿名可执行段"，
 * 说明 GOT/PLT 被指向了 trampoline。不改 text，CRC 抓不到，必须靠这条。 */
int sg_hook_got_scan(void) {
    const char *names[] = { "open", "read", "strcmp",
                            "eglSwapBuffers", "glDrawArrays", 0 };
    SgMapEntry *maps = 0; int count = 0;
    if (!sg_read_maps(&maps, &count)) return -1;
    int hooked = 0;
    for (int i = 0; names[i] && !hooked; i++) {
        void *sym = dlsym(RTLD_DEFAULT, names[i]);
        if (!sym) continue;
        uint64_t a = (uint64_t)(uintptr_t)sym;
        for (int j = 0; j < count; j++) {
            if (sg_is_suspicious_anon_rx(&maps[j]) && a >= maps[j].start && a < maps[j].end) {
                hooked = 1; break;
            }
        }
    }
    sg_free_maps(maps);
    return hooked;
}

/* 说明：不提供基于 LR(x30) 寄存器的 hook 检测。
 * 原因：AArch64 上函数内的 `mov x30` 拿到的不是"调用者地址"——函数 prologue
 * 先把 x29/x30 压栈保存，之后 x30 被编译器复用为临时寄存器，读到的值是残留的
 * 任意值，检测结果随机漂移，无判别力。真正的"调用者归属"必须走
 * __builtin_return_address + 明确禁止尾调用优化，且即便拿到也只在特定调用链
 * 有意义，收益与复杂度不匹配。故以 hook.ue_procevt（按基址+RVA 读跳板）作为
 * UE hook 检测的正解。 */

/* ---- UE processEvent 地址 hook 检测（按基址+偏移读跳板） ----
 *
 * 场景：外挂 hook UE 引擎的 processEvent（任务坐标等关键逻辑入口）实现透视。
 * processEvent 是 UE 引擎内部函数，地址 = 引擎 so 基址 + 固定偏移（RVA）。
 *
 * 检测：anti 自己拿引擎 so 基址 + RVA，读该地址前 8 字节，判断是否被改写成
 * Dobby/Frida 的 inline trampoline（ldr x16/x17; br x16/x17）。外挂 hook 了它
 * → 首部必是跳板 → 告警。不依赖 dlsym 符号名，直接按地址读。
 *
 * 注意：UE_PROCESS_EVENT_RVA 是占位示例值，接入方按自己逆向出的 processEvent
 * 偏移替换（不同游戏/引擎版本偏移不同）。
 *
 * 返回：0=OK（首部未被 hook），1=SUSPICIOUS（首部是跳板），-1=SKIPPED（读不到）。 */

/* 占位：接入方替换为自己逆向出的 processEvent 相对引擎 so 基址的 RVA */
#ifndef UE_PROCESS_EVENT_RVA
#define UE_PROCESS_EVENT_RVA 0x00000000
#endif

int sg_hook_ue_processevent_scan(char *buf, size_t len) {
#if defined(__aarch64__)
    if (buf && len) buf[0] = 0;

    /* 定位引擎 so 基址（每轮重查，因为引擎可能延迟加载）。
     * 接入方按自己引擎替换模块名（UE4 用 libUE4.so，其他引擎对应改）。 */
    uint64_t base = sg_module_base("libUE4.so", 0, 0);
    if (!base) return -1;   /* 引擎未加载 → SKIPPED */

    uint64_t addr = base + UE_PROCESS_EVENT_RVA;   /* processEvent RVA */

    /* XOM 守卫：读前判可读，否则不误报不崩溃 */
    if (!sg_mem_readable((const void *)(uintptr_t)addr, 16)) return -1;

    if (is_frida_trampoline((const uint8_t *)(uintptr_t)addr)) {
        if (buf && len) {
            snprintf(buf, len, "processEvent@%llx trampoline", (unsigned long long)addr);
        }
        return 1;
    }
    return 0;
#else
    return -1;
#endif
}
