#include "../core/syscall_utils.h"
#include <stdint.h>
#include <string.h>

extern "C" {
void sg_memory_init(void);
int  sg_memory_canary_check(void);
int  sg_memory_guard_probe(void);
}

/* ============================================================================
 * 内存域检测：定位是"防篡改"，不是"防读"。
 *
 * 为什么不做"指针置 0 当陷阱检测谁在读"：
 *   外部进程(CE/Frida/gdb)读你的内存走 process_vm_readv / /proc/pid/mem / ptrace，
 *   由内核完成，目标进程不会收到任何信号/异常，你的代码根本没机会执行。
 *   纯用户态无从感知"读"这个动作本身。
 *
 * 真正可行的两件事：
 *   1) canary  -- 给关键对象附一个随机令牌+校验和，定时比对。抓"被改写"(外挂改数值)。
 *   2) guard  -- 对本进程内关键页 mprotect(PROT_NONE) + SIGSEGV handler，
 *                抓"本进程内代码"的越权访问(注入 so / inline hook 后解引用)。
 *      注意：这抓不到外部进程的读取，别在 README 里夸大。
 * ========================================================================== */

/* --- 演示对象：模拟 UE 里你关心的 AActor* rootComponent 这种关键指针 --- */
struct GuardedObject {
    void   *criticalPtr;   // 模拟 rootComponent
    uint64_t magic;        // 编译期常量，检测"整个对象被清零/置 0"
    uint64_t token;        // 运行期随机令牌
    uint64_t checksum;     // F(criticalPtr, token)
};

static GuardedObject g_guarded;

static uint64_t mix64(uint64_t x) {
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27; x *= 0x94d049bb133111ebULL;
    x ^= x >> 31; return x;
}
static uint64_t calc_checksum(const GuardedObject *o) {
    return mix64((uint64_t)(uintptr_t)o->criticalPtr ^ o->token ^ o->magic);
}

void sg_memory_init(void) {
    g_guarded.magic = 0x53474e54494e454cULL;   // "SENTINEL"
    g_guarded.token = mix64((uint64_t)(uintptr_t)&g_guarded ^ 0x9e3779b97f4a7c15ULL);
    g_guarded.criticalPtr = &g_guarded;          // 指向自身，占位
    g_guarded.checksum = calc_checksum(&g_guarded);
}

/* 返回 1=可疑(被篡改) 0=正常。定时(如每 2s)调用一次。 */
int sg_memory_canary_check(void) {
    if (g_guarded.magic != 0x53474e54494e454cULL) return 1;  // 整块被清零 → 你的"置0陷阱"能抓到的是这种
    if (calc_checksum(&g_guarded) != g_guarded.checksum) return 1;
    return 0;
}

/* 返回一个可被后续 mprotect 守护的地址，交给 JNI 侧安装 SIGSEGV handler。
 * demo 里只返回有效性，真正的 guard page + handler 见 docs/DETECTION_SPEC.md。 */
int sg_memory_guard_probe(void) {
    return sg_mem_readable(&g_guarded, sizeof(g_guarded)) ? 0 : -1;
}
