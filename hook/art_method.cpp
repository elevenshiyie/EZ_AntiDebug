#include <jni.h>
#include "../core/maps.h"
#include "../core/syscall_utils.h"
#include <stdint.h>
#include <string.h>

extern "C" {
int  sg_hook_art_entry_scan(JNIEnv *env, jclass ignored);
}

/* ============================================================================
 * ArtMethod entry 校验（抓 Java 层 hook：Xposed/LSPosed/夜安(YAHFA)/SandHook/
 * Pine/Epic/LSPlant —— 所有"改方法入口"的 ART hook）。
 *
 * 原理（学自 sentry D9）：jmethodID 在 ART 里就是 ArtMethod*。
 * Java hook 框架把 entry_point_from_quick_compiled_code 指向自己的
 * trampoline/可执行岛（匿名 r-x 段）。我们：
 *   1) JNI GetMethodID 拿 ArtMethod*；
 *   2) 按版本尝试偏移 {48, 56, 64} 读 entry（任一偏移落在合法区即算正常）；
 *   3) "合法区" = maps 里带文件路径的 r-x 段（libart/oat/本 app so）
 *              + 白名单命名的 JIT 段（dalvik-jit/jit-cache/code-cache）。
 *      entry 落在"无名且非白名单的匿名 r-x" → hook 可执行岛 → 命中。
 *
 * 为什么这是"大杀器"：类名/so/堆栈特征都会被魔改包名绕过，
 * 而"方法入口落在合法映射之外"是 hook 行为本身的物证。
 * ============================================================================ */

static int is_legal_exec(const SgMapEntry *maps, int count, uint64_t addr) {
    for (int i = 0; i < count; i++) {
        const SgMapEntry *m = &maps[i];
        if (m->perms[2] != 'x') continue;
        if (addr < m->start || addr >= m->end) continue;
        /* 命中一个可执行段：看它合不合法 */
        if (m->path[0] == '/') return 1; /* 文件映射：libart/oat/dex/本 app so */
        static const char *JIT[] = {
            "dalvik-jit", "dalvik-main", "jit-cache", "code-cache", 0
        };
        for (int j = 0; JIT[j]; j++)
            if (sg_strstr(m->path, JIT[j])) return 1;
        return 0; /* 无名非白名单匿名 r-x → 可执行岛 */
    }
    return 0;
}

/* entry_point_from_quick_compiled_code 在 ArtMethod 中的偏移随版本变化：
 * 常见公开值为 48 / 56 / 64（Android 7~14）。多偏移 OR-legal：任一合法即正常。 */
static const int ENTRY_OFFSETS[] = {48, 56, 64};

/* 纯 C 库自动启动模式下，不依赖宿主传类数组。
 * 默认检测一组高频被 hook 的系统类（hook 框架最常下手的地方）。 */
static const char *const DEFAULT_CLASSES[] = {
    "java/lang/System",        /* currentTimeMillis / exit 最常被 hook */
    "android/os/SystemClock",  /* 时间类，外挂变速最爱 */
    "java/lang/String",        /* equals / hashCode 常被 hook */
    0
};
static const char *const DEFAULT_METHODS[][2] = {
    {"currentTimeMillis", "()J"},
    {"elapsedRealtime", "()J"},
    {"hashCode", "()I"},
    0
};

int sg_hook_art_entry_scan(JNIEnv *env, jclass ignored) {
    (void)ignored;
    if (!env) return -1;

    SgMapEntry *maps = 0;
    int count = 0;
    if (!sg_read_maps(&maps, &count)) return -1;

    int suspicious = 0;

    for (int ci = 0; DEFAULT_CLASSES[ci] && !suspicious; ci++) {
        jclass cls = env->FindClass(DEFAULT_CLASSES[ci]);
        if (!cls) { env->ExceptionClear(); continue; }

        for (int mi = 0; DEFAULT_METHODS[mi][0]; mi++) {
            jmethodID mid = env->GetMethodID(cls, DEFAULT_METHODS[mi][0], DEFAULT_METHODS[mi][1]);
            if (!mid) { env->ExceptionClear(); continue; } /* 该签名不存在，跳过 */

            uintptr_t method = (uintptr_t)mid;
            if (!sg_mem_readable((const void *)method, 72)) {
                /* ArtMethod 结构不可读（极端情况）→ 跳过该方法 */
                continue;
            }

            int any_legal = 0;
            for (size_t oi = 0; oi < sizeof(ENTRY_OFFSETS) / sizeof(int); oi++) {
                uint64_t entry;
                memcpy(&entry, (const void *)(method + ENTRY_OFFSETS[oi]), sizeof(entry));
                if (entry == 0) continue; /* 该偏移不是 entry（读到别的字段为 0） */
                if (is_legal_exec(maps, count, entry)) { any_legal = 1; break; }
            }
            if (!any_legal) {
                /* 三个偏移读出的指针全都落在合法区之外 → 入口被指走了 */
                suspicious = 1;
                break;
            }
        }
    }

    sg_free_maps(maps);
    return suspicious;
}
