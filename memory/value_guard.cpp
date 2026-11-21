#include "value_guard.h"
#include "../core/syscall_utils.h"
#include "../core/safe_read.h"
#include "../core/maps.h"
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <android/log.h>

#define VG_TAG "AntiCheat"
#define VG_LOGI(...) __android_log_print(ANDROID_LOG_INFO, VG_TAG, __VA_ARGS__)
#define VG_LOGW(...) __android_log_print(ANDROID_LOG_WARN, VG_TAG, __VA_ARGS__)

/* ============================================================================
 * 关键值守护实现：后台线程周期读关键值，与基线比对，抓"被改写"。
 *
 * 这是"防写入"检测的核心：外挂改关键数值（血量/上限/金币这类），我们能抓到。
 * 与 mem.canary 的区别：canary 守护的是 anti 自己的本地对象；本模块守护
 * 的是"游戏真实内存里的值"，通过 UE 侧传入的 getter 回调读取。
 * ========================================================================== */

#define SG_VALUE_GUARD_MAX 16          /* 最多守护 16 个关键值 */
#define SG_VALUE_GUARD_INTERVAL_MS 2000  /* 巡检间隔 2s（可调） */

/* 链失效哨兵：getter 返回此值表示"指针链断了/地址不可读"，区别于任何真实
 * 业务值（int32 范围 [-2^31, 2^31-1]，用 int64 极值绝不可能撞上真实值）。 */
#define SG_VALUE_SENTINEL ((int64_t)0x7FFFFFFFFFFFFFFFLL)
/* 连续失败多少次才把"链失效"定性为 SKIPPED（避免引擎加载瞬间误标） */
#define SG_VALUE_FAIL_LIMIT 5

typedef struct {
    sg_value_getter_fn     getter;     /* 无上下文 getter */
    sg_value_getter_ctx_fn getter_ctx; /* 带上下文 getter */
    void                  *ctx;
    char                   name[64];
    int64_t                baseline;   /* 首次读到有效值时的基线 */
    int                    inited;     /* 是否已锁定有效基线 */
    int                    tampered;   /* 已被判篡改 */
    int                    fail_count; /* 连续链失效次数 */
    int                    dead;       /* 链已定性失效(>FAIL_LIMIT)，本轮不再报 */
    int                    is_bitf;    /* 值是 float/double 的位模式（需还原语义显示） */
} SgValueGuardSlot;

/* 按位模式类型把 int64 还原成可读字符串，供日志展示。
 * is_bitf=0 直接按十进制打印；is_bitf=1 按 float 位模式打印（附十进制）。 */
static void fmt_value(char *out, size_t out_len, int64_t v, int is_bitf) {
    if (is_bitf) {
        float f; int32_t b = (int32_t)(v & 0xFFFFFFFF);
        memcpy(&f, &b, 4);
        /* float 位模式：显示 float 值 + 原始十六进制位 */
        snprintf(out, out_len, "%g (bits 0x%08X)", (double)f, (unsigned)b);
    } else {
        snprintf(out, out_len, "%lld", (long long)v);
    }
}

static SgValueGuardSlot g_slots[SG_VALUE_GUARD_MAX];
static int              g_slot_n;
static pthread_mutex_t  g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t        g_thread;
static volatile int     g_running;
static volatile int     g_any_tampered;

/* ---- 注册 ---- */
int sg_value_guard_register(sg_value_getter_fn getter, const char *name) {
    if (!getter) return -1;
    pthread_mutex_lock(&g_lock);
    int rc = -1;
    if (g_slot_n < SG_VALUE_GUARD_MAX) {
        SgValueGuardSlot *s = &g_slots[g_slot_n];
        s->getter = getter;
        s->getter_ctx = 0;
        s->ctx = 0;
        s->baseline = 0;
        s->inited = 0;
        s->tampered = 0;
        s->fail_count = 0;
        s->dead = 0;
        s->is_bitf = 0;
        sg_strncpy(s->name, name ? name : "(unnamed)", sizeof(s->name));
        g_slot_n++;
        rc = 0;
    }
    pthread_mutex_unlock(&g_lock);
    return rc;
}

int sg_value_guard_register_ctx(sg_value_getter_ctx_fn getter, void *ctx,
                                const char *name) {
    if (!getter) return -1;
    pthread_mutex_lock(&g_lock);
    int rc = -1;
    if (g_slot_n < SG_VALUE_GUARD_MAX) {
        SgValueGuardSlot *s = &g_slots[g_slot_n];
        s->getter = 0;
        s->getter_ctx = getter;
        s->ctx = ctx;
        s->baseline = 0;
        s->inited = 0;
        s->tampered = 0;
        s->fail_count = 0;
        s->dead = 0;
        s->is_bitf = 0;
        sg_strncpy(s->name, name ? name : "(unnamed)", sizeof(s->name));
        g_slot_n++;
        rc = 0;
    }
    pthread_mutex_unlock(&g_lock);
    return rc;
}

/* ---- 单槽巡检：读当前值，比对基线 ----
 *
 * 关键修正（修复"改值后无输出"的根因）：
 *   1) getter 返回哨兵 SG_VALUE_SENTINEL 表示"链断/地址不可读"，此时跳过本轮
 *      —— 既不设基线、也不判篡改。旧实现把 -1 直接当基线锁死，导致链断时
 *      基线被污染成 -1，之后任何真实变化都被 -1 掩盖，改值永远不告警。
 *   2) 首次读到有效值才锁定基线；锁定后值变化即判篡改并打日志。
 *   3) 连续 SG_VALUE_FAIL_LIMIT 次失效 → 定性 dead（链长期断，可能引擎卸载/
 *      偏移错），打一次日志后静默，避免每轮刷屏。链一旦恢复自动清零复活。 */
static void check_slot(SgValueGuardSlot *s) {
    int64_t cur;
    if (s->getter_ctx) cur = s->getter_ctx(s->ctx);
    else if (s->getter) cur = s->getter();
    else return;

    /* 链断：跳过本轮，累计失败，不定性基线 */
    if (cur == SG_VALUE_SENTINEL) {
        s->fail_count++;
        if (!s->dead && s->fail_count >= SG_VALUE_FAIL_LIMIT) {
            s->dead = 1;
            VG_LOGW("[value_guard] '%s' chain dead (>%d fails) — engine not loaded or offsets wrong",
                    s->name, SG_VALUE_FAIL_LIMIT);
        }
        return;
    }

    /* 链恢复正常：清零失败计数与 dead 标记 */
    if (s->fail_count || s->dead) {
        char buf[64];
        fmt_value(buf, sizeof(buf), cur, s->is_bitf);
        VG_LOGI("[value_guard] '%s' chain recovered (cur=%s)", s->name, buf);
        s->fail_count = 0;
        s->dead = 0;
    }

    if (!s->inited) {
        /* 首次读到有效值：锁定基线 */
        s->baseline = cur;
        s->inited = 1;
        char buf[64];
        fmt_value(buf, sizeof(buf), cur, s->is_bitf);
        VG_LOGI("[value_guard] '%s' baseline locked = %s", s->name, buf);
        return;
    }
    if (cur != s->baseline) {
        if (!s->tampered) {
            char old_buf[64], new_buf[64];
            fmt_value(old_buf, sizeof(old_buf), s->baseline, s->is_bitf);
            fmt_value(new_buf, sizeof(new_buf), cur, s->is_bitf);
            VG_LOGW("[value_guard] '%s' TAMPERED: %s -> %s",
                    s->name, old_buf, new_buf);
        }
        s->tampered = 1;
        __atomic_store_n(&g_any_tampered, 1, __ATOMIC_RELAXED);
    }
}

/* ---- 守护线程 ---- */
static void *guard_loop(void *arg) {
    (void)arg;
    while (g_running) {
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < g_slot_n; i++) {
            check_slot(&g_slots[i]);
        }
        pthread_mutex_unlock(&g_lock);

        struct timespec ts = { SG_VALUE_GUARD_INTERVAL_MS / 1000,
                               (SG_VALUE_GUARD_INTERVAL_MS % 1000) * 1000 * 1000 };
        nanosleep(&ts, 0);
    }
    return 0;
}

int sg_value_guard_start(void) {
    if (g_running) return 0;
    g_running = 1;
    __atomic_store_n(&g_any_tampered, 0, __ATOMIC_RELAXED);
    if (pthread_create(&g_thread, 0, guard_loop, 0) != 0) {
        g_running = 0;
        return -1;
    }
    return 0;
}

void sg_value_guard_stop(void) {
    g_running = 0;
    if (g_thread) pthread_join(g_thread, 0);
    g_thread = 0;
}

/* ---- 查询 ---- */
int sg_value_guard_tampered(void) {
    return __atomic_load_n(&g_any_tampered, __ATOMIC_RELAXED) ? 1 : 0;
}

int sg_value_guard_tampered_names(char *buf, size_t len) {
    if (!buf || len == 0) return 0;
    buf[0] = 0;
    int n = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_slot_n; i++) {
        if (!g_slots[i].tampered) continue;
        size_t used = sg_strlen(buf);
        if (used && used + 1 < len) { buf[used] = ','; buf[used + 1] = 0; used++; }
        if (used < len) sg_strncpy(buf + used, g_slots[i].name, len - used);
        n++;
    }
    pthread_mutex_unlock(&g_lock);
    return n;
}

/* ============================================================================
 * 内置偏移链守护（无需 UE 传回调，anti 自己沿指针链读）
 *
 * 背景：做项目/面试阶段不方便改 UE 源码，anti.so 必须自己内置"防写"能力：
 *   用 sg_module_base(module) 拿引擎基址，沿偏移链安全解引用读关键值，
 *   首次设基线，之后值变即判篡改。
 *
 * 关键：链上每一步 sg_safe_read_ptr 判 0（链断/失效/被改）→ 返回哨兵 -1，
 * 绝不 SIGSEGV。这是"防写"检测在 anti 内部自洽的关键。
 * ========================================================================== */

typedef struct {
    uint64_t base;           /* 模块基址（注册时解析一次，也可每轮重算） */
    uint32_t off[16];        /* 偏移链 */
    int      n;
    sg_chain_leaf_type leaf_type; /* 末层读值类型 */
} SgChainCtx;

/* 末层按 leaf_type 读值，统一归一成 int64（float/double 读其位模式存进 int64，
 * 供 check_slot 判"变没变"；日志展示时再按类型还原语义）。 */
static int64_t chain_read_leaf(SgChainCtx *c, uintptr_t p) {
    uintptr_t addr = p + c->off[c->n - 1];
    switch (c->leaf_type) {
        case SG_LEAF_I32: return (int64_t)sg_safe_read_i32(addr);
        case SG_LEAF_U32: return (int64_t)sg_safe_read_u32(addr);
        case SG_LEAF_I64: return (int64_t)sg_safe_read_i64(addr);
        case SG_LEAF_U64: return (int64_t)sg_safe_read_u64(addr);
        case SG_LEAF_F32: { float f = sg_safe_read_float(addr); int32_t b; memcpy(&b, &f, 4); return (int64_t)b; }
        case SG_LEAF_F64: { double d = sg_safe_read_double(addr); int64_t b; memcpy(&b, &d, 8); return b; }
        case SG_LEAF_PTR: return (int64_t)sg_safe_read_ptr(addr);
        default:          return (int64_t)sg_safe_read_i32(addr);
    }
}

/* 偏移链 getter：沿 base + off[] 读末层值（末层类型由 leaf_type 决定）。
 * 链上任何一步失败返回哨兵 SG_VALUE_SENTINEL（而非 -1），让 check_slot 能区分
 * "链断"(跳过本轮) 与 "真实读到值 -1"(合法业务值)。 */
static int64_t chain_getter_wrap(void *ctx) {
    SgChainCtx *c = (SgChainCtx *)ctx;
    if (!c || c->n < 1) return SG_VALUE_SENTINEL;

    /* 第 0 层：world = *(base + off[0]) */
    uintptr_t p = sg_safe_read_ptr(c->base + c->off[0]);
    if (!p) return SG_VALUE_SENTINEL;

    /* 中间层：p = *(p + off[i])，i=1..n-2 */
    for (int i = 1; i < c->n - 1; i++) {
        p = sg_safe_read_ptr(p + c->off[i]);
        if (!p) return SG_VALUE_SENTINEL;
    }

    /* 末层：按 leaf_type 读 */
    return chain_read_leaf(c, p);
}

int sg_value_guard_register_chain(const char *module, const uint32_t *off_chain,
                                  int n, const char *name) {
    return sg_value_guard_register_chain_typed(module, off_chain, n,
                                               SG_LEAF_I32, name);
}

int sg_value_guard_register_chain_typed(const char *module,
                                        const uint32_t *off_chain, int n,
                                        sg_chain_leaf_type leaf_type,
                                        const char *name) {
    if (!module || !off_chain || n < 1 || n > 16) return -1;
    uint64_t base = sg_module_base(module, 0, 0);
    if (!base) return -1;   /* 引擎还没加载/找不到 → 注册失败，稍后可重试 */

    /* 分配上下文（简单起见用静态池，链上下文与槽位一一对应） */
    static SgChainCtx g_chain_ctx[SG_VALUE_GUARD_MAX];
    static int g_chain_n = 0;
    if (g_chain_n >= SG_VALUE_GUARD_MAX) return -1;
    SgChainCtx *c = &g_chain_ctx[g_chain_n];
    c->base = base;
    c->n = n;
    c->leaf_type = leaf_type;
    for (int i = 0; i < n; i++) c->off[i] = off_chain[i];

    /* 复用现有回调注册，用函数指针 + 上下文 */
    int rc = sg_value_guard_register_ctx((sg_value_getter_ctx_fn)chain_getter_wrap,
                                         c, name);
    if (rc == 0) {
        /* 记录末层类型是 float/double（位模式），日志按语义还原 */
        pthread_mutex_lock(&g_lock);
        if (g_slot_n > 0) {
            g_slots[g_slot_n - 1].is_bitf =
                (leaf_type == SG_LEAF_F32 || leaf_type == SG_LEAF_F64) ? 1 : 0;
        }
        pthread_mutex_unlock(&g_lock);
        g_chain_n++;
    }
    return rc;
}

int sg_value_guard_register_builtin_clientcap(void) {
    /* 内置示例：接入方按自己游戏的指针链替换这里。
     * 偏移链语义：world = *(base + off[0])，然后 p = *(p + off[i])，
     * 末层按 leaf_type 读。下面全部是占位示例值（0x1000/0x20/0x30/0x40），
     * 实际偏移由接入方按自己逆向结果填入，模块名也换成自己的引擎 so。 */
    static const uint32_t off[] = { 0x1000, 0x20, 0x30, 0x0, 0x40, 0x50 };
    return sg_value_guard_register_chain_typed("libexample.so", off, 6,
                                               SG_LEAF_I32, "ExampleValue");
}
