/* ============================================================================
 * AntiCheat JNI 入口 —— demo 只需 System.loadLibrary("anticheat") 一行。
 *
 * 设计：anticheat.so 是纯 C/C++ 检测库，通过 JNI_OnLoad 自动启动，
 * 不要求宿主声明任何 native 方法。启动后：
 *   1) 启动 self-trace 守护（封 ptrace 通道 + 清硬断 + 哨兵硬断）
 *   2) 装 SIGTRAP handler（异常处理链兜底）
 *   3) 起一个后台 pthread 周期巡检（默认 5s），结果写 logcat(tag "AntiCheat")
 *   4) 可选：把聚合结果通过 JNI 回调宿主（若宿主注册了回调）
 *
 * 关键：fork 守护在 zygote 派生进程里的坑——子进程只许纯 syscall，
 * 禁止 malloc/ART/JNI。所以所有"需要 libc/ART"的检测都放在父进程侧，
 * 由后台巡检线程执行；守护子进程只做 ptrace 代理 + 体检。
 * ========================================================================== */

#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "../core/whitelist.h"

#define TAG "AntiCheat"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

/* ---- 各检测模块导出（全部三态：0=OK / 1=SUSPICIOUS / -1=SKIPPED） ---- */
extern "C" {
/* memory */
void sg_memory_init(void);
int  sg_memory_canary_check(void);
int  sg_memory_guard_probe(void);
int  sg_value_guard_tampered(void);
int  sg_value_guard_tampered_names(char *buf, size_t len);
int  sg_value_guard_start(void);
int  sg_value_guard_register_builtin_clientcap(void);
/* inject */
int  sg_inject_anon_rx_scan(void);
int  sg_inject_anon_rx_scan_detailed(char *buf, size_t len);
int  sg_inject_anon_name_scan(char *buf, size_t len);
int  sg_inject_memfd_scan(char *buf, size_t len);
int  sg_inject_so_list(char *buf, size_t len);
/* hook (native) */
int  sg_hook_inline_scan(void);
int  sg_hook_got_scan(void);
int  sg_hook_ue_processevent_scan(char *buf, size_t len);
/* hook (java/art) —— 需要 JNIEnv，由巡检线程自行 Attach 后调用 */
int  sg_hook_art_entry_scan(JNIEnv *env, jclass clazz);
/* debug */
int  sg_dbg_tracerpid_pid(void);
int  sg_dbg_ptrace_self(void);
int  sg_dbg_sigtrap_trap(void);
/* guard */
int  sg_guard_start(void);
int  sg_guard_hwbp_status(void);
int  sg_guard_hold_status(void);
int  sg_guard_hold_errno(void);
int32_t sg_guard_pid(void);
uint32_t sg_guard_sigtrap_count(void);
int  sg_guard_scan_sysfs(void);
int  sg_guard_scan_devices(void);
int  sg_guard_set_nondumpable(void);
int  sg_guard_apply_read_channel_lock(void);
int  sg_guard_read_channel_locked(void);
int  sg_guard_sentinel_tampered(void);
int  sg_guard_install_sigtrap(void);
int  sg_guard_trap_count(void);
/* 反影子页/异常 hook */
int  sg_guard_text_exec_check(char *buf, size_t len);
int  sg_guard_shadow_pool_check(void);
int  sg_guard_signal_handler_check(char *buf, size_t len);
int  sg_guard_seccomp_check(void);
}

/* ---- 巡检线程状态 ---- */
static volatile int g_scan_running;
static pthread_t g_scan_thread;

/* 三态转可读字符串 */
static const char *st_name(int c) {
    return c == 1 ? "SUSPICIOUS" : (c == -1 ? "SKIPPED" : "OK");
}

/* ---- 处置档位 ----
 * 三档：封号 / 禁赛并警告 / 人工观察账号行为。
 * 命中检测项时按严重度输出固定格式：
 *   [EZ_AntiDebug] 检测到使用 <攻击手法>，建议采取措施为 <档位>
 * OK / SKIPPED 一律静默，不刷屏（开源库的干净日志观感）。 */
typedef enum {
    SEV_BAN      = 0,  /* 封号 */
    SEV_WARN     = 1,  /* 禁赛并警告 */
    SEV_REVIEW   = 2,  /* 人工观察账号行为 */
} sev_level_t;

static const char *sev_text(sev_level_t s) {
    switch (s) {
        case SEV_BAN:    return "封号";
        case SEV_WARN:   return "禁赛并警告";
        case SEV_REVIEW: return "人工观察账号行为";
    }
    return "人工观察账号行为";
}

/* 命中输出：只在检测项真阳性时调用 */
static void report_hit(const char *what, sev_level_t sev) {
    LOGI("检测到使用 %s，建议采取措施为 %s", what, sev_text(sev));
}

/* 一轮完整扫描：只打印命中的检测项（OK/SKIPPED 静默）。
 * 命中格式：检测到使用 <手法>，建议采取措施为 <档位> */
static void run_one_scan(JNIEnv *env) {
    /* ---- 内存完整性 ---- */
    if (sg_memory_canary_check() == 1)
        report_hit("内存完整性破坏（canary 被篡改）", SEV_BAN);
    if (sg_memory_guard_probe() == 1)
        report_hit("越权内存访问（guard page 命中）", SEV_REVIEW);

    char vg[256] = {0};
    int vg_n = sg_value_guard_tampered_names(vg, sizeof(vg) - 1);
    if (vg_n > 0)
        report_hit("关键游戏数据被篡改（value_guard）", SEV_WARN);

    /* ---- 注入 ---- */
    char ar[256] = {0};
    int ar_n = sg_inject_anon_rx_scan_detailed(ar, sizeof(ar) - 1);
    if (ar_n > 0)
        report_hit("匿名可执行段注入（anon_rx）", SEV_REVIEW);

    char an[256] = {0};
    int an_n = sg_inject_anon_name_scan(an, sizeof(an) - 1);
    if (an_n > 0)
        report_hit("命名匿名段注入（anon_name）", SEV_BAN);

    char mf[256] = {0};
    int mf_n = sg_inject_memfd_scan(mf, sizeof(mf) - 1);
    if (mf_n > 0)
        report_hit("memfd 隐身注入（memfd）", SEV_BAN);

    char so[512] = {0};
    int so_n = sg_inject_so_list(so, sizeof(so) - 1);
    if (so_n > 0)
        report_hit("非法 so 注入（so_list）", SEV_BAN);

    /* ---- native hook ---- */
    if (sg_hook_inline_scan() == 1)
        report_hit("函数 inline hook", SEV_BAN);
    if (sg_hook_got_scan() == 1)
        report_hit("GOT 表劫持", SEV_WARN);

    char pe[256] = {0};
    int pe_n = sg_hook_ue_processevent_scan(pe, sizeof(pe) - 1);
    if (pe_n > 0)
        report_hit("UE processEvent 被 hook", SEV_BAN);

    /* ---- Java 层 ART hook ---- */
    if (env && sg_hook_art_entry_scan(env, 0) == 1)
        report_hit("Java 层 ART 方法 hook", SEV_BAN);

    /* ---- 调试/断点 ---- */
    int tracer = sg_dbg_tracerpid_pid();
    int guard_pid = (int)sg_guard_pid();
    if (tracer > 0 && !(guard_pid > 0 && tracer == guard_pid))
        report_hit("外部调试器附加（tracerpid）", SEV_BAN);

    int guarded = sg_guard_hold_status() == 1;
    int ch_locked = sg_guard_read_channel_locked();
    if (!guarded && !ch_locked && sg_dbg_ptrace_self() == 1)
        report_hit("ptrace 附加（TRACEME 被占）", SEV_BAN);
    if (!guarded && sg_dbg_sigtrap_trap() == 1)
        report_hit("SIGTRAP 信号劫持", SEV_REVIEW);

    /* ---- guard 自身状态 ---- */
    if (sg_guard_hwbp_status() == 1)
        report_hit("硬件断点被拦截/清除", SEV_BAN);

    /* ---- 通道封堵 + 驱动扫描 + 哨兵硬断 ---- */
    if (sg_guard_scan_sysfs() == 1)
        report_hit("恶意驱动文件（sysfs）", SEV_BAN);
    if (sg_guard_scan_devices() == 1)
        report_hit("恶意设备节点（devices）", SEV_BAN);
    if (sg_guard_sentinel_tampered() > 0)
        report_hit("哨兵断点被外部篡改", SEV_BAN);

    /* ---- 反影子页/异常 hook（白名单驱动，未命中白名单才报） ---- */
    char tx[256] = {0};
    int tx_n = sg_guard_text_exec_check(tx, sizeof(tx) - 1);
    if (tx_n > 0)
        report_hit("代码段权限被异常篡改（text_x）", SEV_BAN);

    char sh[128] = {0};
    int sh_n = sg_guard_signal_handler_check(sh, sizeof(sh) - 1);
    if (sh_n > 0)
        report_hit("信号 handler 被劫持（sighand）", SEV_WARN);

    if (sg_guard_seccomp_check() == 1)
        report_hit("seccomp 过滤规则（seccomp）", SEV_REVIEW);

    if (sg_guard_shadow_pool_check() == 1)
        report_hit("影子页内存池（shadow pool）", SEV_BAN);
}

/* 巡检线程：先 Attach 到 JVM（要调 ART hook 需要 JNIEnv），周期扫描 */
static void *scan_loop(void *arg) {
    JavaVM *vm = (JavaVM *)arg;
    JNIEnv *env = 0;
    int attached = 0;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (vm->AttachCurrentThread(&env, 0) == JNI_OK) attached = 1;
    }

    while (g_scan_running) {
        run_one_scan(env);
        /* 5s 周期，用 nanosleep 可被中断 */
        struct timespec ts = { 5, 0 };
        nanosleep(&ts, 0);
    }

    if (attached) vm->DetachCurrentThread();
    return 0;
}

/* ---- JNI_OnLoad：库加载即自动启动 ---- */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;

    LOGI("anticheat.so loaded, auto-starting guard...");

    /* 1) 内存模块初始化（canary 采样） */
    sg_memory_init();

    /* 2) 内置默认白名单（纯 so 层，无需 Java 侧调用）。
     *
     *    shadow.text_x 抓的是"文件映射代码段权限被翻转"这个裸特征，真实
     *    App 上会命中三类段。检测流水线按"平台 → 用户 → 注入主战场"逐层
     *    放行、逐层收窄，只有落到最后一层仍命中的才是真正可疑：
     *
     *      第一层「系统/内核只读段」(前缀匹配，通用)：
     *          /system/ /vendor/ /apex/ /system_ext/ /data/dalvik-cache/
     *          [vdso] [vectors] —— 平台自带、非 App 可控，SIGHOOK 不以
     *          系统段为靶(它打的是目标 so 的 .text)。放行理由与具体游戏
     *          无关，任何进程通用。
     *
     *      第二层「App 自身常态段」(子串匹配，接入方可追加)：
     *          引擎 libUE4/libil2cpp/...、ART JIT(code_cache/.vdex)——
     *          这是"本 App 常态"，需按引擎登记。接入方可用 addPathWhitelist
     *          追加自己 App 特有的热更新/自研库。
     *
     *      第三层「不放行 = 主战场」：
     *          除上述之外的任意 .so 段权限翻转 → 告警。尤其是 /data/app/
     *          下用户自定义库、以及 memfd 注入(后面 inject.memfd 专查
     *          memfd:jit 改名 / memhide 隐藏)，这些正是注入/hook 落点，
     *          绝不进白名单。
     *
     *    信号白名单同理：SIGSEGV/SIGTRAP 是 ART 运行时常态(崩溃收集器、
     *    调试态 handler)，放行；SIGSYS(31) 保留——SIGHOOK 的 seccomp 锁
     *    信号若捕获 SIGSYS 仍能亮。
     */

    /* ---- 第一层：系统/内核只读分区（前缀匹配，通用） ---- */
    sg_wl_add_path_prefix("/system/");
    sg_wl_add_path_prefix("/vendor/");
    sg_wl_add_path_prefix("/apex/");
    sg_wl_add_path_prefix("/system_ext/");
    sg_wl_add_path_prefix("/data/dalvik-cache/");
    sg_wl_add_path_prefix("[vdso]");
    sg_wl_add_path_prefix("[vectors]");

    /* ---- 第二层：App 自身常态段（子串匹配，接入方可追加） ---- */
    sg_wl_add_path("libUE4.so");
    sg_wl_add_path("libUnreal.so");
    sg_wl_add_path("libil2cpp.so");
    sg_wl_add_path("libunity.so");
    sg_wl_add_path("libmain.so");
    sg_wl_add_path("libc++_shared.so");   /* NDK C++ 运行时库，GOT/PLT 被 linker 正常改 */
    sg_wl_add_path("libplaycore.so");     /* Google Play Core（Play 服务集成） */
    sg_wl_add_path("libtry-alloc-lib.so");/* 游戏自带自定义分配器 */
    sg_wl_add_path("libanticheat.so");    /* 检测库自身：GOT/PLT 被 linker 正常改，勿自报 */
    sg_wl_add_path("libexample.so");      /* 示例：接入方自己的 so */
    sg_wl_add_path("code_cache");
    sg_wl_add_path(".vdex");          /* ART 校验 dex 段 mprotect 属常态 */
    sg_wl_add_path("/memfd:jit");     /* ART JIT 缓存(memfd) 属常态 */
    sg_wl_add_path("/memfd:dalvik");  /* dalvik JIT 缓存 */

    /* ---- 信号白名单：ART 运行时常态，SIGSYS 保留 ---- */
    sg_wl_add_signal(11);   /* SIGSEGV：ART/崩溃收集器常态 */
    sg_wl_add_signal(5);    /* SIGTRAP：ART 调试运行时态 handler 常态 */

    sg_wl_set_seccomp(1);   /* 内嵌 WebView/Chromium 的 seccomp 属常态 */
    LOGI("built-in whitelist registered (system/engine/JIT/SIGSEGV/SIGTRAP)");

    /* 3) 启动 self-trace 守护（封 ptrace + 清硬断 + 哨兵硬断） */
    int g = sg_guard_start();
    LOGI("self-trace guard start: %s", g == 0 ? "OK" : "FAILED");

    /* 3.5) 封外部读通道：占位失败(SELinux Enforcing)时自动开 dumpable=0，
     *      挡 /proc/pid/mem + process_vm_readv（非 root），与占位互斥故仅降级时启用 */
    int locked = sg_guard_apply_read_channel_lock();
    LOGI("read-channel lock (dumpable=0): %s", locked == 0 ? "applied" : "skipped/held");

    /* 4) 装 SIGTRAP handler 兜底（root 绕过占位时仍能计数） */
    sg_guard_install_sigtrap();

    /* 4.5) 注册内置防写守护点（无需接入方传回调，anti 自己沿引擎 so 偏移链
     *      读关键值），然后启动关键值守护线程。偏移链在 value_guard.cpp 里是
     *      占位示例，接入方按自己逆向结果替换。若引擎此刻未加载，注册会失败
     *      (SKIPPED)。 */
    int vg_reg = sg_value_guard_register_builtin_clientcap();
    LOGI("value-guard builtin: %s", vg_reg == 0 ? "registered" : "SKIPPED(engine not loaded)");
    int vg = sg_value_guard_start();
    LOGI("value-guard thread start: %s", vg == 0 ? "OK" : "FAILED");

    /* 5) 起周期巡检后台线程 */
    g_scan_running = 1;
    if (pthread_create(&g_scan_thread, 0, scan_loop, vm) != 0) {
        LOGW("failed to start scan thread");
        g_scan_running = 0;
    }

    return JNI_VERSION_1_6;
}

/* ---- JNI_OnUnload：卸载时停巡检 ---- */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    g_scan_running = 0;
    pthread_join(g_scan_thread, 0);
    LOGI("anticheat.so unloaded");
}

/* ============================================================================
 * 白名单注册 JNI —— 宿主（demo 的 Java 层）可主动声明自己 App 的常态特征，
 * 让 shadow.text_x / sighand / seccomp 三信号从"误报"变"放行"。
 *
 * 对应 Java 声明（com.tencent.myapplication.AntiCheat）：
 *   public static native void addPathWhitelist(String substr);
 *   public static native void addPathPrefixWhitelist(String prefix);
 *   public static native void addSignalWhitelist(int signo);
 *   public static native void setSeccompWhitelist(boolean enabled);
 * ========================================================================== */

static const char *WL_CLASS = "com/tencent/myapplication/AntiCheat";

JNIEXPORT void JNICALL
Java_com_tencent_myapplication_AntiCheat_addPathWhitelist(
        JNIEnv *env, jclass clazz, jstring substr) {
    (void)clazz;
    if (!substr) return;
    const char *s = env->GetStringUTFChars(substr, 0);
    if (s) {
        sg_wl_add_path(s);
        LOGI("wl: add path '%s'", s);
        env->ReleaseStringUTFChars(substr, s);
    }
}

JNIEXPORT void JNICALL
Java_com_tencent_myapplication_AntiCheat_addPathPrefixWhitelist(
        JNIEnv *env, jclass clazz, jstring prefix) {
    (void)clazz;
    if (!prefix) return;
    const char *s = env->GetStringUTFChars(prefix, 0);
    if (s) {
        sg_wl_add_path_prefix(s);
        LOGI("wl: add path prefix '%s'", s);
        env->ReleaseStringUTFChars(prefix, s);
    }
}

JNIEXPORT void JNICALL
Java_com_tencent_myapplication_AntiCheat_addSignalWhitelist(
        JNIEnv *env, jclass clazz, jint signo) {
    (void)env; (void)clazz;
    sg_wl_add_signal((int)signo);
    LOGI("wl: add signal %d", (int)signo);
}

JNIEXPORT void JNICALL
Java_com_tencent_myapplication_AntiCheat_setSeccompWhitelist(
        JNIEnv *env, jclass clazz, jboolean enabled) {
    (void)env; (void)clazz;
    sg_wl_set_seccomp(enabled ? 1 : 0);
    LOGI("wl: set seccomp whitelist %d", enabled ? 1 : 0);
}
