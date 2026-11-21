#ifndef SENTINEL_WHITELIST_H
#define SENTINEL_WHITELIST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 全局白名单 —— 让"接入方"自己声明哪些是本 App 的常态特征。
 *
 * 背景：shadow.text_x / shadow.sighand / shadow.seccomp 这三条，在"裸"
 * 判定下几乎每个真实 App 都会亮（UE/JIT 改段权限、ART 装 SIGSEGV、内嵌
 * WebView 装 seccomp）。一刀切 DISABLED 会丢检测力；全局告警则全是误报。
 * 正确做法是"白名单驱动"：默认内置一组常见框架特征 + 允许接入方运行时
 * 追加自己 App 特有的白名单条目。命中白名单 → 放行(OK)，否则 → 告警。
 *
 * 三类白名单：
 *   1. 路径前缀白名单  —— shadow.text_x 用：这些 so/路径的 mprotect 是正常
 *      （引擎、JIT、热更新、native 自研库）。
 *   2. 信号号白名单    —— shadow.sighand 用：这些信号号被捕获是 App 自装
 *      handler（崩溃收集、FP 模拟等），非 SIGHOOK。
 *   3. seccomp 白名单   —— shadow.seccomp 用：App 声明"我装了 seccomp-bpf"
 *      （内嵌 Chromium/WebView、自定义 sandbox），Seccomp=2 属常态。
 *
 * 线程安全：巡检线程在启动后才读白名单；接入方应在 JNI_OnLoad 内、巡检
 * 线程起来前完成注册。注册函数做了简单上锁，注册与查询并发也安全。
 * ========================================================================== */

/* 单类白名单容量上限（超出静默忽略，够用即可） */
#define SG_WL_MAX 64

/* ---- 注册接口（返回 0=成功，-1=参数非法/已满） ---- */

/* 追加一条路径白名单（子串匹配，命中即放行）。适合文件名/子串特征，
 * 如 "libUE4.so"、"code_cache"、"jit"。 */
int sg_wl_add_path(const char *substr);

/* 追加一条路径前缀白名单（前缀匹配，命中即放行）。适合"系统只读分区"
 * 这类必须以路径开头为准的段，如 "/system/"、"/apex/"、"[/vdso]"。前缀
 * 匹配比子串匹配更严，避免 App 私有 so 路径中恰好含前缀字样被误放行。 */
int sg_wl_add_path_prefix(const char *prefix);

/* 追加一个信号号白名单（按信号号，如 11=SIGSEGV）。 */
int sg_wl_add_signal(int signo);

/* 打开/关闭 seccomp 白名单（1=App 声明 seccomp 属常态）。 */
void sg_wl_set_seccomp(int enabled);

/* ---- 查询接口（检测模块调用，命中返回 1） ---- */

/* path 是否命中路径子串白名单。 */
int sg_wl_match_path(const char *path);

/* path 是否命中路径前缀白名单（前缀匹配）。 */
int sg_wl_match_path_prefix(const char *path);

/* signo 是否命中信号号白名单。 */
int sg_wl_match_signal(int signo);

/* seccomp 白名单是否打开。 */
int sg_wl_seccomp_enabled(void);

#ifdef __cplusplus
}
#endif
#endif
