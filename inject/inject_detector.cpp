#include "../core/maps.h"
#include "../core/syscall_utils.h"
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>

extern "C" {
int  sg_inject_anon_rx_scan(void);
int  sg_inject_anon_rx_scan_detailed(char *buf, size_t len);
int  sg_inject_anon_name_scan(char *buf, size_t len);
int  sg_inject_memfd_scan(char *buf, size_t len);
int  sg_inject_so_list(char *buf, size_t len);
}

/* 扫描匿名 r-x 段：Frida/LSPosed/Zygisk 注入后常驻留可执行匿名映射。
 * 白名单与大小阈值在 maps.cpp 里，避免把 JIT/scudo 误判成注入。 */
int sg_inject_anon_rx_scan(void) {
    return sg_inject_anon_rx_scan_detailed(0, 0);
}

/* 同 sg_inject_anon_rx_scan，但输出命中段的地址范围到 buf（供诊断，确认
 * 到底是哪个匿名 r-x 段命中，是真注入还是 ART/JIT 漏网）。 */
int sg_inject_anon_rx_scan_detailed(char *buf, size_t len) {
    if (buf && len) buf[0] = 0;
    SgMapEntry *maps = 0; int count = 0;
    if (!sg_read_maps(&maps, &count)) return -1;  // 读不到 → SKIPPED，不误报
    int found = 0;
    for (int i = 0; i < count; i++) {
        if (!sg_is_suspicious_anon_rx(&maps[i])) continue;
        found = 1;
        if (buf && len) {
            size_t used = sg_strlen(buf);
            if (used && used + 1 < len) { buf[used] = ','; buf[used + 1] = 0; used++; }
            char rng[64];
            snprintf(rng, sizeof(rng), "%llx-%llx",
                     (unsigned long long)maps[i].start,
                     (unsigned long long)maps[i].end);
            if (used < len) sg_strncpy(buf + used, rng, len - used);
        }
    }
    sg_free_maps(maps);
    return found;
}

/* ---- 命名匿名段检测（[anon:xxx] 可执行） ----
 * 补 inject.anon_rx 的盲区：anon_rx 只扫"无名字的纯匿名 r-x"，而攻击者为让
 * 注入代码在 maps 里"有个身份"，会用 prctl(PR_SET_VMA_ANON_NAME) 起名
 * （甚至起 "jit-cache" 之类伪装名）。这条专扫 [anon: 前缀的可执行段，
 * 名字输出到 buf 供诊断。返回 1=命中，0=正常，-1=读不到。 */
int sg_inject_anon_name_scan(char *buf, size_t len) {
    if (buf && len) buf[0] = 0;
    SgMapEntry *maps = 0; int count = 0;
    if (!sg_read_maps(&maps, &count)) return -1;
    int found = 0;
    for (int i = 0; i < count; i++) {
        const SgMapEntry *m = &maps[i];
        if (sg_is_suspicious_anon_named(m)) {
            found = 1;
            if (buf && len) {
                size_t used = sg_strlen(buf);
                if (used && used + 1 < len) { buf[used] = ','; buf[used + 1] = 0; used++; }
                if (used < len) sg_strncpy(buf + used, m->path, len - used);
            }
        }
    }
    sg_free_maps(maps);
    return found;
}

/* ---- memfd / unlink 隐身注入检测（不依赖具体 so 名） ----
 *
 * 针对 AndKittyInjector 这类"memfd dlopen + hide solist/maps"的隐身注入：
 *
 * 攻击手法（源码实证 AndKittyInjector/src/Injector/KittyInjector.cpp）：
 *   1) --memfd：memfd_create(名字) 造匿名文件 → android_dlopen_ext(library_fd=..)
 *      加载 → close(fd)。虽然 fd 关了，但 so 的段仍映射在进程里，maps 里
 *      会留下 "/memfd:<name> (deleted)" 的路径。name 可自定（--memfd-name），
 *      默认随机——所以**不能靠名字匹配，要靠 "memfd:" 这个前缀本身**。
 *   2) --hide：把 soinfo 从 linker solist/sonext 摘除（dl_iterate_phdr 看不到），
 *      再把每个 segment munmap 后用 mmap(MAP_FIXED|MAP_ANONYMOUS) 重映射——
 *      maps 里这些段从"带路径的 so 段"变成"匿名段"，但权限/大小不变。
 *
 * 所以两条"不靠 so 名"的可检测物证：
 *   A) path 含 "memfd:" 前缀 → 一定有进程用 memfd 加载过可执行/so 文件。
 *      正常 app 从不用 memfd 加载 native 库（那是进程注入/脱壳的专用手法）。
 *   B) path 含 "(deleted)" 且段可执行 → 文件被 unlink 后仍在执行。
 *      正常 so 不会"被删掉还在跑"，这是"加载即删、不留文件"的隐身特征。
 *
 * 注意：只判"可执行段 + 带路径"，避免把普通 (deleted) 数据文件误判。
 */
int sg_inject_memfd_scan(char *buf, size_t len) {
    if (buf && len) buf[0] = 0;
    SgMapEntry *maps = 0; int count = 0;
    if (!sg_read_maps(&maps, &count)) return -1;
    int found = 0;
    for (int i = 0; i < count; i++) {
        const SgMapEntry *m = &maps[i];
        if (!m->path[0] || m->path[0] == '[') continue;  // 无路径/虚拟段跳过

        /* 正常 app 的 memfd 用途（ART JIT code cache / profile / WebView）——
         * 这些是系统运行时/引擎的正常行为，命中即放行，不告警。
         * 用 "jit" 覆盖 jit-cache / jit-zygote-cache / dalvik-jit-code-cache 等
         * 所有 ART JIT 变体；"zygote" 单独兜底 zygote fork 的缓存。 */
        static const char *MEMFD_OK[] = {
            "jit", "zygote", "code-cache", "profile",
            "webview", "chromium", "translate", "houdini",
            0
        };
        int is_normal_memfd = 0;
        for (int k = 0; MEMFD_OK[k]; k++)
            if (sg_strstr(m->path, MEMFD_OK[k])) { is_normal_memfd = 1; break; }

        /* A) memfd: 前缀 —— 注入铁证。收窄：只认「可执行段」。
         *     注入的 so 段是 r-xp（要执行代码），而 ART JIT 数据/profile 是 rw-p。
         *     这样既能滤掉引擎正常的非执行 memfd，又不漏真注入。 */
        int is_memfd_x = sg_strstr(m->path, "memfd:") && m->perms[2] == 'x';
        /* B) (deleted) 且可执行 —— unlink 后仍在执行的隐身 so */
        int is_deleted_x = (m->perms[2] == 'x' && sg_strstr(m->path, "(deleted)"));

        if (!is_normal_memfd && (is_memfd_x || is_deleted_x)) {
            found = 1;
            if (buf && len) {
                size_t used = sg_strlen(buf);
                if (used && used + 1 < len) { buf[used] = ','; buf[used + 1] = 0; used++; }
                if (used < len) sg_strncpy(buf + used, m->path, len - used);
            }
            break;
        }
    }
    sg_free_maps(maps);
    return found;
}


/* 用 dl_iterate_phdr 枚举已加载 so，与"预期白名单"外的可疑库比对。
 * 比单纯读 maps 更抗伪造（走 linker 的结构）。
 * 返回逗号拼接的可疑 so 名（经 JNI 传回 Java），空串表示正常。 */
/* 判断一个 so 路径是否"合法"：
 *   - 系统路径：/system/、/vendor/、/apex/、/product/、/system_ext/
 *   - 本 app 路径：/data/app/（含 oat/dex，但 so 通常在 native lib 子目录）
 *   - 其余路径（如 /data/local/tmp/、/sdcard/、/data/user/0/<other>/）可疑。
 * 注入器（AndKittyInjector 等）常把 so 落到 /data/local/tmp 或应用私有目录外，
 * 路径本身即是物证，不依赖"名字里有没有 frida"。 */
static int is_legit_so_path(const char *p) {
    static const char *LEGIT_PREFIX[] = {
        "/system/", "/vendor/", "/apex/", "/product/", "/system_ext/",
        "/data/app/",          /* 本 app 与已安装 app 的 native lib */
        "/data/dalvik-cache/", /* 系统/厂商 dex 编译缓存（MIUI 等常态，非注入物证） */
        0
    };
    for (int i = 0; LEGIT_PREFIX[i]; i++)
        if (sg_strstr(p, LEGIT_PREFIX[i])) return 1;
    return 0;
}

static int collect_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    char *out = (char *)data;
    const char *p = info->dlpi_name;
    if (!p || !*p) return 0;                       // 主程序
    if (p[0] == '[') return 0;                     // [vdso]/[vvar]/[anon:...] 等内核/匿名虚拟段，正常
    static const char *SUSPECT[] = {
        "frida", "gum-js", "linjector",
        "lspd", "xposed", "edxposed",       /* Xposed 系 */
        "yahfa", "sandhook", "pine",        /* 夜安/SandHook/Pine 等 ART hook */
        "epic", "whale", "dexposed",        /* Epic/Whale/Dexposed */
        "zygisk", "riru", "substrate", "lsplant",
        0
    };
    int suspicious = 0;
    for (int i = 0; SUSPECT[i]; i++) {
        if (sg_strstr(p, SUSPECT[i])) { suspicious = 1; break; }
    }
    /* 路径启发式：不在系统/本 app 路径下的 so，即使改了名也可疑 */
    if (!suspicious && !is_legit_so_path(p)) suspicious = 1;

    if (suspicious) {
        size_t used = sg_strlen(out);
        if (used && used < 1023) { out[used] = ','; out[used + 1] = 0; used++; }
        sg_strncpy(out + used, p, 1024 - used);
    }
    return 0;
}

int sg_inject_so_list(char *buf, size_t len) {
    if (!buf || len == 0) return 0;
    buf[0] = 0;
    dl_iterate_phdr(collect_cb, buf);
    return (int)sg_strlen(buf);
}
