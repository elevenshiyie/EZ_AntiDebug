#include "maps.h"
#include "syscall_utils.h"
#include "whitelist.h"
#include <stdlib.h>
#include <string.h>

#define MAPS_BUF (1024 * 1024)  // 现代 App maps 常 > 256KB，一次性开 1MB

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char **pp, uint64_t *out) {
    uint64_t v = 0; int got = 0, h;
    while ((h = hexval(**pp)) >= 0) { v = (v << 4) | (unsigned)h; (*pp)++; got++; }
    *out = v; return got;
}

static int parse_line(const char *line, SgMapEntry *e) {
    const char *p = line;
    memset(e, 0, sizeof(*e));
    if (!parse_hex(&p, &e->start) || *p != '-') return 0;
    p++;
    if (!parse_hex(&p, &e->end)) return 0;
    while (*p == ' ') p++;
    for (int i = 0; i < 4 && *p && *p != ' '; i++, p++) e->perms[i] = *p;
    while (*p == ' ') p++;
    // 跳过 offset dev inode，取 pathname
    for (int field = 0; field < 3; field++) {
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
    }
    sg_strncpy(e->path, p, sizeof(e->path));
    return 1;
}

int sg_read_maps(SgMapEntry **out, int *out_count) {
    int used = 0;
    int fd = sg_open_fallback("/proc/self/maps", 0 /*O_RDONLY*/, 0, &used);
    if (fd < 0) return 0;
    char *buf = (char *)malloc(MAPS_BUF);
    if (!buf) { sg_close(fd); return 0; }
    size_t n = 0;
    while (n < MAPS_BUF - 1) {
        ssize_t r = sg_read_fallback(fd, buf + n, MAPS_BUF - 1 - n, used);
        if (r <= 0) break;
        n += (size_t)r;
    }
    sg_close(fd);
    buf[n] = 0;

    SgMapEntry *arr = (SgMapEntry *)malloc(sizeof(SgMapEntry) * 4096);
    if (!arr) { free(buf); return 0; }
    int count = 0;
    char *p = buf;
    while (*p && count < 4096) {
        char *eol = strchr(p, '\n');
        if (!eol) break;
        *eol = 0;
        if (parse_line(p, &arr[count])) count++;
        p = eol + 1;
    }
    free(buf);
    *out = arr; *out_count = count;
    return count;
}

void sg_free_maps(SgMapEntry *arr) { free(arr); }

int sg_is_suspicious_anon_rx(const SgMapEntry *e) {
    if (e->perms[2] != 'x') return 0;           // 必须可执行
    if (e->path[0] && e->path[0] != '[') return 0; // 有文件路径 → 正常 so

    static const char *WHITELIST[] = {
        "[vdso]", "[vvar]", "[stack", "[heap]",
        "dalvik-jit", "dalvik-main", "dalvik-",
        "scudo", "linker_alloc", "libc_malloc",
        "jit-cache", "code-cache", "/memfd:",
        "[anon:.bss]", "[anon:bionic TLS]", "[anon:stack_and_tls:",
        0
    };
    for (int i = 0; WHITELIST[i]; i++)
        if (sg_strstr(e->path, WHITELIST[i])) return 0;

    uint64_t size = e->end - e->start;
    // 白名单之外：>=128KB 直接可疑；小段需进一步看内容（这里从简，demo 只看大小）
    return size >= 128 * 1024 ? 1 : 0;
}

/* ---- 命名匿名段检测（[anon:xxx] 可执行） ----
 * 针对"纯匿名段"难定性、攻击者反而主动给匿名内存起名/挂 memfd 的手法。
 *
 * 关键认知（区别于 inject.anon_rx）：
 *   - inject.anon_rx 扫"无名字的纯匿名 r-x 段"，只能靠大小猜，误报率高；
 *   - 本函数扫"起了名字的匿名段 [anon:xxx]"。攻击者为让注入代码在 maps 里
 *     "有个身份"，会用 prctl(PR_SET_VMA_ANON_NAME) 起名（甚至起 "jit-cache"
 *     之类伪装名），或用 memfd 挂名。这些"命名"动作反而留下可识别指纹。
 *
 * 判定：只认「可执行段 + 名字不在白名单」。名字可能伪装，所以不靠名字定性，
 * 而是靠"可执行 + 大小超阈值"这条硬特征；白名单只放行 ART/JIT/scudo 等
 * 运行时自带的正常命名段。 */
int sg_is_suspicious_anon_named(const SgMapEntry *e) {
    if (e->perms[2] != 'x') return 0;                    // 必须可执行
    if (sg_strstr(e->path, "[anon:") != e->path) return 0; // 只认 [anon: 前缀开头

    /* 正常运行时自带的命名匿名段（ART JIT / 线程栈 / 分配器） */
    static const char *NORMAL[] = {
        "jit", "dalvik", "code-cache", "profile",
        "scudo", "linker_alloc", "libc_malloc",
        "bionic", "stack", "tls", ".bss", ".data", ".rodata",
        0
    };
    for (int i = 0; NORMAL[i]; i++)
        if (sg_strstr(e->path, NORMAL[i])) return 0;

    uint64_t size = e->end - e->start;
    /* 白名单外 + 可执行 + >=128KB → 可疑。小段(几十字节 shellcode 也可能被
     * 起名)这里从简按大小阈值，与 inject.anon_rx 保持一致口径。 */
    return size >= 128 * 1024 ? 1 : 0;
}

int sg_addr_in_exec_range(uint64_t addr, SgMapEntry *maps, int count) {
    for (int i = 0; i < count; i++)
        if (maps[i].perms[2] == 'x' && addr >= maps[i].start && addr < maps[i].end)
            return 1;
    return 0;
}

uint64_t sg_module_base(const char *name, uint64_t *out_start, uint64_t *out_end) {
    if (!name || !*name) return 0;
    SgMapEntry *maps = 0; int count = 0;
    if (!sg_read_maps(&maps, &count)) return 0;

    uint64_t base = 0, lo = 0, hi = 0;
    for (int i = 0; i < count; i++) {
        if (!sg_strstr(maps[i].path, name)) continue;
        uint64_t s = maps[i].start, e = maps[i].end;
        if (base == 0) { base = s; lo = s; hi = e; }
        else { if (s < lo) lo = s; if (e > hi) hi = e; }
    }
    sg_free_maps(maps);
    if (out_start) *out_start = lo;
    if (out_end)   *out_end   = hi;
    return base;
}

int sg_addr_owner_path(uint64_t addr, char *out_path, size_t out_len) {
    if (!out_path || out_len == 0) return 0;
    out_path[0] = 0;
    SgMapEntry *maps = 0; int count = 0;
    if (!sg_read_maps(&maps, &count)) return 0;
    int found = 0;
    for (int i = 0; i < count; i++) {
        if (addr >= maps[i].start && addr < maps[i].end) {
            if (maps[i].path[0]) {
                sg_strncpy(out_path, maps[i].path, out_len);
                found = 1;
            }
            break;
        }
    }
    sg_free_maps(maps);
    return found;
}

int sg_self_module_bounds(uint64_t *out_start, uint64_t *out_end) {
    SgMapEntry *maps = 0; int count = 0;
    if (!sg_read_maps(&maps, &count)) return 0;
    // 取包含本函数地址的那一段作为"自身模块"近似（demo 足够；实战应取整个 so 的 min/max）
    uint64_t self = (uint64_t)(uintptr_t)&sg_self_module_bounds;
    for (int i = 0; i < count; i++) {
        if (self >= maps[i].start && self < maps[i].end) {
            // 向上/下扩展到同名 so 的所有段
            uint64_t lo = maps[i].start, hi = maps[i].end;
            const char *name = maps[i].path;
            if (name[0]) {
                for (int j = 0; j < count; j++) {
                    if (sg_strncmp(maps[j].path, name, sizeof(maps[j].path)) == 0) {
                        if (maps[j].start < lo) lo = maps[j].start;
                        if (maps[j].end > hi) hi = maps[j].end;
                    }
                }
            }
            *out_start = lo; *out_end = hi;
            sg_free_maps(maps);
            return 1;
        }
    }
    sg_free_maps(maps);
    return 0;
}
