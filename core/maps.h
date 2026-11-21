#ifndef SENTINEL_MAPS_H
#define SENTINEL_MAPS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t start, end;
    char perms[5];       // r-xp / rw-p ...
    char path[512];
} SgMapEntry;

/* syscall 直读 /proc/self/maps，解析成数组。返回条数，<=0 表示读不到(SKIPPED)。 */
int sg_read_maps(SgMapEntry **out, int *out_count);
void sg_free_maps(SgMapEntry *arr);

/* 判定一段是否为"可疑匿名可执行映射"：有 x 权限、无路径、不在白名单内。 */
int sg_is_suspicious_anon_rx(const SgMapEntry *e);

/* 判定一段是否为"可疑命名匿名段"([anon:xxx] 且可执行)。
 * prctl(PR_SET_VMA_ANON_NAME) 起的匿名名会以 "[anon:名字]" 出现在 maps path。
 * 攻击者常给 shellcode/注入代码匿名段起伪装名，故不靠名字、靠"可执行 + 大块
 * + 非白名单名"判定。名字本身(含 /memfd:/ 前缀与常见正常名)在此过滤。 */
int sg_is_suspicious_anon_named(const SgMapEntry *e);

/* addr 是否落在任一可执行段内（LR / ArtMethod entry 校验用）。 */
int sg_addr_in_exec_range(uint64_t addr, SgMapEntry *maps, int count);

/* 取自身模块的首尾地址（LR 越界判断用）。 */
int sg_self_module_bounds(uint64_t *out_start, uint64_t *out_end);

/* 按 so 名（子串匹配，如 "libUE4.so"）从 /proc/self/maps 取该模块基址。
 * 对齐外挂 GetGameModule 语义：找到第一个含该名字的映射段，返回其 start。
 * 找到返回基址(>0)，否则返回 0。可选输出该模块首/尾地址到 out_start/out_end。 */
uint64_t sg_module_base(const char *name, uint64_t *out_start, uint64_t *out_end);

/* 返回 addr 所属映射段的 path（若落在文件映射段），否则返回 0。
 * 用于"hook 跳转目标归属哪个 so"的白名单判定：目标落在合法库(如 wind.so)
 * 则放行，落在匿名/未知段才判可疑。out_path 需调用方提供 >=256 字节缓冲。 */
int sg_addr_owner_path(uint64_t addr, char *out_path, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif
