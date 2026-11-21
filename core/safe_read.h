#ifndef SENTINEL_SAFE_READ_H
#define SENTINEL_SAFE_READ_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 安全读内存原语（anti 侧遍历目标进程/自身内存的基础设施）
 *
 * 背景：外挂用 Check()/Ram<T>()/getDword() 这套"读前探可读性"的原语去读游戏
 * 内存。anti 侧做 value_guard、指针链守护、或任何内存侧检测时，同样需要"绝不
 * 把自己读崩"的安全读原语——否则沿一条失效指针链解引用会 SIGSEGV 打崩检测库
 * 自身。
 *
 * 语义对齐外挂写法，但底层统一走 sg_mem_readable（write 到管道做 copy_from_user
 * 探测），而不是 process_vm_readv 读自己（读自己 pid 在部分内核/SELinux 下会被
 * 拒，且 XOM 段读字节会 SIGSEGV，write 探测两者都规避）。
 *
 * 所有 Read* 返回 0 表示"地址不可读/非法"，调用方据此判断指针链是否失效。
 * ============================================================================ */

/* 地址合法性粗判：过小的地址(低于页)、或明显非法的高位指针，直接判非法。
 * 对齐外挂 CheckADDRULL 的思路，避免对无意义地址做探测。 */
int sg_safe_addr_valid(uintptr_t addr);

/* 探测 [addr, addr+len) 是否可读。可读返回 1，否则 0。 */
int sg_safe_readable(const void *addr, size_t len);

/* 安全拷贝：src 可读则拷贝 n 字节到 dest 并返回 1，否则返回 0 且不动 dest。
 * 对应外挂 Mymemcpy()。 */
int sg_safe_memcpy(void *dest, const void *src, size_t n);

/* 逐类型安全读，返回 0 表示不可读/非法地址（对齐 getDword/getFloat/... 语义）。 */
uintptr_t sg_safe_read_ptr(uintptr_t addr);   /* 读一个指针（对齐 GetPointer） */
int32_t   sg_safe_read_i32(uintptr_t addr);   /* getDword */
uint32_t  sg_safe_read_u32(uintptr_t addr);
int64_t   sg_safe_read_i64(uintptr_t addr);
uint64_t  sg_safe_read_u64(uintptr_t addr);
float     sg_safe_read_float(uintptr_t addr); /* getFloat */
double    sg_safe_read_double(uintptr_t addr);/* getDouble */
int16_t   sg_safe_read_i16(uintptr_t addr);   /* getWord */
int8_t    sg_safe_read_i8(uintptr_t addr);    /* getByte */
uint8_t   sg_safe_read_u8(uintptr_t addr);

/* 读一个 bool（对齐 GetBool），返回 0/1，非法地址返回 0。 */
int sg_safe_read_bool(uintptr_t addr);

#ifdef __cplusplus
}
#endif
#endif
