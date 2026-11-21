#include "safe_read.h"
#include "syscall_utils.h"
#include <string.h>

/* 地址合法性粗判：过小或明显非法的高位指针直接判非法。
 * 对齐外挂 CheckADDRULL 的思路（低于 0x4000、或高位异常）。 */
int sg_safe_addr_valid(uintptr_t addr) {
    if (addr < 0x4000) return 0;                       /* 低于页，无意义 */
    /* ARM64 用户态地址高位应为 0x0000 前缀；0xFFFF 前缀是内核/非规范地址。
     * 保留 0x7F.. 边界判断，与常见外挂实现口径一致。 */
    if ((addr & 0xFFFF000000000000ULL) != 0) return 0;
    return 1;
}

int sg_safe_readable(const void *addr, size_t len) {
    if (!addr || len == 0) return 0;
    if (!sg_safe_addr_valid((uintptr_t)addr)) return 0;
    return sg_mem_readable(addr, len);
}

int sg_safe_memcpy(void *dest, const void *src, size_t n) {
    if (!dest || !src || n == 0) return 0;
    if (!sg_safe_readable(src, n)) return 0;
    memcpy(dest, src, n);
    return 1;
}

uintptr_t sg_safe_read_ptr(uintptr_t addr) {
    uintptr_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

int32_t sg_safe_read_i32(uintptr_t addr) {
    int32_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

uint32_t sg_safe_read_u32(uintptr_t addr) {
    uint32_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

int64_t sg_safe_read_i64(uintptr_t addr) {
    int64_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

uint64_t sg_safe_read_u64(uintptr_t addr) {
    uint64_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

float sg_safe_read_float(uintptr_t addr) {
    float v = 0.0f;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0.0f;
}

double sg_safe_read_double(uintptr_t addr) {
    double v = 0.0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0.0;
}

int16_t sg_safe_read_i16(uintptr_t addr) {
    int16_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

int8_t sg_safe_read_i8(uintptr_t addr) {
    int8_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

uint8_t sg_safe_read_u8(uintptr_t addr) {
    uint8_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? v : 0;
}

int sg_safe_read_bool(uintptr_t addr) {
    uint8_t v = 0;
    return sg_safe_memcpy(&v, (const void *)addr, sizeof(v)) ? (v != 0) : 0;
}
