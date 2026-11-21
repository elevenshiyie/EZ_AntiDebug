#ifndef SENTINEL_VALUE_GUARD_H
#define SENTINEL_VALUE_GUARD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 关键值守护（防写入）：监测游戏内存里的关键数值是否被外挂改写。
 *
 * 背景：外挂开线程裸读指针链拿到关键数据（如世界对象下的角色属性），这属于
 * "读"，检测库感知不到。但外挂更常做的是"写"——改血量/上限等关键数值。
 * 这个"写"是可以检测的：anti 自己开一个后台线程，周期沿指针链读当前值，
 * 与基线比对，变了就是被改（外挂篡改数值）。
 *
 * 用法（接入方侧）：
 *   1) 写一个"读当前值"的回调：
 *        int32_t read_value(void) {
 *            uintptr_t w  = *(uintptr_t*)(engine_base + OFF_WORLD);
 *            uintptr_t p  = *(uintptr_t*)(*(uintptr_t*)(w + OFF_A) + OFF_B);
 *            return *(int32_t*)(p + OFF_VALUE);
 *        }
 *   2) 注册：
 *        sg_value_guard_register(read_value, "MyValue");
 *   3) anti 后台线程周期调用并比对，被改即告警。
 *
 * 注意：
 *   - getter 回调里严禁做重活/锁（在 anti 的守护线程里执行）。
 *   - 指针链解引用前先 sg_mem_readable 探测（链上指针可能失效/被改）。
 *   - 这是"检测"，不是"拦截"——发现被改后告警/上报，不阻止外挂写。
 * ========================================================================== */

/* 读当前值的回调：返回关键值的 int64 表示（int32 也转 int64）。 */
typedef int64_t (*sg_value_getter_fn)(void);

/* 带上下文的 getter：ctx 由调用方传入（供偏移链 getter 等使用）。 */
typedef int64_t (*sg_value_getter_ctx_fn)(void *ctx);

/* 注册一个关键值守护点（无上下文）。返回 0=成功，-1=失败（如超容量）。 */
int sg_value_guard_register(sg_value_getter_fn getter, const char *name);

/* 注册一个带上下文的守护点。ctx 会传给 getter。 */
int sg_value_guard_register_ctx(sg_value_getter_ctx_fn getter, void *ctx,
                                const char *name);

/* 启动守护线程（应在 JNI_OnLoad 里、注册完成后调用一次）。返回 0=成功。 */
int sg_value_guard_start(void);

/* 停止守护线程（卸载时调用）。 */
void sg_value_guard_stop(void);

/* 查询：是否有任一守护值被篡改。1=有，0=无，-1=未启动。 */
int sg_value_guard_tampered(void);

/* 输出被篡改值的名字（逗号拼接），供日志/上报。返回 0=无，>0=有。 */
int sg_value_guard_tampered_names(char *buf, size_t len);

/* 内置默认守护点：按 so 名 + 偏移链读 UE 关键值（无需 UE 传回调）。
 * 返回 0=成功，-1=失败。anti 内部用它自动注册"防写"守护，不依赖改 UE 源码。
 *
 * 偏移链语义（接入方自行填入）：
 *   world = *(base + off_chain[0])              // base=引擎 so 基址
 *   然后依次：p = *(p + off_chain[i])，i=1..n-2
 *   最终值 = *(p + off_chain[n-1])
 * 例：off_chain = {OFF_WORLD, OFF_A, OFF_B, 0x0, OFF_C, OFF_VALUE}, n=6。 */
int sg_value_guard_register_chain(const char *module, const uint32_t *off_chain,
                                  int n, const char *name);

/* 偏移链末层读值类型。外挂读的关键值未必是 int32（常是 float/double/指针），
 * 链 getter 按此类型读末层，日志里按真实语义显示（如 float 80.0 而非其位模式）。 */
typedef enum {
    SG_LEAF_I32 = 0,   /* int32  */
    SG_LEAF_U32,       /* uint32 */
    SG_LEAF_I64,       /* int64  */
    SG_LEAF_U64,       /* uint64 */
    SG_LEAF_F32,       /* float  */
    SG_LEAF_F64,       /* double */
    SG_LEAF_PTR        /* 指针   */
} sg_chain_leaf_type;

/* 注册一个按 so 名 + 偏移链读值的守护点（末层按 leaf_type 读）。
 * 返回 0=成功，-1=失败。 */
int sg_value_guard_register_chain_typed(const char *module,
                                        const uint32_t *off_chain, int n,
                                        sg_chain_leaf_type leaf_type,
                                        const char *name);

/* 内置默认守护示例：等价于
 * sg_value_guard_register_chain("libexample.so",
 *     {OFF_WORLD, OFF_A, OFF_B, 0x0, OFF_C, OFF_VALUE}, 6, "ExampleValue")。
 * 偏移是占位示例，接入方按自己逆向结果替换。 */
int sg_value_guard_register_builtin_clientcap(void);

#ifdef __cplusplus
}
#endif
#endif
