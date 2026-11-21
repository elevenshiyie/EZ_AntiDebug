# EZ_AntiDebug

Android 用户态反调试 / 反注入 / 反篡改检测库，纯 C/C++，编译成一个 `libanticheat.so`。

宿主 App 那边只要 `System.loadLibrary("anticheat")`，`JNI_OnLoad` 里会自己起守护线程和周期巡检，不用写任何 native 方法，也不用动业务代码。

只检测、只报告，不杀进程不阻断。命中一条打一条日志，格式固定：

```
检测到使用 <攻击手法>，建议采取措施为 <封号 / 禁赛并警告 / 人工观察账号行为>
```

## 构建

只支持 arm64-v8a。原因是里面 syscall 号、ArtMethod 偏移、NT_ARM_HW_BREAK 这些全是 ARM64 语义，此版本仅为学习就不提供更多的 ABI 适配了。

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_SYSTEM_NAME=ANDROID \
  -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a \
  -DCMAKE_ANDROID_NDK=/path/to/ndk
cmake --build build
# 产物在 outputs/arm64-v8a/libanticheat.so
```

## 接入

```java
static {
    System.loadLibrary("anticheat");
}
```

几个 `shadow.*` 信号在裸判定下几乎所有正经 App 都会亮（UE/JIT 会 mprotect 段、ART 会装 SIGSEGV handler、内嵌 WebView 会装 seccomp），所以留了白名单接口让宿主声明"这是我自己干的"：

```java
AntiCheat.addPathWhitelist("libUE4.so");
AntiCheat.addSignalWhitelist(11);
AntiCheat.setSeccompWhitelist(true);
```

看输出：`adb logcat -s AntiCheat`。

## 检测项

命中才打印，OK 和 SKIPPED 都静默。档位我自己拍的，觉得不合理就改 `jni/jni_entry.cpp` 里的 `report_hit`。

| 信号 | 检测什么 | 处置 |
|---|---|---|
| `inject.memfd` | memfd + unlink 的隐身注入 | 封号 |
| `inject.so_list` | 多出来的非法 so | 封号 |
| `inject.anon_name` | 带名字的匿名段 | 封号 |
| `inject.anon_rx` | 匿名可执行段 | 人工观察 |
| `hook.inline` | inline hook 跳板 | 封号 |
| `hook.ue_procevt` | UE processEvent 被 hook | 封号 |
| `hook.art_entry` | Java 层 ART 方法 hook | 封号 |
| `hook.got` | GOT 表被改 | 禁赛并警告 |
| `mem.canary` | 内存里的 canary 被改 | 封号 |
| `mem.value_guard` | 关键数值被改 | 禁赛并警告 |
| `mem.guard_page` | 越权内存访问 | 人工观察 |
| `dbg.tracerpid` | TracerPid 非 0 | 封号 |
| `dbg.ptrace_self` | TRACEME 被占 | 封号 |
| `dbg.sigtrap` | SIGTRAP 陷阱 | 人工观察 |
| `guard.hwbp` | 硬件断点被清 | 封号 |
| `chan.sysfs` / `chan.devices` | 可疑驱动/设备节点 | 封号 |
| `chan.sentinel` | 哨兵断点被改 | 封号 |
| `shadow.text_x` | 代码段被改成可写可执行 | 封号 |
| `shadow.pool` | 影子页内存池 | 封号 |
| `shadow.sighand` | SIGSEGV handler 被换 | 禁赛并警告 |
| `shadow.seccomp` | 装了 seccomp 过滤 | 人工观察 |

## 目录

```
core/     syscall 直调、/proc/self/maps 解析、白名单、安全读
memory/   canary、关键值守护
inject/   匿名段 / memfd / so 列表
hook/     inline / GOT / UE processEvent / ART
debug/    TracerPid / TRACEME / SIGTRAP
guard/    self-trace 占位、通道封堵、哨兵硬断、反影子页
jni/      JNI_OnLoad 启动 + 巡检循环 + 命中报告
```

## 测不到的东西

- **Zygisk / Zygote 阶段注入**： fork 之前就进来了、同 uid，anti 加载时注入早完成了，没感知窗口。
- **内核态**： 内核态任何操作几乎都检测不到，比如用 vmmap 读 maps、内核态读写、内核态硬断这些，用户态代码碰不到。
- **`process_vm_readv` 读内存**： 外部进程读内存是内核代劳的，纯用户态无感知接口。要拦得改游戏源码，比如关键数据用 mincore 造缺页当陷阱、或者强制走 call 读取再查堆栈，这样读/写就会留下可检测的痕迹。

## 下一阶段预计新增

- **Root环境检测**
- **虚拟机环境检测**
- **SeLinux是否开启**
- **其他**

## 特别鸣谢

- [taisuii/sentry](https://github.com/taisuii/sentry) — 借鉴 syscall 直调思路（检测逻辑自身走 `svc`、不依赖 libc，避免被 Frida 一刀切 hook 整类失效），以及"组合多个信号做结论、不强求单个信号一锤定音"的写法。
- [Inforaam/MobShield-Android](https://github.com/Inforaam/MobShield-Android) — 借鉴"主动标注每个检测项的适用边界、诚实降级"的做法，本库的 `OK / SUSPICIOUS / SKIPPED` 三态和"测不到的东西"一节就是照这个思路来的。
- [jmpews/Dobby](https://github.com/jmpews/Dobby) — 测试用。用它做 inline hook，验证 `hook.inline` 和 `hook.ue_procevt` 能抓到它的跳板。
- [MJx0/AndKittyInjector](https://github.com/MJx0/AndKittyInjector) — 测试用。用它做 ptrace 注入（含 `--memfd` 隐身模式），验证 `inject.memfd` / `inject.so_list` / `shadow.text_x` 这几条。

## License

MIT
