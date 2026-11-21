# ============================================================================
# AntiCheat —— 纯 C/C++ 检测库（独立 so：libanticheat.so）
#
# 宿主（demo）只需：
#   1) CMake 里 add_subdirectory(AntiCheat) 或直接编译本目录
#   2) Java 侧一行 System.loadLibrary("anticheat")
#   3) 无需声明任何 native 方法——JNI_OnLoad 自动启动守护 + 周期巡检
#
# 仅 arm64-v8a：syscall 号 / ArtMethod 偏移 / NT_ARM_HW_BREAK 都是 ARM64 语义。
# ============================================================================

cmake_minimum_required(VERSION 3.21)

set(CMAKE_SYSTEM_NAME ANDROID)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_NDK "D:/AndroidLink/ndk/android-ndk-r29-beta4")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/outputs/${CMAKE_ANDROID_ARCH_ABI}/)

find_program(CCACHE_PROGRAM ccache)
set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})

set(COMMON_COMPILE_OPTIONS -w)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++20")

project("anticheat")

add_library(anticheat SHARED
        # 核心：syscall 直调 + maps 解析 + 全局白名单 + 安全读原语
        core/syscall_utils.cpp
        core/maps.cpp
        core/whitelist.cpp
        core/safe_read.cpp

        # 四域检测
        memory/memory_detector.cpp
        memory/value_guard.cpp
        inject/inject_detector.cpp
        hook/hook_detector.cpp
        hook/art_method.cpp
        debug/debug_detector.cpp

        # 守护：self-trace 占位 + 通道封堵 + 哨兵硬断 + 反影子页/异常hook
        guard/self_guard.cpp
        guard/channel_guard.cpp
        guard/anti_shadow_hook.cpp

        # JNI 入口：自动启动 + 周期巡检
        jni/jni_entry.cpp)

target_include_directories(anticheat PRIVATE .)

# Android 日志 + 动态链接（dl_iterate_phdr 在 libc 里，无需额外链接）
target_link_libraries(anticheat
        android
        log)
